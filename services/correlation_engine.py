"""
Correlation engine for entity extraction, graph building, and risk propagation.
"""

from __future__ import annotations

import ipaddress
import re
from itertools import combinations
from typing import Any, Dict, List, Set, Tuple


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
DOMAIN_PATTERN = re.compile(
    r"\b(?=.{4,253}\b)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b"
)


class CorrelationEngine:
    """Builds graph relationships from threat intel API responses."""

    def build(self, indicator: str, indicator_type: str, results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        entities = self._extract_entities(results)
        nodes = self._create_nodes(indicator, indicator_type, entities, results)
        edges = self._map_relationships(indicator, entities)
        graph = self._build_graph(nodes, edges)
        adjusted_nodes = self._propagate_risk(nodes, edges)

        return {
            "entities": [
                {
                    "value": e["value"],
                    "type": e["type"],
                    "sources": sorted(e["sources"]),
                }
                for e in entities.values()
            ],
            "nodes": adjusted_nodes,
            "edges": edges,
            "graph": graph,
            "stats": {
                "node_count": len(adjusted_nodes),
                "edge_count": len(edges),
                "source_coverage": len(
                    {
                        src
                        for e in entities.values()
                        for src in e["sources"]
                    }
                ),
            },
        }

    def _extract_entities(self, results: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        entities: Dict[str, Dict[str, Any]] = {}

        for source, payload in results.items():
            if payload.get("status") != "success":
                continue

            for value in self._walk_values(payload):
                for candidate in self._extract_from_text(value):
                    key = f"{candidate['type']}::{candidate['value']}"
                    if key not in entities:
                        entities[key] = {
                            "value": candidate["value"],
                            "type": candidate["type"],
                            "sources": set(),
                        }
                    entities[key]["sources"].add(source)

        return entities

    def _walk_values(self, obj: Any):
        if isinstance(obj, dict):
            for value in obj.values():
                yield from self._walk_values(value)
        elif isinstance(obj, list):
            for value in obj:
                yield from self._walk_values(value)
        elif isinstance(obj, (str, int, float)):
            yield str(obj)

    def _extract_from_text(self, text: str) -> List[Dict[str, str]]:
        found: List[Dict[str, str]] = []

        for ip in IP_PATTERN.findall(text):
            if self._is_valid_ip(ip):
                found.append({"type": "ip", "value": ip})

        for url in URL_PATTERN.findall(text):
            found.append({"type": "url", "value": url[:400]})

        for h in HASH_PATTERN.findall(text):
            if len(h) in (32, 40, 64):
                found.append({"type": "hash", "value": h.lower()})

        for domain in DOMAIN_PATTERN.findall(text):
            if not self._looks_like_ip(domain):
                found.append({"type": "domain", "value": domain.lower()})

        # Preserve order and uniqueness.
        seen: Set[Tuple[str, str]] = set()
        unique: List[Dict[str, str]] = []
        for item in found:
            key = (item["type"], item["value"])
            if key not in seen:
                seen.add(key)
                unique.append(item)

        return unique

    def _create_nodes(
        self,
        indicator: str,
        indicator_type: str,
        entities: Dict[str, Dict[str, Any]],
        results: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        nodes: List[Dict[str, Any]] = [
            {
                "id": f"input::{indicator}",
                "value": indicator,
                "type": indicator_type,
                "base_score": self._average_score(results),
                "adjusted_score": None,
                "source_count": len([k for k, v in results.items() if v.get("status") == "success"]),
            }
        ]

        for data in entities.values():
            sources = sorted(data["sources"])
            base_score = self._average_score(results, sources)
            nodes.append(
                {
                    "id": f"{data['type']}::{data['value']}",
                    "value": data["value"],
                    "type": data["type"],
                    "base_score": base_score,
                    "adjusted_score": None,
                    "source_count": len(sources),
                }
            )

        return nodes

    def _map_relationships(self, indicator: str, entities: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        edges: List[Dict[str, Any]] = []
        seen_edges: Set[Tuple[str, str, str]] = set()

        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for entity in entities.values():
            for source in entity["sources"]:
                grouped.setdefault(source, []).append(entity)

        for source, src_entities in grouped.items():
            ids = [f"{e['type']}::{e['value']}" for e in src_entities]
            for a, b in combinations(sorted(set(ids)), 2):
                key = (a, b, "co_occurrence")
                if key in seen_edges:
                    continue
                seen_edges.add(key)
                edges.append(
                    {
                        "from": a,
                        "to": b,
                        "relationship": "co_occurrence",
                        "source": source,
                    }
                )

        for entity in entities.values():
            target = f"{entity['type']}::{entity['value']}"
            if target == f"input::{indicator}":
                continue
            key = (f"input::{indicator}", target, "observed_with")
            if key in seen_edges:
                continue
            seen_edges.add(key)
            edges.append(
                {
                    "from": f"input::{indicator}",
                    "to": target,
                    "relationship": "observed_with",
                    "source": "correlation",
                }
            )

        return edges

    def _build_graph(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        adjacency: Dict[str, List[str]] = {node["id"]: [] for node in nodes}
        for edge in edges:
            adjacency.setdefault(edge["from"], []).append(edge["to"])
            adjacency.setdefault(edge["to"], []).append(edge["from"])
        return adjacency

    def _propagate_risk(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        adjacency: Dict[str, Set[str]] = {}
        for edge in edges:
            adjacency.setdefault(edge["from"], set()).add(edge["to"])
            adjacency.setdefault(edge["to"], set()).add(edge["from"])

        node_map = {node["id"]: node for node in nodes}

        for node in nodes:
            base = float(node.get("base_score", 0) or 0)
            neighbors = adjacency.get(node["id"], set())

            malicious_neighbors = 0
            for neighbor in neighbors:
                neighbor_score = float(node_map.get(neighbor, {}).get("base_score", 0) or 0)
                if neighbor_score >= 70:
                    malicious_neighbors += 1

            boost = min(30, malicious_neighbors * 10)
            node["adjusted_score"] = round(min(100, base + boost), 2)

        return nodes

    @staticmethod
    def _average_score(results: Dict[str, Dict[str, Any]], sources: List[str] | None = None) -> float:
        score_values: List[float] = []

        for source, payload in results.items():
            if sources is not None and source not in sources:
                continue
            if payload.get("status") != "success":
                continue
            score = payload.get("threat_score")
            if isinstance(score, (int, float)):
                score_values.append(float(score))

        if not score_values:
            return 0.0

        return round(sum(score_values) / len(score_values), 2)

    @staticmethod
    def _is_valid_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        return bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", value))
