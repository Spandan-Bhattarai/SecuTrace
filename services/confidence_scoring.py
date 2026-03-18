"""
Confidence scoring engine for normalized weighted threat evaluation.
"""

from __future__ import annotations

from typing import Any, Dict


class ConfidenceScoringEngine:
    """Computes confidence score and verdict from source results + graph context."""

    SOURCE_WEIGHTS = {
        "virustotal": 1.0,
        "abuseipdb": 0.9,
        "shodan": 0.7,
        "alienvault": 0.9,
        "ipinfo": 0.5,
        "urlhaus": 0.8,
        "threatfox": 0.8,
        "malwarebazaar": 0.95,
        "dshield": 0.75,
        "nvd": 0.85,
        "osv": 0.85,
    }

    def compute(self, results: Dict[str, Dict[str, Any]], correlation: Dict[str, Any]) -> Dict[str, Any]:
        normalized_scores = self._normalize_scores(results)
        weighted_scores = self._apply_weights(normalized_scores)

        total_weight = sum(entry["weight"] for entry in weighted_scores.values())
        weighted_sum = sum(entry["weighted_score"] for entry in weighted_scores.values())
        base_score = (weighted_sum / total_weight) if total_weight > 0 else 0.0

        context_boost = self._context_boost(correlation)
        final_score = round(min(100.0, base_score + context_boost), 2)
        verdict = self._verdict(final_score)
        category = self._confidence_category(total_weight, len(weighted_scores))

        return {
            "category": category,
            "components": {
                "normalized_scores": normalized_scores,
                "weighted_scores": weighted_scores,
                "context_boost": context_boost,
            },
            "final_score": final_score,
            "verdict": verdict,
            "thresholds": {
                "safe_max": 34,
                "suspicious_max": 69,
                "malicious_min": 70,
            },
        }

    def _normalize_scores(self, results: Dict[str, Dict[str, Any]]) -> Dict[str, float]:
        normalized: Dict[str, float] = {}

        for source, payload in results.items():
            status = payload.get("status")

            if status == "success":
                raw = payload.get("threat_score")
                if isinstance(raw, (int, float)):
                    normalized[source] = float(max(0, min(100, raw)))
                else:
                    normalized[source] = 50.0
            elif status == "not_found":
                normalized[source] = 10.0
            else:
                # skipped / error / not_configured are excluded.
                continue

        return normalized

    def _apply_weights(self, normalized_scores: Dict[str, float]) -> Dict[str, Dict[str, float]]:
        weighted: Dict[str, Dict[str, float]] = {}

        for source, score in normalized_scores.items():
            weight = self.SOURCE_WEIGHTS.get(source, 0.6)
            weighted[source] = {
                "normalized_score": round(score, 2),
                "weight": round(weight, 3),
                "weighted_score": round(score * weight, 2),
            }

        return weighted

    @staticmethod
    def _context_boost(correlation: Dict[str, Any]) -> float:
        stats = correlation.get("stats", {})
        nodes = correlation.get("nodes", [])

        node_count = int(stats.get("node_count", 0) or 0)
        edge_count = int(stats.get("edge_count", 0) or 0)

        if node_count <= 1:
            return 0.0

        malicious_nodes = 0
        for node in nodes:
            adjusted = node.get("adjusted_score")
            if isinstance(adjusted, (int, float)) and adjusted >= 70:
                malicious_nodes += 1

        malicious_ratio = malicious_nodes / max(1, node_count)
        density = edge_count / max(1, node_count)

        boost = (malicious_ratio * 20.0) + min(8.0, density * 2.0)
        return round(min(25.0, boost), 2)

    @staticmethod
    def _verdict(score: float) -> str:
        if score >= 70:
            return "Malicious"
        if score >= 35:
            return "Suspicious"
        return "Safe"

    @staticmethod
    def _confidence_category(total_weight: float, source_count: int) -> str:
        if source_count >= 6 and total_weight >= 4.0:
            return "High Confidence"
        if source_count >= 3 and total_weight >= 2.0:
            return "Medium Confidence"
        return "Low Confidence"
