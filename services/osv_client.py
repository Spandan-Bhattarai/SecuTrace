"""
OSV (Google Open Source Vulnerabilities) client.

Uses public API without requiring an API key.
"""

import re
import requests
from typing import Dict, Any, List

from .base_client import BaseClient


class OSVClient(BaseClient):
    """Client for osv.dev API."""

    display_name = "OSV (Google)"
    supported_types = ["domain", "url", "cve", "software", "md5", "sha1", "sha256"]

    VULN_BY_ID_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
    QUERY_URL = "https://api.osv.dev/v1/query"

    ECOSYSTEMS = [
        "PyPI",
        "npm",
        "Go",
        "Maven",
        "NuGet",
        "crates.io",
        "RubyGems",
        "Packagist",
    ]

    def __init__(self):
        super().__init__()

    def is_configured(self) -> bool:
        return True

    def lookup(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        if indicator_type not in self.supported_types:
            return {
                "status": "skipped",
                "message": "OSV supports software/CVE/hash-focused lookups",
            }

        try:
            if self._is_vuln_id(indicator):
                return self._lookup_by_id(indicator)

            aggregate = []
            for ecosystem in self.ECOSYSTEMS:
                data = self._query_package(indicator, ecosystem)
                vulns = data.get("vulns", []) if isinstance(data, dict) else []
                for vuln in vulns:
                    aggregate.append(
                        {
                            "id": vuln.get("id"),
                            "summary": vuln.get("summary", "")[:220],
                            "modified": vuln.get("modified"),
                            "ecosystem": ecosystem,
                        }
                    )

            if not aggregate:
                return {
                    "status": "not_found",
                    "message": "No vulnerabilities found in OSV",
                }

            unique = {}
            for item in aggregate:
                if item["id"] and item["id"] not in unique:
                    unique[item["id"]] = item

            vulnerabilities = list(unique.values())[:15]
            threat_score = round(min(100.0, len(vulnerabilities) * 10.0), 2)

            return {
                "status": "success",
                "vulnerabilities": vulnerabilities,
                "total_results": len(unique),
                "threat_score": threat_score,
            }

        except requests.exceptions.Timeout:
            return {"status": "error", "error": "Request timed out"}
        except requests.exceptions.RequestException as exc:
            return {"status": "error", "error": str(exc)}
        except ValueError:
            return {"status": "error", "error": "Invalid JSON from OSV"}

    def _lookup_by_id(self, vuln_id: str) -> Dict[str, Any]:
        response = requests.get(self.VULN_BY_ID_URL.format(vuln_id=vuln_id), timeout=30)
        if response.status_code == 404:
            return {"status": "not_found", "message": "Vulnerability not found in OSV"}
        if response.status_code != 200:
            return {"status": "error", "error": f"API returned status {response.status_code}"}

        payload = response.json()
        severity_score = self._extract_severity_score(payload)

        return {
            "status": "success",
            "id": payload.get("id"),
            "summary": payload.get("summary", ""),
            "details": (payload.get("details", "") or "")[:400],
            "aliases": payload.get("aliases", []),
            "references": payload.get("references", [])[:6],
            "severity": payload.get("severity", []),
            "threat_score": severity_score,
        }

    def _query_package(self, package_name: str, ecosystem: str) -> Dict[str, Any]:
        body = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            }
        }
        response = requests.post(self.QUERY_URL, json=body, timeout=20)
        if response.status_code != 200:
            return {}
        return response.json() if response.content else {}

    @staticmethod
    def _extract_severity_score(payload: Dict[str, Any]) -> float:
        severities = payload.get("severity", [])
        if not severities:
            aliases = payload.get("aliases", [])
            return 70.0 if any(str(a).startswith("CVE-") for a in aliases) else 45.0

        for sev in severities:
            score = sev.get("score", "")
            # CVSS vectors can be parsed more deeply; this is a simple mapping fallback.
            if "CRITICAL" in score.upper():
                return 95.0
            if "HIGH" in score.upper():
                return 85.0
            if "MEDIUM" in score.upper():
                return 60.0
            if "LOW" in score.upper():
                return 35.0

        return 60.0

    @staticmethod
    def _is_vuln_id(value: str) -> bool:
        return bool(
            re.match(r"^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+)$", value, re.IGNORECASE)
        )
