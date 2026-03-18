"""
NVD (NIST) vulnerability aggregation client.

Uses public API without requiring an API key.
"""

import re
import requests
from typing import Dict, Any, List

from .base_client import BaseClient


class NVDClient(BaseClient):
    """Client for NVD CVE API (v2)."""

    display_name = "NVD (NIST)"
    supported_types = ["domain", "url", "cve", "software"]

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        super().__init__()

    def is_configured(self) -> bool:
        # NVD supports no-key usage for basic calls.
        return True

    def lookup(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        if indicator_type not in self.supported_types:
            return {
                "status": "skipped",
                "message": "NVD supports software/CVE-focused lookups",
            }

        try:
            params = {"resultsPerPage": 10}
            if self._is_cve(indicator):
                params["cveId"] = indicator.upper()
            else:
                params["keywordSearch"] = indicator

            response = requests.get(self.BASE_URL, params=params, timeout=30)
            if response.status_code != 200:
                return {
                    "status": "error",
                    "error": f"API returned status {response.status_code}",
                }

            payload = response.json()
            vulns = payload.get("vulnerabilities", [])
            if not vulns:
                return {
                    "status": "not_found",
                    "message": "No vulnerabilities found in NVD",
                }

            parsed = self._parse_vulnerabilities(vulns)
            max_cvss = max([v["cvss_score"] for v in parsed], default=0.0)

            return {
                "status": "success",
                "total_results": payload.get("totalResults", len(parsed)),
                "vulnerabilities": parsed[:10],
                "max_cvss": max_cvss,
                "threat_score": round(min(100.0, max_cvss * 10.0), 2),
            }

        except requests.exceptions.Timeout:
            return {"status": "error", "error": "Request timed out"}
        except requests.exceptions.RequestException as exc:
            return {"status": "error", "error": str(exc)}
        except ValueError:
            return {"status": "error", "error": "Invalid JSON from NVD"}

    def _parse_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        parsed = []

        for entry in vulnerabilities:
            cve_obj = entry.get("cve", {})
            cve_id = cve_obj.get("id", "N/A")
            descriptions = cve_obj.get("descriptions", [])
            description = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break

            metrics = cve_obj.get("metrics", {})
            cvss_score = self._extract_cvss(metrics)

            parsed.append(
                {
                    "cve_id": cve_id,
                    "cvss_score": cvss_score,
                    "description": description[:300],
                    "published": cve_obj.get("published"),
                    "last_modified": cve_obj.get("lastModified"),
                }
            )

        return parsed

    @staticmethod
    def _extract_cvss(metrics: Dict[str, Any]) -> float:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                data = entries[0].get("cvssData", {})
                base = data.get("baseScore")
                if isinstance(base, (int, float)):
                    return float(base)
        return 0.0

    @staticmethod
    def _is_cve(value: str) -> bool:
        return bool(re.match(r"^CVE-\d{4}-\d{4,}$", value, re.IGNORECASE))
