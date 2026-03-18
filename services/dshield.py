"""
DShield client.

Free IP reputation/intel lookup powered by ISC DShield.
"""

from typing import Dict, Any

import requests

from .base_client import BaseClient


class DShieldClient(BaseClient):
    """Client for ISC DShield IP intelligence."""

    display_name = "DShield"
    supported_types = ["ip"]
    BASE_URL = "https://www.dshield.org/api/ip/{indicator}?json"

    def is_configured(self) -> bool:
        # Public API endpoint; no key required.
        return True

    def lookup(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        if indicator_type not in self.supported_types:
            return {
                "status": "skipped",
                "message": "DShield supports IP lookups only",
            }

        try:
            response = requests.get(
                self.BASE_URL.format(indicator=indicator),
                timeout=30,
            )

            if response.status_code != 200:
                return {
                    "status": "error",
                    "error": f"API returned status {response.status_code}",
                }

            data = response.json() if response.content else {}
            ip_data = data.get("ip", {}) if isinstance(data, dict) else {}

            if not ip_data:
                return {
                    "status": "not_found",
                    "message": "No DShield data found for this indicator",
                }

            maxrisk = self._to_int(ip_data.get("maxrisk"))
            attacks = self._to_int(ip_data.get("attacks"))
            threatfeeds = ip_data.get("threatfeeds", {})
            feed_count = len(threatfeeds) if isinstance(threatfeeds, dict) else 0

            classification = self._classify(maxrisk, attacks, feed_count)

            return {
                "status": "success",
                "indicator": indicator,
                "classification": classification,
                "maxrisk": maxrisk,
                "attacks": attacks,
                "network": ip_data.get("network"),
                "as_number": ip_data.get("as"),
                "as_name": ip_data.get("asname"),
                "as_country": ip_data.get("ascountry"),
                "abuse_contact": ip_data.get("asabusecontact"),
                "threat_feed_count": feed_count,
                "threatfeeds": threatfeeds,
                "comment": ip_data.get("comment"),
                "threat_score": self._score_from_classification(classification),
            }

        except requests.exceptions.Timeout:
            return {"status": "error", "error": "Request timed out"}
        except requests.exceptions.RequestException as exc:
            return {"status": "error", "error": str(exc)}
        except ValueError:
            return {"status": "error", "error": "Invalid response format from DShield"}

    @staticmethod
    def _to_int(value: Any) -> int:
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str) and value.strip().isdigit():
            return int(value)
        return 0

    @staticmethod
    def _classify(maxrisk: int, attacks: int, feed_count: int) -> str:
        if maxrisk >= 7 or attacks >= 1000:
            return "malicious"
        if maxrisk >= 3 or attacks >= 100 or feed_count > 0:
            return "suspicious"
        return "benign"

    @staticmethod
    def _score_from_classification(classification: str) -> float:
        if classification == "malicious":
            return 80.0
        if classification == "suspicious":
            return 50.0
        return 15.0