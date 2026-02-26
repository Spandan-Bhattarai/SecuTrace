"""
AbuseIPDB API Client
https://www.abuseipdb.com/
"""

import os
import requests
from typing import Dict, Any
from .base_client import BaseClient


class AbuseIPDBClient(BaseClient):
    """Client for AbuseIPDB API v2"""
    
    display_name = "AbuseIPDB"
    supported_types = ['ip']
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self):
        super().__init__()
        self.api_key = os.getenv('ABUSEIPDB_API_KEY')
    
    def is_configured(self) -> bool:
        return bool(self.api_key)
    
    def lookup(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        if indicator_type != 'ip':
            return {'status': 'skipped', 'message': 'AbuseIPDB only supports IP lookups'}
        
        headers = {
            'Key': self.api_key,
            'Accept': 'application/json'
        }
        
        params = {
            'ipAddress': indicator,
            'maxAgeInDays': 90,
            'verbose': True
        }
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/check",
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                return {
                    'status': 'success',
                    'ip_address': data.get('ipAddress'),
                    'is_public': data.get('isPublic', False),
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'country_code': data.get('countryCode', 'N/A'),
                    'country_name': data.get('countryName', 'N/A'),
                    'isp': data.get('isp', 'N/A'),
                    'domain': data.get('domain', 'N/A'),
                    'usage_type': data.get('usageType', 'N/A'),
                    'total_reports': data.get('totalReports', 0),
                    'num_distinct_users': data.get('numDistinctUsers', 0),
                    'last_reported_at': data.get('lastReportedAt'),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'threat_score': data.get('abuseConfidenceScore', 0),
                    'categories': self._get_categories(data.get('reports', []))
                }
            elif response.status_code == 404:
                return {'status': 'not_found', 'message': 'IP not found in AbuseIPDB'}
            elif response.status_code == 429:
                return {'status': 'error', 'error': 'Rate limit exceeded'}
            else:
                return {'status': 'error', 'error': f'API returned status {response.status_code}'}
                
        except requests.exceptions.Timeout:
            return {'status': 'error', 'error': 'Request timed out'}
        except requests.exceptions.RequestException as e:
            return {'status': 'error', 'error': str(e)}
    
    def _get_categories(self, reports: list) -> Dict[str, int]:
        """Extract category counts from reports"""
        category_map = {
            1: 'DNS Compromise',
            2: 'DNS Poisoning',
            3: 'Fraud Orders',
            4: 'DDoS Attack',
            5: 'FTP Brute-Force',
            6: 'Ping of Death',
            7: 'Phishing',
            8: 'Fraud VoIP',
            9: 'Open Proxy',
            10: 'Web Spam',
            11: 'Email Spam',
            12: 'Blog Spam',
            13: 'VPN IP',
            14: 'Port Scan',
            15: 'Hacking',
            16: 'SQL Injection',
            17: 'Spoofing',
            18: 'Brute-Force',
            19: 'Bad Web Bot',
            20: 'Exploited Host',
            21: 'Web App Attack',
            22: 'SSH',
            23: 'IoT Targeted'
        }
        
        category_counts = {}
        for report in reports[:20]:  # Limit to last 20 reports
            for cat_id in report.get('categories', []):
                cat_name = category_map.get(cat_id, f'Category {cat_id}')
                category_counts[cat_name] = category_counts.get(cat_name, 0) + 1
        
        return category_counts
