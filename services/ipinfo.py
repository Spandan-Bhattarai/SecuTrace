"""
IPInfo API Client
https://ipinfo.io/
"""

import os
import requests
from typing import Dict, Any
from .base_client import BaseClient


class IPInfoClient(BaseClient):
    """Client for IPInfo API"""
    
    display_name = "IPInfo"
    supported_types = ['ip']
    
    BASE_URL = "https://ipinfo.io"
    
    def __init__(self):
        super().__init__()
        self.api_key = os.getenv('IPINFO_API_KEY')
    
    def is_configured(self) -> bool:
        return bool(self.api_key)
    
    def lookup(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        if indicator_type != 'ip':
            return {'status': 'skipped', 'message': 'IPInfo only supports IP lookups'}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/{indicator}",
                params={'token': self.api_key},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Check for privacy/hosting indicators
                privacy = data.get('privacy', {})
                is_vpn = privacy.get('vpn', False)
                is_proxy = privacy.get('proxy', False)
                is_tor = privacy.get('tor', False)
                is_hosting = privacy.get('hosting', False)
                
                # Calculate threat score based on privacy indicators
                threat_score = 0
                if is_tor:
                    threat_score += 40
                if is_vpn:
                    threat_score += 20
                if is_proxy:
                    threat_score += 30
                if is_hosting:
                    threat_score += 10
                
                return {
                    'status': 'success',
                    'ip': data.get('ip'),
                    'hostname': data.get('hostname', 'N/A'),
                    'city': data.get('city', 'N/A'),
                    'region': data.get('region', 'N/A'),
                    'country': data.get('country', 'N/A'),
                    'loc': data.get('loc', 'N/A'),
                    'org': data.get('org', 'N/A'),
                    'postal': data.get('postal', 'N/A'),
                    'timezone': data.get('timezone', 'N/A'),
                    'asn': data.get('asn', {}),
                    'company': data.get('company', {}),
                    'privacy': {
                        'vpn': is_vpn,
                        'proxy': is_proxy,
                        'tor': is_tor,
                        'relay': privacy.get('relay', False),
                        'hosting': is_hosting
                    },
                    'abuse': data.get('abuse', {}),
                    'domains': data.get('domains', {}),
                    'threat_score': threat_score
                }
            
            elif response.status_code == 404:
                return {'status': 'not_found', 'message': 'IP not found in IPInfo'}
            elif response.status_code == 429:
                return {'status': 'error', 'error': 'Rate limit exceeded'}
            else:
                return {'status': 'error', 'error': f'API returned status {response.status_code}'}
                
        except requests.exceptions.Timeout:
            return {'status': 'error', 'error': 'Request timed out'}
        except requests.exceptions.RequestException as e:
            return {'status': 'error', 'error': str(e)}
