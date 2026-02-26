"""
ThreatFox API Client
https://threatfox.abuse.ch/
Supports optional API key for authenticated requests
"""

import os
import requests
from typing import Dict, Any
from .base_client import BaseClient


class ThreatFoxClient(BaseClient):
    """Client for ThreatFox API (abuse.ch)"""
    
    display_name = "ThreatFox"
    supported_types = ['ip', 'domain', 'url', 'md5', 'sha256']
    
    BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"
    
    def __init__(self):
        super().__init__()
        self.api_key = os.getenv('THREATFOX_API_KEY')
    
    def is_configured(self) -> bool:
        return True  # Works without key but better with key
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers with optional auth key"""
        headers = {
            'User-Agent': 'SOAR-ThreatIntel/1.0',
            'Content-Type': 'application/json'
        }
        if self.api_key:
            headers['Auth-Key'] = self.api_key
        return headers
    
    def lookup(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        try:
            if indicator_type == 'ip':
                return self._search_ioc(indicator, 'ip:port')
            elif indicator_type == 'domain':
                return self._search_ioc(indicator, 'domain')
            elif indicator_type == 'url':
                return self._search_ioc(indicator, 'url')
            elif indicator_type in ['md5', 'sha256']:
                return self._search_hash(indicator)
            else:
                return {'status': 'skipped', 'message': f'ThreatFox does not support {indicator_type} lookups'}
                
        except requests.exceptions.Timeout:
            return {'status': 'error', 'error': 'Request timed out'}
        except requests.exceptions.RequestException as e:
            return {'status': 'error', 'error': str(e)}
    
    def _search_ioc(self, indicator: str, ioc_type: str) -> Dict[str, Any]:
        """Search for an IoC"""
        response = requests.post(
            self.BASE_URL,
            json={
                'query': 'search_ioc',
                'search_term': indicator
            },
            headers=self._get_headers(),
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('query_status') == 'ok':
                iocs = data.get('data', [])
                
                # Calculate threat score based on number of IoCs and confidence
                threat_score = min(len(iocs) * 20, 100)
                
                return {
                    'status': 'success',
                    'ioc_count': len(iocs),
                    'iocs': [
                        {
                            'ioc': ioc.get('ioc'),
                            'ioc_type': ioc.get('ioc_type'),
                            'threat_type': ioc.get('threat_type'),
                            'malware': ioc.get('malware'),
                            'malware_alias': ioc.get('malware_alias'),
                            'malware_printable': ioc.get('malware_printable'),
                            'confidence_level': ioc.get('confidence_level'),
                            'first_seen': ioc.get('first_seen_utc'),
                            'last_seen': ioc.get('last_seen_utc'),
                            'tags': ioc.get('tags', [])
                        }
                        for ioc in iocs[:10]
                    ],
                    'threat_score': threat_score
                }
            elif data.get('query_status') == 'no_result':
                return {'status': 'not_found', 'message': 'IoC not found in ThreatFox'}
            else:
                return {'status': 'error', 'error': data.get('query_status')}
        else:
            return {'status': 'error', 'error': f'API returned status {response.status_code}'}
    
    def _search_hash(self, file_hash: str) -> Dict[str, Any]:
        """Search for a file hash"""
        response = requests.post(
            self.BASE_URL,
            json={
                'query': 'search_hash',
                'hash': file_hash
            },
            headers=self._get_headers(),
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('query_status') == 'ok':
                results = data.get('data', [])
                
                return {
                    'status': 'success',
                    'result_count': len(results),
                    'results': [
                        {
                            'ioc': r.get('ioc'),
                            'threat_type': r.get('threat_type'),
                            'malware': r.get('malware'),
                            'confidence_level': r.get('confidence_level'),
                            'first_seen': r.get('first_seen_utc'),
                            'tags': r.get('tags', [])
                        }
                        for r in results[:10]
                    ],
                    'threat_score': 80 if results else 0
                }
            elif data.get('query_status') == 'no_result':
                return {'status': 'not_found', 'message': 'Hash not found in ThreatFox'}
            else:
                return {'status': 'error', 'error': data.get('query_status')}
        else:
            return {'status': 'error', 'error': f'API returned status {response.status_code}'}
