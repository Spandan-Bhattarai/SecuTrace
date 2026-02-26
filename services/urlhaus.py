"""
URLhaus API Client
https://urlhaus.abuse.ch/
Uses abuse.ch Auth-Key for authentication
"""

import os
import requests
from typing import Dict, Any
from .base_client import BaseClient


class URLHausClient(BaseClient):
    """Client for URLhaus API (abuse.ch)"""
    
    display_name = "URLhaus"
    supported_types = ['ip', 'domain', 'url', 'md5', 'sha256']
    
    BASE_URL = "https://urlhaus-api.abuse.ch/v1"
    
    def __init__(self):
        super().__init__()
        # Uses same Auth-Key as ThreatFox (abuse.ch shared key)
        self.api_key = os.getenv('THREATFOX_API_KEY')
    
    def is_configured(self) -> bool:
        return True  # Works with or without key depending on abuse.ch policy
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers with auth key"""
        headers = {'User-Agent': 'SOAR-ThreatIntel/1.0'}
        if self.api_key:
            headers['Auth-Key'] = self.api_key
        return headers
    
    def lookup(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        try:
            if indicator_type == 'ip':
                return self._lookup_host(indicator)
            elif indicator_type == 'domain':
                return self._lookup_host(indicator)
            elif indicator_type == 'url':
                return self._lookup_url(indicator)
            elif indicator_type in ['md5', 'sha256']:
                return self._lookup_payload(indicator, indicator_type)
            else:
                return {'status': 'skipped', 'message': f'URLhaus does not support {indicator_type} lookups'}
                
        except requests.exceptions.Timeout:
            return {'status': 'error', 'error': 'Request timed out'}
        except requests.exceptions.RequestException as e:
            return {'status': 'error', 'error': str(e)}
    
    def _lookup_host(self, host: str) -> Dict[str, Any]:
        """Look up a host (IP or domain)"""
        response = requests.post(
            f"{self.BASE_URL}/host/",
            data={'host': host},
            headers=self._get_headers(),
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('query_status') == 'ok':
                urls = data.get('urls', [])
                
                # Calculate threat score based on URL count and status
                online_count = sum(1 for u in urls if u.get('url_status') == 'online')
                threat_score = min(online_count * 20 + len(urls) * 5, 100)
                
                return {
                    'status': 'success',
                    'host': data.get('host'),
                    'url_count': data.get('url_count', 0),
                    'blacklists': data.get('blacklists', {}),
                    'urls': [
                        {
                            'url': u.get('url'),
                            'url_status': u.get('url_status'),
                            'threat': u.get('threat'),
                            'tags': u.get('tags', []),
                            'date_added': u.get('date_added')
                        }
                        for u in urls[:10]
                    ],
                    'threat_score': threat_score
                }
            elif data.get('query_status') == 'no_results':
                return {'status': 'not_found', 'message': 'Host not found in URLhaus'}
            else:
                return {'status': 'error', 'error': data.get('query_status')}
        else:
            return {'status': 'error', 'error': f'API returned status {response.status_code}'}
    
    def _lookup_url(self, url: str) -> Dict[str, Any]:
        """Look up a URL"""
        response = requests.post(
            f"{self.BASE_URL}/url/",
            data={'url': url},
            headers=self._get_headers(),
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('query_status') == 'ok':
                threat_score = 80 if data.get('threat') else 30
                
                return {
                    'status': 'success',
                    'url': data.get('url'),
                    'url_status': data.get('url_status'),
                    'host': data.get('host'),
                    'date_added': data.get('date_added'),
                    'threat': data.get('threat'),
                    'blacklists': data.get('blacklists', {}),
                    'tags': data.get('tags', []),
                    'payloads': [
                        {
                            'filename': p.get('filename'),
                            'file_type': p.get('file_type'),
                            'signature': p.get('signature'),
                            'md5_hash': p.get('response_md5'),
                            'sha256_hash': p.get('response_sha256')
                        }
                        for p in data.get('payloads', [])[:5]
                    ],
                    'threat_score': threat_score
                }
            elif data.get('query_status') == 'no_results':
                return {'status': 'not_found', 'message': 'URL not found in URLhaus'}
            else:
                return {'status': 'error', 'error': data.get('query_status')}
        else:
            return {'status': 'error', 'error': f'API returned status {response.status_code}'}
    
    def _lookup_payload(self, file_hash: str, hash_type: str) -> Dict[str, Any]:
        """Look up a file hash"""
        response = requests.post(
            f"{self.BASE_URL}/payload/",
            data={f'{hash_type}_hash': file_hash},
            headers=self._get_headers(),
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('query_status') == 'ok':
                return {
                    'status': 'success',
                    'md5_hash': data.get('md5_hash'),
                    'sha256_hash': data.get('sha256_hash'),
                    'file_type': data.get('file_type'),
                    'file_size': data.get('file_size'),
                    'signature': data.get('signature'),
                    'firstseen': data.get('firstseen'),
                    'lastseen': data.get('lastseen'),
                    'url_count': data.get('url_count', 0),
                    'urls': data.get('urls', [])[:10],
                    'threat_score': 85
                }
            elif data.get('query_status') == 'no_results':
                return {'status': 'not_found', 'message': 'Hash not found in URLhaus'}
            else:
                return {'status': 'error', 'error': data.get('query_status')}
        else:
            return {'status': 'error', 'error': f'API returned status {response.status_code}'}
