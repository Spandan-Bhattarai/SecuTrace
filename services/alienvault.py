"""
AlienVault OTX API Client
https://otx.alienvault.com/
"""

import os
import requests
from typing import Dict, Any
from .base_client import BaseClient


class AlienVaultOTXClient(BaseClient):
    """Client for AlienVault Open Threat Exchange (OTX) API"""
    
    display_name = "AlienVault OTX"
    supported_types = ['ip', 'domain', 'url', 'md5', 'sha1', 'sha256']
    
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    def __init__(self):
        super().__init__()
        self.api_key = os.getenv('ALIENVAULT_OTX_API_KEY')
    
    def is_configured(self) -> bool:
        return bool(self.api_key)
    
    def lookup(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        headers = {
            'X-OTX-API-KEY': self.api_key
        }
        
        try:
            if indicator_type == 'ip':
                url = f"{self.BASE_URL}/indicators/IPv4/{indicator}/general"
            elif indicator_type == 'domain':
                url = f"{self.BASE_URL}/indicators/domain/{indicator}/general"
            elif indicator_type == 'url':
                url = f"{self.BASE_URL}/indicators/url/{indicator}/general"
            elif indicator_type in ['md5', 'sha1', 'sha256']:
                hash_type = 'FileHash-MD5' if indicator_type == 'md5' else \
                           'FileHash-SHA1' if indicator_type == 'sha1' else 'FileHash-SHA256'
                url = f"{self.BASE_URL}/indicators/file/{indicator}/general"
            else:
                return {'status': 'error', 'error': f'Unsupported type: {indicator_type}'}
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                pulses = data.get('pulse_info', {})
                pulse_count = pulses.get('count', 0)
                
                # Calculate threat score based on pulse count and validation
                threat_score = min(pulse_count * 10, 100)
                
                result = {
                    'status': 'success',
                    'indicator': data.get('indicator'),
                    'type': data.get('type'),
                    'pulse_count': pulse_count,
                    'pulses': [
                        {
                            'name': p.get('name'),
                            'description': p.get('description', '')[:200],
                            'created': p.get('created'),
                            'tags': p.get('tags', [])[:5]
                        }
                        for p in pulses.get('pulses', [])[:5]
                    ],
                    'validation': data.get('validation', []),
                    'threat_score': threat_score,
                    'sections': data.get('sections', [])
                }
                
                # Add type-specific data
                if indicator_type == 'ip':
                    result['asn'] = data.get('asn', 'N/A')
                    result['country_code'] = data.get('country_code', 'N/A')
                    result['country_name'] = data.get('country_name', 'N/A')
                    result['city'] = data.get('city', 'N/A')
                    result['reputation'] = data.get('reputation', 0)
                elif indicator_type == 'domain':
                    result['alexa'] = data.get('alexa', 'N/A')
                    result['whois'] = data.get('whois', 'N/A')[:500] if data.get('whois') else 'N/A'
                
                return result
            
            elif response.status_code == 404:
                return {'status': 'not_found', 'message': 'Indicator not found in AlienVault OTX'}
            else:
                return {'status': 'error', 'error': f'API returned status {response.status_code}'}
                
        except requests.exceptions.Timeout:
            return {'status': 'error', 'error': 'Request timed out'}
        except requests.exceptions.RequestException as e:
            return {'status': 'error', 'error': str(e)}
