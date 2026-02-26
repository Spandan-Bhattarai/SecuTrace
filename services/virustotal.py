"""
VirusTotal API Client
https://www.virustotal.com/
"""

import os
import requests
from typing import Dict, Any
from .base_client import BaseClient


class VirusTotalClient(BaseClient):
    """Client for VirusTotal API v3"""
    
    display_name = "VirusTotal"
    supported_types = ['ip', 'domain', 'url', 'md5', 'sha1', 'sha256']
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self):
        super().__init__()
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY')
    
    def is_configured(self) -> bool:
        return bool(self.api_key)
    
    def lookup(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        headers = {
            'x-apikey': self.api_key
        }
        
        try:
            if indicator_type == 'ip':
                url = f"{self.BASE_URL}/ip_addresses/{indicator}"
            elif indicator_type == 'domain':
                url = f"{self.BASE_URL}/domains/{indicator}"
            elif indicator_type == 'url':
                # URL needs to be base64 encoded without padding
                import base64
                url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
                url = f"{self.BASE_URL}/urls/{url_id}"
            elif indicator_type in ['md5', 'sha1', 'sha256']:
                url = f"{self.BASE_URL}/files/{indicator}"
            else:
                return {'status': 'error', 'error': f'Unsupported type: {indicator_type}'}
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                attributes = data.get('attributes', {})
                
                # Extract relevant stats
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                
                result = {
                    'status': 'success',
                    'malicious': last_analysis_stats.get('malicious', 0),
                    'suspicious': last_analysis_stats.get('suspicious', 0),
                    'harmless': last_analysis_stats.get('harmless', 0),
                    'undetected': last_analysis_stats.get('undetected', 0),
                    'reputation': attributes.get('reputation', 'N/A'),
                    'last_analysis_date': attributes.get('last_analysis_date'),
                    'tags': attributes.get('tags', []),
                }
                
                # Add type-specific info
                if indicator_type == 'ip':
                    result['country'] = attributes.get('country', 'N/A')
                    result['as_owner'] = attributes.get('as_owner', 'N/A')
                    result['asn'] = attributes.get('asn', 'N/A')
                elif indicator_type == 'domain':
                    result['registrar'] = attributes.get('registrar', 'N/A')
                    result['creation_date'] = attributes.get('creation_date')
                elif indicator_type in ['md5', 'sha1', 'sha256']:
                    result['file_type'] = attributes.get('type_description', 'N/A')
                    result['file_size'] = attributes.get('size', 'N/A')
                    result['names'] = attributes.get('names', [])[:5]
                
                # Calculate threat score
                total = sum(last_analysis_stats.values()) if last_analysis_stats else 0
                if total > 0:
                    result['threat_score'] = round(
                        (last_analysis_stats.get('malicious', 0) + 
                         last_analysis_stats.get('suspicious', 0) * 0.5) / total * 100, 2
                    )
                else:
                    result['threat_score'] = 0
                
                return result
            
            elif response.status_code == 404:
                return {'status': 'not_found', 'message': 'Indicator not found in VirusTotal'}
            else:
                return {'status': 'error', 'error': f'API returned status {response.status_code}'}
                
        except requests.exceptions.Timeout:
            return {'status': 'error', 'error': 'Request timed out'}
        except requests.exceptions.RequestException as e:
            return {'status': 'error', 'error': str(e)}
