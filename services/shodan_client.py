"""
Shodan API Client
https://www.shodan.io/
"""

import os
import requests
from typing import Dict, Any
from .base_client import BaseClient


class ShodanClient(BaseClient):
    """Client for Shodan API"""
    
    display_name = "Shodan"
    supported_types = ['ip', 'domain']
    
    BASE_URL = "https://api.shodan.io"
    
    def __init__(self):
        super().__init__()
        self.api_key = os.getenv('SHODAN_API_KEY')
    
    def is_configured(self) -> bool:
        return bool(self.api_key)
    
    def lookup(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        if indicator_type not in ['ip', 'domain']:
            return {'status': 'skipped', 'message': 'Shodan only supports IP and domain lookups'}
        
        try:
            if indicator_type == 'ip':
                return self._lookup_ip(indicator)
            else:
                return self._lookup_domain(indicator)
        except requests.exceptions.Timeout:
            return {'status': 'error', 'error': 'Request timed out'}
        except requests.exceptions.RequestException as e:
            return {'status': 'error', 'error': str(e)}
    
    def _lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Look up an IP address"""
        response = requests.get(
            f"{self.BASE_URL}/shodan/host/{ip}",
            params={'key': self.api_key},
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract open ports and services
            ports = data.get('ports', [])
            services = []
            vulns = []
            
            for service in data.get('data', []):
                services.append({
                    'port': service.get('port'),
                    'transport': service.get('transport', 'tcp'),
                    'product': service.get('product', 'N/A'),
                    'version': service.get('version', 'N/A')
                })
                # Collect vulnerabilities
                if 'vulns' in service:
                    vulns.extend(list(service['vulns'].keys()))
            
            # Calculate threat score based on open ports and vulns
            threat_score = min(len(ports) * 5 + len(vulns) * 15, 100)
            
            return {
                'status': 'success',
                'ip_str': data.get('ip_str'),
                'hostnames': data.get('hostnames', []),
                'country_name': data.get('country_name', 'N/A'),
                'country_code': data.get('country_code', 'N/A'),
                'city': data.get('city', 'N/A'),
                'org': data.get('org', 'N/A'),
                'isp': data.get('isp', 'N/A'),
                'asn': data.get('asn', 'N/A'),
                'os': data.get('os', 'N/A'),
                'ports': ports,
                'services': services[:10],  # Limit to 10 services
                'vulnerabilities': list(set(vulns))[:20],  # Unique vulns, limit to 20
                'last_update': data.get('last_update'),
                'tags': data.get('tags', []),
                'threat_score': threat_score
            }
        elif response.status_code == 404:
            return {'status': 'not_found', 'message': 'IP not found in Shodan'}
        elif response.status_code == 403:
            return {'status': 'not_found', 'message': 'No Shodan data available for this IP (requires upgrade or IP not scanned)'}
        elif response.status_code == 401:
            return {'status': 'error', 'error': 'Invalid Shodan API key'}
        else:
            return {'status': 'error', 'error': f'API returned status {response.status_code}'}
    
    def _lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Look up a domain"""
        response = requests.get(
            f"{self.BASE_URL}/dns/resolve",
            params={'key': self.api_key, 'hostnames': domain},
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            ip = data.get(domain)
            
            if ip:
                # Get IP info for the resolved domain
                ip_result = self._lookup_ip(ip)
                ip_result['resolved_ip'] = ip
                return ip_result
            else:
                return {'status': 'not_found', 'message': 'Domain could not be resolved'}
        else:
            return {'status': 'error', 'error': f'API returned status {response.status_code}'}
