"""
Threat Intelligence Service
Orchestrates lookups across multiple threat intelligence sources
"""

import re
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional

from .virustotal import VirusTotalClient
from .abuseipdb import AbuseIPDBClient
from .shodan_client import ShodanClient
from .alienvault import AlienVaultOTXClient
from .ipinfo import IPInfoClient
from .urlhaus import URLHausClient
from .threatfox import ThreatFoxClient
from .malwarebazaar import MalwareBazaarClient


class ThreatIntelService:
    """
    Main service that orchestrates threat intelligence lookups
    across multiple sources
    """
    
    def __init__(self):
        self.clients = {
            'virustotal': VirusTotalClient(),
            'abuseipdb': AbuseIPDBClient(),
            'shodan': ShodanClient(),
            'alienvault': AlienVaultOTXClient(),
            'ipinfo': IPInfoClient(),
            'urlhaus': URLHausClient(),
            'threatfox': ThreatFoxClient(),
            'malwarebazaar': MalwareBazaarClient()
        }
    
    def detect_indicator_type(self, indicator: str) -> str:
        """
        Detect the type of indicator (IP, domain, URL, hash)
        """
        # Check if it's an IP address
        try:
            ipaddress.ip_address(indicator)
            return 'ip'
        except ValueError:
            pass
        
        # Check if it's a URL
        if indicator.startswith(('http://', 'https://')):
            return 'url'
        
        # Check if it's a hash (MD5, SHA1, SHA256)
        if re.match(r'^[a-fA-F0-9]{32}$', indicator):
            return 'md5'
        if re.match(r'^[a-fA-F0-9]{40}$', indicator):
            return 'sha1'
        if re.match(r'^[a-fA-F0-9]{64}$', indicator):
            return 'sha256'
        
        # Otherwise treat as domain
        return 'domain'
    
    def lookup_all(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """
        Look up an indicator across all available sources using parallel execution
        """
        results = {}
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            
            for name, client in self.clients.items():
                if client.is_configured():
                    future = executor.submit(
                        self._safe_lookup, 
                        client, 
                        indicator, 
                        indicator_type
                    )
                    futures[future] = name
                else:
                    results[name] = {
                        'status': 'not_configured',
                        'error': 'API key not configured'
                    }
            
            for future in as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result()
                except Exception as e:
                    results[name] = {
                        'status': 'error',
                        'error': str(e)
                    }
        
        return results
    
    def lookup_single(self, indicator: str, indicator_type: str, source: str) -> Dict[str, Any]:
        """
        Look up an indicator on a single source
        """
        if source not in self.clients:
            return {'status': 'error', 'error': f'Unknown source: {source}'}
        
        client = self.clients[source]
        
        if not client.is_configured():
            return {'status': 'not_configured', 'error': 'API key not configured'}
        
        return self._safe_lookup(client, indicator, indicator_type)
    
    def _safe_lookup(self, client, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """
        Safely execute a lookup with error handling
        """
        try:
            return client.lookup(indicator, indicator_type)
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def get_sources_status(self) -> List[Dict[str, Any]]:
        """
        Get the configuration status of all sources
        """
        sources = []
        for name, client in self.clients.items():
            sources.append({
                'name': name,
                'display_name': client.display_name,
                'configured': client.is_configured(),
                'supports': client.supported_types
            })
        return sources
