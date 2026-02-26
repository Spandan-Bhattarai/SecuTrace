"""
Base client for threat intelligence services
"""

import os
from abc import ABC, abstractmethod
from typing import Dict, Any, List


class BaseClient(ABC):
    """
    Abstract base class for all threat intelligence clients
    """
    
    display_name: str = "Base Client"
    supported_types: List[str] = ['ip', 'domain', 'url', 'md5', 'sha1', 'sha256']
    
    def __init__(self):
        self.api_key = None
    
    @abstractmethod
    def is_configured(self) -> bool:
        """Check if the client has necessary API credentials configured"""
        pass
    
    @abstractmethod
    def lookup(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """
        Perform a lookup for the given indicator
        
        Args:
            indicator: The IoC to look up (IP, domain, URL, hash)
            indicator_type: The type of indicator ('ip', 'domain', 'url', 'md5', 'sha1', 'sha256')
        
        Returns:
            Dict containing lookup results with 'status' key
        """
        pass
