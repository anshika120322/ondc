"""
ONDC Lookup Helper
Discovers participants (buyers and sellers) using the lookup API
"""

import requests
from typing import Dict, List, Any, Optional


class ONDCLookupHelper:
    """Helper class for ONDC participant lookup"""
    
    def __init__(self, lookup_url: str):
        """
        Initialize lookup helper with a persistent session for connection pooling
        
        Args:
            lookup_url: URL of the lookup API endpoint
        """
        self.lookup_url = lookup_url
        self.session = requests.Session()  # Use persistent session for connection pooling
    
    def lookup(self, domain: str, participant_type: str, city: str,
               country: str = "IND", core_version: str = "1.2.0",
               timeout: int = 10) -> Dict[str, Any]:
        """
        Query the lookup API
        
        Args:
            domain: ONDC domain (e.g., "ONDC:RET10")
            participant_type: "BPP" (seller) or "BAP" (buyer)
            city: City code (e.g., "std:080")
            country: Country code (default: "IND")
            core_version: ONDC core version (default: "1.2.0")
            timeout: Request timeout in seconds
            
        Returns:
            Dictionary with lookup results
        """
        payload = {
            "domain": domain,
            "type": participant_type,
            "city": city,
            "country": country,
            "core_version": core_version
        }
        
        try:
            response = self.session.post(
                self.lookup_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=timeout
            )
            
            if response.status_code == 200:
                return {
                    "success": True,
                    "data": response.json(),
                    "status_code": response.status_code,
                    "query": payload
                }
            else:
                return {
                    "success": False,
                    "error": f"Status {response.status_code}",
                    "response": response.text,
                    "status_code": response.status_code,
                    "query": payload
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "query": payload
            }
    
    def discover_participants(self, domains: List[str], cities: List[str],
                            participant_types: List[str] = ["BPP", "BAP"]) -> Dict[str, Any]:
        """
        Discover all participants across multiple domains and cities
        
        Args:
            domains: List of ONDC domains
            cities: List of city codes
            participant_types: List of participant types (default: ["BPP", "BAP"])
            
        Returns:
            Dictionary with discovery results including counts and participant lists
        """
        results = {
            "summary": {
                "total_queries": 0,
                "successful_queries": 0,
                "failed_queries": 0,
                "bpp_count": 0,
                "bap_count": 0
            },
            "participants": {
                "BPP": {},
                "BAP": {}
            },
            "queries": []
        }
        
        for domain in domains:
            for city in cities:
                for ptype in participant_types:
                    results["summary"]["total_queries"] += 1
                    
                    result = self.lookup(domain, ptype, city)
                    results["queries"].append(result)
                    
                    if result["success"]:
                        results["summary"]["successful_queries"] += 1
                        
                        # Parse participants from response
                        data = result.get("data", [])
                        if isinstance(data, list):
                            participant_count = len(data)
                        elif isinstance(data, dict):
                            participant_count = 1
                            data = [data]
                        else:
                            participant_count = 0
                            data = []
                        
                        if participant_count > 0:
                            key = f"{domain}:{city}"
                            if key not in results["participants"][ptype]:
                                results["participants"][ptype][key] = []
                            
                            results["participants"][ptype][key].extend(data)
                            
                            if ptype == "BPP":
                                results["summary"]["bpp_count"] += participant_count
                            else:
                                results["summary"]["bap_count"] += participant_count
                    else:
                        results["summary"]["failed_queries"] += 1
        
        return results
    
    def get_participant_count(self, domain: str = None, city: str = None,
                            participant_type: str = None) -> int:
        """
        Get count of participants for specific criteria
        
        Args:
            domain: Filter by domain (optional)
            city: Filter by city (optional)
            participant_type: Filter by type "BPP" or "BAP" (optional)
            
        Returns:
            Count of matching participants
        """
        count = 0
        
        domains = [domain] if domain else ["ONDC:RET10", "ONDC:RET11", "ONDC:RET12"]
        cities = [city] if city else ["std:080", "std:022", "std:011"]
        types = [participant_type] if participant_type else ["BPP", "BAP"]
        
        for d in domains:
            for c in cities:
                for t in types:
                    result = self.lookup(d, t, c)
                    if result["success"]:
                        data = result.get("data", [])
                        if isinstance(data, list):
                            count += len(data)
                        elif isinstance(data, dict):
                            count += 1
        
        return count
    
    def close(self):
        """Close the requests session to free up connections"""
        if self.session:
            self.session.close()
