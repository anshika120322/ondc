"""
Test Data Generator

Generates realistic test data for participant registration and updates.
"""

import random
import string
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional


class DataGenerator:
    """Generates test data for ONDC Registry participants."""
    
    # Available city codes
    CITY_CODES = [
        "std:011", "std:022", "std:033", "std:040", "std:044",
        "std:080", "std:0120", "std:020", "std:079", "std:0124",
        "std:0422", "std:0484", "std:0821", "std:0172", "std:0183", "std:0495"
    ]
    
    # Available domains
    DOMAINS = [
        "ONDC:RET10", "ONDC:RET11", "ONDC:RET12", "ONDC:RET13",
        "ONDC:RET14", "ONDC:LOG", "ONDC:FIS10", "ONDC:FIS11", "ONDC:FIS12"
    ]
    
    # Network participant types
    NP_TYPES = ["SELLER", "BUYER", "LOGISTICS", "GATEWAY"]
    
    def __init__(self, seed: Optional[int] = None):
        """
        Initialize data generator.
        
        Args:
            seed: Random seed for reproducibility
        """
        if seed:
            random.seed(seed)
    
    @staticmethod
    def generate_subscriber_id(prefix: str = "test", suffix: Optional[str] = None) -> str:
        """
        Generate unique subscriber ID.
        
        Args:
            prefix: Prefix for the ID
            suffix: Optional suffix (uses random string if None)
            
        Returns:
            Subscriber ID in format: prefix-app-{suffix}.example.com
        """
        if not suffix:
            suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"{prefix}-app-{suffix}.example.com"
    
    @staticmethod
    def generate_unique_key_id(prefix: str = "UK") -> str:
        """
        Generate unique key ID.
        
        Args:
            prefix: Prefix for the key ID
            
        Returns:
            Unique key ID (e.g., "UK0001") - minimum 6 characters
        """
        return f"{prefix}{random.randint(1000, 9999)}"
    
    @staticmethod
    def generate_email(subscriber_id: str) -> str:
        """Generate email from subscriber ID."""
        domain = subscriber_id.split('.', 1)[-1]  # Get domain part
        return f"support@{domain}"
    
    @staticmethod
    def generate_phone() -> str:
        """Generate random Indian phone number."""
        return f"+91{random.randint(7000000000, 9999999999)}"
    
    @staticmethod
    def generate_url(subscriber_id: str, path: str = "") -> str:
        """Generate URL from subscriber ID."""
        return f"https://{subscriber_id}{path}"
    
    def generate_credential(
        self,
        cred_type: str = "GST",
        cred_id: Optional[str] = None
    ) -> Dict:
        """
        Generate credential object.
        
        Args:
            cred_type: Credential type (GST, PAN, etc.)
            cred_id: Credential ID (generates if None)
            
        Returns:
            Credential dictionary
        """
        if not cred_id:
            cred_id = f"cred_{cred_type.lower()}_{random.randint(100, 999)}"
        
        cred_data = {}
        if cred_type == "GST":
            cred_data = {
                "gstin": f"29ABCDE{random.randint(1000, 9999)}F1Z5",
                "legal_name": "Example Retail Pvt Ltd"
            }
        elif cred_type == "PAN":
            cred_data = {
                "pan": f"ABCDE{random.randint(1000, 9999)}F"
            }
        
        return {
            "cred_id": cred_id,
            "type": cred_type,
            "cred_data": cred_data
        }
    
    def generate_contact(
        self,
        contact_type: str = "TECHNICAL",
        contact_id: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None
    ) -> Dict:
        """
        Generate contact object.
        
        Args:
            contact_type: Contact type (TECHNICAL, BUSINESS, etc.)
            contact_id: Contact ID (generates if None)
            email: Email address (generates if None)
            phone: Phone number (generates if None)
            
        Returns:
            Contact dictionary
        """
        if not contact_id:
            contact_id = f"contact_{contact_type.lower()}_{random.randint(100, 999)}"
        
        return {
            "contact_id": contact_id,
            "type": contact_type,
            "name": f"{contact_type.title()} Support",
            "email": email or f"test{random.randint(1000, 9999)}@example.com",
            "phone": phone or self.generate_phone(),
            "designation": f"{contact_type.title()} Lead"
        }
    
    def generate_location(
        self,
        location_id: Optional[str] = None,
        num_cities: int = 1
    ) -> Dict:
        """
        Generate location object.
        
        Args:
            location_id: Location ID (generates if None)
            num_cities: Number of cities to include
            
        Returns:
            Location dictionary
        """
        if not location_id:
            location_id = f"loc{random.randint(100, 999)}"
        
        cities = random.sample(self.CITY_CODES, min(num_cities, len(self.CITY_CODES)))
        return {
            "location_id": location_id,
            "type": "WAREHOUSE",
            "country": "IND",
            "city": cities
        }
    
    def generate_uri(
        self,
        subscriber_id: str,
        uri_id: Optional[str] = None,
        uri_type: str = "CALLBACK"
    ) -> Dict:
        """
        Generate URI object.
        
        Args:
            subscriber_id: Subscriber ID for URL generation
            uri_id: URI ID (generates if None)
            uri_type: URI type (CALLBACK, WEBHOOK, etc.)
            
        Returns:
            URI dictionary
        """
        if not uri_id:
            uri_id = f"uri_{uri_type.lower()}_{random.randint(100, 999)}"
        
        return {
            "uri_id": uri_id,
            "type": uri_type,
            "url": self.generate_url(subscriber_id, "/callback"),
            "description": f"{uri_type.title()} endpoint"
        }
    
    def generate_key(
        self,
        signing_public_key: Optional[str] = None,
        encryption_public_key: Optional[str] = None,
        algorithm: str = "ED25519"
    ) -> Dict:
        """
        Generate key object.
        
        Args:
            signing_public_key: Signing public key (generates if None)
            encryption_public_key: Encryption public key (generates if None)
            algorithm: Algorithm name
            
        Returns:
            Key dictionary
        """
        if not signing_public_key:
            signing_public_key = ''.join(random.choices(string.ascii_letters + string.digits, k=44))
        if not encryption_public_key:
            encryption_public_key = signing_public_key  # Use same for simplicity
        
        now = datetime.now(timezone.utc)
        valid_until = now + timedelta(days=365)
        
        return {
            "signing_public_key": signing_public_key,
            "encryption_public_key": encryption_public_key,
            "valid_from": now.isoformat(),
            "valid_until": valid_until.isoformat()
        }
    
    def generate_config(
        self,
        subscriber_id: str,
        domain: Optional[str] = None,
        np_type: Optional[str] = None,
        location_id: Optional[str] = None,
        uri_id: Optional[str] = None,
        keys_id: Optional[str] = None
    ) -> Dict:
        """
        Generate config object for a domain.
        
        Args:
            subscriber_id: Subscriber ID (required in config)
            domain: Domain name (random if None)
            np_type: Network participant type (random if None)
            location_id: Location ID reference
            uri_id: URI ID reference
            keys_id: Keys ID reference
            
        Returns:
            Config dictionary
        """
        if not domain:
            domain = random.choice(self.DOMAINS)
        if not np_type:
            np_type = random.choice(self.NP_TYPES)
        
        config = {
            "domain": domain,
            "np_type": np_type,
            "subscriber_id": subscriber_id
        }
        
        if location_id:
            config["location_id"] = location_id
        if uri_id:
            config["uri_id"] = uri_id
        if keys_id:
            config["keys_id"] = keys_id
        
        return config
    
    def generate_complete_participant(
        self,
        subscriber_id: Optional[str] = None,
        action: str = "WHITELISTED",
        num_domains: int = 1,
        num_cities: int = 1,
        include_all_fields: bool = True
    ) -> Dict:
        """
        Generate complete participant data.
        
        Args:
            subscriber_id: Subscriber ID (generates if None)
            action: Action/Status (WHITELISTED, SUBSCRIBED, etc.)
            num_domains: Number of domains
            num_cities: Number of cities in location
            include_all_fields: Include all optional fields
            
        Returns:
            Complete participant data dictionary
        """
        if not subscriber_id:
            subscriber_id = self.generate_subscriber_id()
        
        email = self.generate_email(subscriber_id)
        unique_key_id = self.generate_unique_key_id()
        location_id = f"loc{random.randint(100, 999)}"
        uri_id = f"uri_callback_{random.randint(100, 999)}"
        keys_id = unique_key_id
        
        # Base required data
        data = {
            "participant_id": subscriber_id,
            "action": action,
            "configs": [self.generate_config(
                subscriber_id,
                location_id=location_id if include_all_fields else None,
                uri_id=uri_id if include_all_fields else None,
                keys_id=keys_id if include_all_fields else None
            ) for _ in range(num_domains)]
        }
        
        # Add optional fields
        if include_all_fields:
            data["credentials"] = [self.generate_credential("GST")]
            data["contacts"] = [self.generate_contact("TECHNICAL", email=email)]
            data["location"] = self.generate_location(location_id, num_cities)
            data["uri"] = self.generate_uri(subscriber_id, uri_id)
            data["key"] = self.generate_key(keys_id)
        
        return data
    
    def generate_patch_update(
        self,
        update_type: str,
        subscriber_id: Optional[str] = None,
        new_status: Optional[str] = None
    ) -> Dict:
        """
        Generate PATCH update data.
        
        Args:
            update_type: Type of update (status, credentials, contacts, etc.)
            subscriber_id: Subscriber ID (for URL/email generation)
            new_status: New status (for status updates)
            
        Returns:
            PATCH update data
        """
        data = {}
        
        if subscriber_id:
            data["subscriber_id"] = subscriber_id
        
        if update_type == "status" and new_status:
            data["action"] = new_status
        
        elif update_type == "credentials":
            data["credentials"] = [
                self.generate_credential("SIGNING"),
                self.generate_credential("ENCRYPTION")
            ]
        
        elif update_type == "contacts":
            email = self.generate_email(subscriber_id) if subscriber_id else None
            data["contacts"] = [self.generate_contact(email=email)]
        
        elif update_type == "location":
            data["location"] = self.generate_location(2)
        
        elif update_type == "uri":
            if subscriber_id:
                data["uri"] = [self.generate_uri(subscriber_id)]
        
        elif update_type == "key":
            data["key"] = [self.generate_key()]
        
        elif update_type == "configs":
            data["configs"] = [self.generate_config()]
        
        return data
