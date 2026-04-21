import random
from locust import task
from tests.registry.subscribe.common.base_subscribe_test import RegistrySubscribeBase

"""
ONDC Registry Subscribe API - Performance Tests
Based on functional tests but with weighted tasks for realistic load testing
Run with: --users 20 --run-time 300 --ramp-up 30
"""

class ONDCRegSubscribePerformance(RegistrySubscribeBase):
    """Performance test scenarios with realistic load distribution"""
    
    config_file = 'resources/registry/subscribe/test_subscribe_functional.yml'
    tenant_name = 'ondcRegistry'
    
    # Common scenario: Admin whitelisting (20% weight)
    @task(20)
    def perf_admin_seller_whitelist(self):
        self.step_name = 'Perf_Admin_Seller_Whitelist'
        payload = self._generate_test_payload(np_type='seller')
        success, data, status = self._send_admin_subscribe_request(
            self.step_name, payload
        )
    
    @task(15)
    def perf_admin_buyer_whitelist(self):
        self.step_name = 'Perf_Admin_Buyer_Whitelist'
        payload = self._generate_test_payload(np_type='buyer')
        success, data, status = self._send_admin_subscribe_request(
            self.step_name, payload
        )
    
    @task(10)
    def perf_admin_logistics_whitelist(self):
        self.step_name = 'Perf_Admin_Logistics_Whitelist'
        payload = self._generate_test_payload(np_type='logistics')
        success, data, status = self._send_admin_subscribe_request(
            self.step_name, payload
        )
    
    # Common scenario: V3 Subscribe (30% weight)
    @task(30)
    def perf_v3_seller_subscribe(self):
        self.step_name = 'Perf_V3_Seller_Subscribe'
        payload = self._generate_test_payload(np_type='seller')
        success, data, status = self._send_v3_subscribe_request(
            self.step_name, payload
        )
    
    @task(20)
    def perf_v3_buyer_subscribe(self):
        self.step_name = 'Perf_V3_Buyer_Subscribe'
        payload = self._generate_test_payload(np_type='buyer')
        success, data, status = self._send_v3_subscribe_request(
            self.step_name, payload
        )
    
    @task(15)
    def perf_v3_logistics_subscribe(self):
        self.step_name = 'Perf_V3_Logistics_Subscribe'
        payload = self._generate_test_payload(np_type='logistics')
        success, data, status = self._send_v3_subscribe_request(
            self.step_name, payload
        )
    
    # Multi-domain scenarios (10% weight)
    @task(10)
    def perf_v3_multi_domain_subscribe(self):
        self.step_name = 'Perf_V3_Multi_Domain_Subscribe'
        
        # Multi-domain payload
        pid = f"multi-domain-{random.randint(1000, 9999)}.participant.ondc"
        loc_id = f"loc_{random.randint(1000,9999)}"
        uri_id1 = f"uri_{random.randint(1000,9999)}"
        uri_id2 = f"uri_{random.randint(2000,2999)}"
        payload = {
            "participant_id": pid,
            "action": "SUBSCRIBE",
            "credentials": [
                {"type": "GST", "cred_data": {"gstin": "22ABCDE1234F1Z5"}}
            ],
            "contacts": [
                {"type": "TECHNICAL", "email": f"tech{random.randint(100, 999)}@example.com"}
            ],
            "key": {
                "uk_id": self.uk_id,
                "signing_public_key": self.signing_public_key,
                "encryption_public_key": self.encryption_public_key,
                "signed_algorithm": "ED25519",
                "encryption_algorithm": "X25519",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_until": "2025-12-31T23:59:59Z"
            },
            "uri": {
                "uri_id": uri_id1,
                "type": "SUBSCRIBER_URL",
                "url": "https://multi-domain.example.com/ondc"
            },
            "location": {
                "location_id": loc_id,
                "country": "IND",
                "city": random.sample(self.cities, 2),
                "type": "SERVICEABLE"  # V3: UPPERCASE enum
            },
            "configs": [
                {"subscriber_id": pid, "key_id": self.uk_id, "domain": "ONDC:RET10", "np_type": "BPP", "location_id": loc_id, "uri_id": uri_id1},
                {"subscriber_id": pid, "key_id": self.uk_id, "domain": "ONDC:RET12", "np_type": "BPP", "location_id": loc_id, "uri_id": uri_id2}
            ]
        }
        
        success, data, status = self._send_v3_subscribe_request(
            self.step_name, payload
        )
    
    # PATCH operations (15% weight)
    @task(15)
    def perf_v3_patch_add_contact(self):
        self.step_name = 'Perf_V3_PATCH_Add_Contact'
        
        # First subscribe
        participant_id = f"patch-contact-{random.randint(1000, 9999)}"
        subscribe_payload = self._generate_test_payload(np_type='seller')
        subscribe_payload['participant_id'] = participant_id
        
        success, data, status = self._send_v3_subscribe_request(
            f"{self.step_name}_Subscribe", subscribe_payload
        )
        
        if success:
            # Then patch - add new contact
            patch_payload = {
                "participant_id": participant_id,
                "contacts": [
                    {"contact_type": "SUPPORT", "email": f"support{random.randint(100, 999)}@example.com", "phone": "+91-9876543210"}
                ]
            }
            
            success, data, status = self._send_v3_patch_request(
                self.step_name, patch_payload
            )
    
    @task(10)
    def perf_v3_patch_add_credential(self):
        self.step_name = 'Perf_V3_PATCH_Add_Credential'
        
        # First subscribe
        participant_id = f"patch-cred-{random.randint(1000, 9999)}"
        subscribe_payload = self._generate_test_payload(np_type='seller')
        subscribe_payload['participant_id'] = participant_id
        
        success, data, status = self._send_v3_subscribe_request(
            f"{self.step_name}_Subscribe", subscribe_payload
        )
        
        if success:
            # Then patch - add new credential
            patch_payload = {
                "participant_id": participant_id,
                "credentials": [
                    {"cred_type": "PAN", "cred_data": {"pan_number": "ABCDE1234F"}}
                ]
            }
            
            success, data, status = self._send_v3_patch_request(
                self.step_name, patch_payload
            )
    
    @task(8)
    def perf_v3_patch_update_additional_data(self):
        self.step_name = 'Perf_V3_PATCH_Update_Additional_Data'
        
        # First subscribe
        participant_id = f"patch-data-{random.randint(1000, 9999)}"
        subscribe_payload = self._generate_test_payload(np_type='seller')
        subscribe_payload['participant_id'] = participant_id
        
        success, data, status = self._send_v3_subscribe_request(
            f"{self.step_name}_Subscribe", subscribe_payload
        )
        
        if success:
            # Then patch - update additional data
            patch_payload = {
                "participant_id": participant_id,
                "additional_data": {
                    "business_name": f"Updated Business {random.randint(100, 999)}",
                    "description": "Performance test participant",
                    "category": "Retail"
                }
            }
            
            success, data, status = self._send_v3_patch_request(
                self.step_name, patch_payload
            )
    
    # Re-subscribe scenarios (5% weight)
    @task(5)
    def perf_v3_re_subscribe(self):
        self.step_name = 'Perf_V3_Re_Subscribe'
        
        participant_id = f"resubscribe-{random.randint(1000, 9999)}"
        payload = self._generate_test_payload(np_type='seller')
        payload['participant_id'] = participant_id
        
        # First subscribe
        success, data, status = self._send_v3_subscribe_request(
            f"{self.step_name}_First", payload
        )
        
        # Re-subscribe with same data (should be idempotent)
        success, data, status = self._send_v3_subscribe_request(
            self.step_name, payload
        )
    
    # Minimal payload scenarios (5% weight)
    @task(5)
    def perf_admin_minimal_payload(self):
        self.step_name = 'Perf_Admin_Minimal_Payload'
        
        # Minimal required fields only
        pid = f"minimal-{random.randint(1000, 9999)}.participant.ondc"
        loc_id = f"loc_{random.randint(1000,9999)}"
        uri_id = f"uri_{random.randint(1000,9999)}"
        payload = {
            "participant_id": pid,
            "action": "WHITELISTED",
            "key": {
                "uk_id": self.uk_id,
                "signing_public_key": self.signing_public_key,
                "encryption_public_key": self.encryption_public_key,
                "signed_algorithm": "ED25519",
                "encryption_algorithm": "X25519",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_until": "2025-12-31T23:59:59Z"
            },
            "uri": {
                "uri_id": uri_id,
                "type": "SUBSCRIBER_URL",
                "url": "https://minimal.example.com/ondc"
            },
            "location": {
                "location_id": loc_id,
                "country": "IND",
                "city": ["std:080"],
                "type": "SERVICEABLE"  # V3: UPPERCASE enum
            },
            "configs": [
                {"subscriber_id": pid, "key_id": self.uk_id, "domain": "ONDC:RET10", "np_type": "BPP", "location_id": loc_id, "uri_id": uri_id}
            ]
        }
        
        success, data, status = self._send_admin_subscribe_request(
            self.step_name, payload
        )
    
    # Full payload scenarios (7% weight)
    @task(7)
    def perf_admin_full_payload(self):
        self.step_name = 'Perf_Admin_Full_Payload'
        
        pid = f"full-payload-{random.randint(1000, 9999)}.participant.ondc"
        loc_id = f"loc_{random.randint(1000,9999)}"
        uri_id = f"uri_{random.randint(1000,9999)}"
        payload = {
            "participant_id": pid,
            "action": "WHITELISTED",
            "credentials": [
                {"type": "GST", "cred_data": {"gstin": "22ABCDE1234F1Z5"}},
                {"type": "PAN", "cred_data": {"pan_number": "ABCDE1234F"}}
            ],
            "contacts": [
                {"type": "TECHNICAL", "email": f"tech{random.randint(100, 999)}@example.com", "phone": "+91-9876543210"},
                {"type": "SUPPORT", "email": f"support{random.randint(100, 999)}@example.com", "phone": "+91-9876543211"}
            ],
            "key": {
                "uk_id": self.uk_id,
                "signing_public_key": self.signing_public_key,
                "encryption_public_key": self.encryption_public_key,
                "signed_algorithm": "ED25519",
                "encryption_algorithm": "X25519",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_until": "2025-12-31T23:59:59Z"
            },
            "uri": {
                "uri_id": uri_id,
                "type": "SUBSCRIBER_URL",
                "url": "https://full.example.com/ondc"
            },
            "location": {
                "location_id": loc_id,
                "country": "IND",
                "city": ["std:080", "std:011"],
                "type": "SERVICEABLE"  # V3: UPPERCASE enum
            },
            "configs": [
                {"subscriber_id": pid, "key_id": self.uk_id, "domain": "ONDC:RET10", "np_type": "BPP", "location_id": loc_id, "uri_id": uri_id}
            ],
            "additional_data": {
                "business_name": f"Full Business {random.randint(100, 999)}",
                "description": "Comprehensive participant data",
                "website": "https://full.example.com"
            }
        }
        
        success, data, status = self._send_admin_subscribe_request(
            self.step_name, payload
        )


tasks = [ONDCRegSubscribePerformance]
