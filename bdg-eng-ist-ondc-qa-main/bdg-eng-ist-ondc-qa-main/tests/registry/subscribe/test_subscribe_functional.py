from locust import task
from tests.registry.subscribe.common.base_subscribe_test import RegistrySubscribeBase
import uuid
import base64
import os

"""
================================================================================
ONDC Registry Subscribe API - Functional Tests (Positive Scenarios)
================================================================================
Test File:   ondc_reg_subscribe_functional.py
Base Class:  RegistrySubscribeBase (registry_subscribe_base.py) - SHARED BASE
YAML Config: ondc_reg_subscribe_functional.yml

TC-01 to TC-23: All positive test scenarios
Run with: --users 1 --iterations 5
================================================================================
"""

class ONDCRegSubscribeFunctional(RegistrySubscribeBase):
    """Functional test scenarios for ONDC Registry Subscribe API"""
    
    config_file = 'resources/registry/subscribe/test_subscribe_functional.yml'
    tenant_name = 'ondcRegistry'
    
    # TC-01: Admin Seller Whitelist
    @task(1)
    def tc001_admin_seller_whitelist(self):
        self.step_name = 'TC001_Admin_Seller_Whitelist'
        payload = self._generate_test_payload(np_type='seller', domain='ONDC:RET10')
        success, data, status, response = self._send_admin_subscribe_request(self.step_name, payload)
        
        if success and data:
            # Validate business logic and report to Locust
            if data.get('Success') != True:
                response.failure(f"TC-001: Expected Success=true, got {data.get('Success')}")
                return
            if 'NewStatus' not in data:
                response.failure(f"TC-001: Missing NewStatus in response")
                return
            response.success()
    
    # TC-02: Admin Seller Full Whitelist
    @task(1)
    def tc002_admin_seller_full_whitelist(self):
        self.step_name = 'TC002_Admin_Seller_Full_Whitelist'
        payload = self._generate_test_payload(np_type='seller', domain='ONDC:RET10')
        
        # Add additional optional fields using helper methods
        payload['credentials'].append(
            self._create_credential("PAN", {"pan": "ABCDE1234F", "name": "Business Owner"})
        )
        payload['contacts'].append(
            self._create_contact(
                "BILLING", "Jane Smith", "business@example.com", "+911234567890",
                "123 Finance Street, Mumbai", "Finance Manager", False
            )
        )
        
        success, data, status, response = self._send_admin_subscribe_request(self.step_name, payload)
        if success:
            response.success()
    
    # TC-03: Admin Buyer Whitelist
    @task(1)
    def tc003_admin_buyer_whitelist(self):
        self.step_name = 'TC003_Admin_Buyer_Whitelist'
        payload = self._generate_test_payload(np_type='buyer', domain='ONDC:RET10')
        success, data, status, response = self._send_admin_subscribe_request(self.step_name, payload)
        if success:
            response.success()
    
    # TC-04: Admin Logistics Whitelist
    @task(1)
    def tc004_admin_logistics_whitelist(self):
        self.step_name = 'TC004_Admin_Logistics_Whitelist'
        payload = self._generate_test_payload(np_type='logistics', domain='ONDC:LOG10')
        success, data, status, response = self._send_admin_subscribe_request(self.step_name, payload)
        if success:
            response.success()
    
    # TC-05: Admin Re-whitelist Idempotent
    @task(1)
    def tc005_admin_rewhitelist_idempotent(self):
        self.step_name = 'TC005_Admin_Rewhitelist_Idempotent'
        
        # First subscribe
        payload = self._generate_test_payload(np_type='seller')
        participant_id = payload['participant_id']
        self._send_admin_subscribe_request(f"{self.step_name}_First", payload)
        
        # Re-subscribe with same participant_id (idempotent)
        success, data, status, response = self._send_admin_subscribe_request(self.step_name, payload)
        
        if success and data:
            # Should succeed without error
            if data.get('Success') != True:
                response.failure(f"TC-005: Idempotent re-whitelist should succeed, got Success={data.get('Success')}")
                return
            response.success()
    
    # TC-06: V3 Seller Subscribe
    @task(1)
    def tc006_v3_seller_subscribe(self):
        self.step_name = 'TC006_V3_Seller_Subscribe'
        payload = self._generate_test_payload(np_type='seller', domain='ONDC:RET10')
        success, data, status, response = self._send_v3_subscribe_request(self.step_name, payload)
        if success:
            response.success()
    
    # TC-07: V3 Buyer Subscribe
    @task(1)
    def tc007_v3_buyer_subscribe(self):
        self.step_name = 'TC007_V3_Buyer_Subscribe'
        payload = self._generate_test_payload(np_type='buyer', domain='ONDC:RET10')
        success, data, status, response = self._send_v3_subscribe_request(self.step_name, payload)
        if success:
            response.success()
    
    # TC-08: V3 Logistics Subscribe
    @task(1)
    def tc008_v3_logistics_subscribe(self):
        self.step_name = 'TC008_V3_Logistics_Subscribe'
        payload = self._generate_test_payload(np_type='logistics', domain='ONDC:LOG10')
        success, data, status, response = self._send_v3_subscribe_request(self.step_name, payload)
        if success:
            response.success()
    
    # TC-09: V3 Multi-domain Subscribe
    @task(1)
    def tc009_v3_multidomain_subscribe(self):
        self.step_name = 'TC009_V3_Multidomain_Subscribe'
        payload = self._generate_test_payload(np_type='seller')
        
        # Get the location_id and uri_id from metadata
        location_id = payload.get('_meta', {}).get('location', {}).get('location_id', 'loc001')
        uri_id = payload.get('_meta', {}).get('uri', {}).get('uri_id', 'uri001')
        
        # For V3 API, use 'configs' with multiple domains
        payload['configs'] = [
            {
                "domain": "ONDC:RET10", 
                "np_type": "BPP",
                "subscriber_id": payload['participant_id'],
                "location_id": location_id,
                "uri_id": uri_id,
                "key_id": self.uk_id
            },
            {
                "domain": "ONDC:RET11", 
                "np_type": "BPP",
                "subscriber_id": payload['participant_id'],
                "location_id": location_id,
                "uri_id": uri_id,
                "key_id": self.uk_id
            },
            {
                "domain": "ONDC:RET12", 
                "np_type": "BPP",
                "subscriber_id": payload['participant_id'],
                "location_id": location_id,
                "uri_id": uri_id,
                "key_id": self.uk_id
            }
        ]
        
        # Clean up _meta before sending
        payload.pop('_meta', None)
        
        success, data, status, response = self._send_v3_subscribe_request(self.step_name, payload)
        if success:
            response.success()
    
    # TC-10: V3 Add Contact (PATCH)
    @task(1)
    def tc010_v3_add_contact(self):
        self.step_name = 'TC010_V3_Add_Contact'
        
        # Step 1: Create participant using correct WHITELISTED → SUBSCRIBED workflow
        success, participant_data, response = self._create_whitelisted_and_subscribe(
            self.step_name, np_type='seller', domain='ONDC:RET10'
        )
        if not success or not participant_data:
            if response:
                response.failure(f"{self.step_name}: Workflow setup failed")
            return
        
        # Step 2: V3 PATCH to add contact
        patch_payload = {
            "participant_id": participant_data["participant_id"],
            "uk_id": participant_data["uk_id"],
            "contacts": [
                self._create_contact(
                    "SUPPORT", "Support Team", "support@example.com", "+919876543210",
                    "123 Support Street, Delhi", "Support Manager", False
                )
            ]
        }
        
        success, data, status, response = self._send_v3_patch_request(self.step_name, patch_payload)
        if success:
            response.success()
    
    # TC-11: V3 Add Credential (PATCH)
    @task(1)
    def tc011_v3_add_credential(self):
        self.step_name = 'TC011_V3_Add_Credential'
        
        # Step 1: Create participant using correct WHITELISTED → SUBSCRIBED workflow
        success, participant_data, response = self._create_whitelisted_and_subscribe(
            self.step_name, np_type='seller', domain='ONDC:RET10'
        )
        if not success or not participant_data:
            if response:
                response.failure(f"{self.step_name}: Workflow setup failed")
            return
        
        # Step 2: V3 PATCH to add credential
        patch_payload = {
            "participant_id": participant_data["participant_id"],
            "uk_id": participant_data["uk_id"],
            "credentials": [
                self._create_credential("FSSAI", {"license_number": "12345678901234", "business_name": "Test Food Business"})
            ]
        }
        
        success, data, status, response = self._send_v3_patch_request(self.step_name, patch_payload)
        if success:
            response.success()
    
    # TC-12: V3 Update Additional Data (PATCH)
    @task(1)
    def tc012_v3_update_additional_data(self):
        self.step_name = 'TC012_V3_Update_Additional_Data'
        
        # Step 1: Create participant using correct WHITELISTED → SUBSCRIBED workflow
        success, participant_data, response = self._create_whitelisted_and_subscribe(
            self.step_name, np_type='seller', domain='ONDC:RET10'
        )
        if not success or not participant_data:
            if response:
                response.failure(f"{self.step_name}: Workflow setup failed")
            return
        
        # Step 2: V3 PATCH to update additional_data
        patch_payload = {
            "participant_id": participant_data["participant_id"],
            "uk_id": participant_data["uk_id"],
            "additional_data": {
                "business_name": "Test Business Ltd",
                "website": "https://testbusiness.com"
            }
        }
        
        success, data, status, response = self._send_v3_patch_request(self.step_name, patch_payload)
        if success:
            response.success()
    
    # TC-13: V3 Partial Patch
    @task(1)
    def tc013_v3_partial_patch(self):
        self.step_name = 'TC013_V3_Partial_Patch'
        
        # Step 1: Create participant using correct WHITELISTED → SUBSCRIBED workflow
        success, participant_data, response = self._create_whitelisted_and_subscribe(
            self.step_name, np_type='seller', domain='ONDC:RET10'
        )
        if not success or not participant_data:
            if response:
                response.failure(f"{self.step_name}: Workflow setup failed")
            return
        
        # Step 2: V3 PATCH with minimal fields
        location_id = participant_data.get("locations", [{}])[0].get("location_id", "loc-default")
        patch_payload = {
            "participant_id": participant_data["participant_id"],
            "uk_id": participant_data["uk_id"],
            "location": {
                "location_id": location_id,
                "country": "IND",
                "city": ["std:011", "std:022"],
                "type": "SERVICEABLE"
            }
        }
        
        success, data, status, response = self._send_v3_patch_request(self.step_name, patch_payload)
        if success:
            response.success()
    
    # TC-14: V3 Multi-field Patch
    @task(1)
    def tc014_v3_multifield_patch(self):
        self.step_name = 'TC014_V3_Multifield_Patch'
        
        # Step 1: Create participant using correct WHITELISTED → SUBSCRIBED workflow
        success, participant_data, response = self._create_whitelisted_and_subscribe(
            self.step_name, np_type='seller', domain='ONDC:RET10'
        )
        if not success or not participant_data:
            if response:
                response.failure(f"{self.step_name}: Workflow setup failed")
            return
        
        # Step 2: V3 PATCH multiple fields at once
        location_id = participant_data.get("locations", [{}])[0].get("location_id", "loc-default")
        patch_payload = {
            "participant_id": participant_data["participant_id"],
            "uk_id": participant_data["uk_id"],
            "contacts": [
                self._create_contact("BILLING", "Billing Team", "billing@example.com", "+919876543211",
                                   "123 Finance Street, Mumbai", "Finance Manager", False)
            ],
            "credentials": [
                self._create_credential("PAN", {"pan": "XYZAB9876C", "name": "Test Business Owner"})
            ],
            "location": {
                "location_id": location_id,
                "country": "IND",
                "city": ["std:033", "std:044"],
                "type": "SERVICEABLE"
            }
        }
        
        success, data, status, response = self._send_v3_patch_request(self.step_name, patch_payload)
        if success:
            response.success()
    
    # TC-15: Admin Minimal Payload
    @task(1)
    def tc015_admin_minimal_payload(self):
        self.step_name = 'TC015_Admin_Minimal_Payload'
        
        # Minimal required fields only
        participant_suffix = str(uuid.uuid4())[:8]
        payload = {
            "participant_id": f"seller-minimal-{participant_suffix}",
            "action": "WHITELISTED",
            "keys": {
                "uk_id": str(uuid.uuid4()),
                "signing_public_key": "dummybase64key",
                "encryption_public_key": "dummybase64key"
            },
            "network_participant": [
                {"domain": "ONDC:RET10", "np_type": "seller"}
            ]
        }
        
        success, data, status, response = self._send_admin_subscribe_request(self.step_name, payload, expected_status=[200, 400])
        if success:
            response.success()
    
    # TC-16: Admin Full Payload
    @task(1)
    def tc016_admin_full_payload(self):
        self.step_name = 'TC016_Admin_Full_Payload'
        payload = self._generate_test_payload(np_type='seller')
        
        # Add all optional fields using helper methods
        payload['credentials'].extend([
            self._create_credential("PAN", {"pan": "ABCDE1234F", "name": "Business Owner"}),
            self._create_credential("FSSAI", {"license_number": "12345678901234", "business_name": "Test Food Business"})
        ])
        payload['contacts'].extend([
            self._create_contact("BILLING", "Jane Smith", "business@example.com", "+911234567890", 
                               "123 Finance Street, Mumbai", "Finance Manager", False),
            self._create_contact("SUPPORT", "Support Team", "support@example.com", "+919876543210",
                               "123 Support Street, Delhi", "Support Manager", False)
        ])
        # NOTE: additional_data removed - not supported by Admin API schema
        
        success, data, status, response = self._send_admin_subscribe_request(self.step_name, payload)
        if success:
            response.success()
    
    # TC-17: V3 Signature Rotation
    @task(1)
    def tc017_v3_signature_rotation(self):
        self.step_name = 'TC017_V3_Signature_Rotation'
        
        # Step 1: Create participant using correct WHITELISTED → SUBSCRIBED workflow
        success, participant_data, response = self._create_whitelisted_and_subscribe(
            self.step_name, np_type='seller', domain='ONDC:RET10'
        )
        if not success or not participant_data:
            if response:
                response.failure(f"{self.step_name}: Workflow setup failed")
            return
        
        # Step 2: Rotate keys via PATCH
        new_uk_id = str(uuid.uuid4())
        patch_payload = {
            "participant_id": participant_data["participant_id"],
            "uk_id": participant_data["uk_id"],
            "key": {
                "uk_id": new_uk_id,
                "signing_public_key": base64.b64encode(os.urandom(32)).decode('utf-8'),
                "encryption_public_key": base64.b64encode(os.urandom(32)).decode('utf-8'),
                "signed_algorithm": "ED25519",
                "encryption_algorithm": "X25519",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_until": "2026-12-31T23:59:59Z"
            }
        }
        
        success, data, status, response = self._send_v3_patch_request(self.step_name, patch_payload)
        if success:
            response.success()
    
    # TC-18: V3 Re-subscribe
    @task(1)
    def tc018_v3_resubscribe(self):
        self.step_name = 'TC018_V3_Resubscribe'
        
        # First subscribe
        payload = self._generate_test_payload(np_type='seller')
        participant_id = payload['participant_id']
        self._send_v3_subscribe_request(f"{self.step_name}_First", payload)
        
        # Re-subscribe (idempotent)
        success, data, status, response = self._send_v3_subscribe_request(self.step_name, payload)
        if success:
            response.success()
    
    # TC-19: Buyer Patch Update
    @task(1)
    def tc019_buyer_patch_update(self):
        self.step_name = 'TC019_Buyer_Patch_Update'
        
        # Step 1: Create participant using correct WHITELISTED → SUBSCRIBED workflow
        success, participant_data, response = self._create_whitelisted_and_subscribe(
            self.step_name, np_type='buyer', domain='ONDC:RET10'
        )
        if not success or not participant_data:
            if response:
                response.failure(f"{self.step_name}: Workflow setup failed")
            return
        
        # Step 2: V3 PATCH update
        patch_payload = {
            "participant_id": participant_data["participant_id"],
            "uk_id": participant_data["uk_id"],
            "contacts": [
                self._create_contact("PROCUREMENT", "Procurement Team", "procurement@buyer.com", "+919876543213",
                                   "123 Procurement Street, Bangalore", "Procurement Manager", False)
            ]
        }
        
        success, data, status, response = self._send_v3_patch_request(self.step_name, patch_payload)
        if success:
            response.success()
    
    # TC-20: Logistics Patch Update
    @task(1)
    def tc020_logistics_patch_update(self):
        self.step_name = 'TC020_Logistics_Patch_Update'
        
        # Step 1: Create participant using correct WHITELISTED → SUBSCRIBED workflow
        success, participant_data, response = self._create_whitelisted_and_subscribe(
            self.step_name, np_type='logistics', domain='ONDC:LOG10'
        )
        if not success or not participant_data:
            if response:
                response.failure(f"{self.step_name}: Workflow setup failed")
            return
        
        # Step 2: V3 PATCH update
        location_id = participant_data.get("locations", [{}])[0].get("location_id", "loc-default")
        patch_payload = {
            "participant_id": participant_data["participant_id"],
            "uk_id": participant_data["uk_id"],
            "location": {
                "location_id": location_id,
                "country": "IND",
                "city": ["std:080", "std:011", "std:022", "std:033"],
                "type": "SERVICEABLE"
            }
        }
        
        success, data, status, response = self._send_v3_patch_request(self.step_name, patch_payload)
        if success:
            response.success()
    
    # TC-21: Admin Multi-domain
    @task(1)
    def tc021_admin_multidomain(self):
        self.step_name = 'TC021_Admin_Multidomain'
        payload = self._generate_test_payload(np_type='seller')
        
        # For Admin API, simply add multiple domains to configs
        payload['configs'] = [
            {
                "domain": "ONDC:RET10", 
                "np_type": "BPP",
                "subscriber_id": payload['participant_id']
            },
            {
                "domain": "ONDC:RET11", 
                "np_type": "BPP",
                "subscriber_id": payload['participant_id']
            },
            {
                "domain": "ONDC:AGR10", 
                "np_type": "BPP",
                "subscriber_id": payload['participant_id']
            }
        ]
        
        # Clean up _meta before sending
        payload.pop('_meta', None)
        
        success, data, status, response = self._send_admin_subscribe_request(self.step_name, payload)
        if success:
            response.success()
    
    # TC-22: Admin Buyer Support Contact
    @task(1)
    def tc022_admin_buyer_support_contact(self):
        self.step_name = 'TC022_Admin_Buyer_Support_Contact'
        payload = self._generate_test_payload(np_type='buyer')
        
        # Add support contact using helper method
        payload['contacts'].append(
            self._create_contact(
                "SUPPORT", "Support Team", "support@buyer.com", "+911234567890",
                "123 Support Street, Delhi", "Support Manager", False
            )
        )
        
        success, data, status, response = self._send_admin_subscribe_request(self.step_name, payload)
        if success:
            response.success()
    
    # TC-23: Admin Seller Multiple Credentials
    @task(1)
    def tc023_admin_seller_multiple_credentials(self):
        self.step_name = 'TC023_Admin_Seller_Multiple_Credentials'
        payload = self._generate_test_payload(np_type='seller')
        
        # Multiple credentials using helper methods (only supported types)
        payload['credentials'] = [
            self._create_credential("GST", {"pan": "ABCDE1234F", "gstin": "22ABCDE1234F1Z5", "business_name": "Test Business Ltd"}),
            self._create_credential("PAN", {"pan": "ABCDE1234F", "name": "Test Business Owner"}),
            self._create_credential("FSSAI", {"license_number": "12345678901234", "business_name": "Test Food Business"})
            # NOTE: TRADE_LICENSE removed - not in CREDENTIAL_TYPE enum
        ]
        
        success, data, status, response = self._send_admin_subscribe_request(self.step_name, payload)
        if success:
            response.success()


tasks = [ONDCRegSubscribeFunctional]
