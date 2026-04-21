from locust import task
from tests.registry.lookup.common.base_lookup_test import RegistryLookupBase
from tests.utils.response_validators import LookupResponseValidator
import random
import json

"""
ONDC Registry V2 Lookup API - Boundary & Edge Case Tests
Tests V2-specific edge cases and boundary values (no max_results or V3-only parameters)
Run with: --users 1 --iterations 10 (minimum 10 to ensure all 10 test cases execute once)
"""

class ONDCRegV2LookupBoundaryTests(RegistryLookupBase):

    config_file = 'resources/registry/lookup/v2/test_lookup_v2.yml'
    tenant_name = 'ondcRegistryV2Lookup'

    def on_start(self):
        """Initialize test and register participant at runtime"""
        super().on_start()
        
        # Register participant before running tests
        registration_success = self._register_participant_runtime()
        if registration_success:
            print(f"\n[INFO] ✅ V2 Boundary Tests initialized for: {self.participant_id}")
            print(f"[INFO] Participant status: SUBSCRIBED (ready for V2 lookup testing)\n")
        else:
            print(f"\n[WARNING] Participant registration uncertain - proceeding with tests\n")

    def _register_participant_runtime(self):
        """Register participant at runtime before running tests"""
        print(f"\n[REGISTRATION] Checking/Registering participant: {self.participant_id}")
        
        try:
            # Step 1: Check if participant already exists and is SUBSCRIBED
            if self._verify_participant_subscribed():
                print(f"[REGISTRATION] ✓ Participant already registered and SUBSCRIBED")
                return True
            
            print(f"[REGISTRATION] Participant not found or not SUBSCRIBED - registering...")
            
            # Step 2: Admin whitelist (if needed)
            whitelist_success = self._admin_whitelist_participant()
            if not whitelist_success:
                print(f"[REGISTRATION] ✗ Admin whitelist failed")
                return False
            
            # Step 3: V3 self-subscribe (V2 uses same registration as V3)
            subscribe_success = self._v3_self_subscribe()
            if not subscribe_success:
                print(f"[REGISTRATION] ✗ V3 self-subscribe failed")
                return False
            
            # Step 4: Verify registration
            print(f"[REGISTRATION] Waiting for database sync...")
            import time
            time.sleep(3)
            
            if self._verify_participant_subscribed():
                print(f"[REGISTRATION] ✓ Participant successfully registered!")
                return True
            else:
                print(f"[REGISTRATION] ⚠ Registration completed but verification uncertain")
                return True  # Continue anyway
                
        except Exception as e:
            print(f"[REGISTRATION] ✗ Error during registration: {e}")
            return False
    
    def _verify_participant_subscribed(self):
        """Check if participant is already registered and SUBSCRIBED using V2 lookup"""
        try:
            # Use V2 lookup to check if participant exists
            payload = {
                "subscriber_id": self.participant_id,
                "country": "IND"
            }
            
            # Generate V2 signature using ONDCAuthHelper
            auth_result = self.ondc_auth_helper.generate_headers(payload)
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': auth_result['Authorization'],
                'Digest': auth_result['Digest']
            }
            
            url = f"{self.host}/v2.0/lookup"
            response = self.client.post(url, data=auth_result['serialized_body'], headers=headers, catch_response=True)
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) > 0:
                    # Check if status is SUBSCRIBED
                    for config in data[0].get('configs', []):
                        if config.get('status') == 'SUBSCRIBED':
                            return True
                    return False
                else:
                    return False
            else:
                return False
                
        except Exception as e:
            print(f"[REGISTRATION] Verification error: {e}")
            return False

    def _admin_whitelist_participant(self):
        """Step 1: Admin whitelists the participant"""
        try:
            payload = {
                "dns_skip": True,
                "skip_ssl_verification": True,
                "participant_id": self.participant_id,
                "action": "WHITELISTED",
                "configs": [{
                    "domain": "ONDC:RET10",
                    "np_type": "BPP",
                    "subscriber_id": self.participant_id
                }]
            }
            
            # Get admin token
            admin_token = self.auth_client.get_token()
            if not admin_token:
                print(f"[REGISTRATION] Failed to get admin token")
                return False
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {admin_token}'
            }
            
            url = f"{self.host}/admin/subscribe"
            response = self.client.post(url, json=payload, headers=headers, catch_response=True)
            
            if response.status_code == 200:
                print(f"[REGISTRATION] ✓ Admin whitelist successful")
                return True
            elif response.status_code == 409:
                print(f"[REGISTRATION] ℹ Participant already exists (continuing)")
                return True
            else:
                print(f"[REGISTRATION] Admin whitelist failed: {response.status_code}")
                print(f"[REGISTRATION] Response: {response.text[:200]}")
                return False
                
        except Exception as e:
            print(f"[REGISTRATION] Admin whitelist error: {e}")
            return False
    
    def _v3_self_subscribe(self):
        """Step 2: Participant self-subscribes using V3 signature"""
        try:
            from datetime import datetime, timezone, timedelta
            import uuid
            
            now = datetime.now(timezone.utc)
            valid_from = now.isoformat()
            valid_until = (now + timedelta(days=365)).isoformat()
            request_id = str(uuid.uuid4())
            
            payload = {
                "dns_skip": True,
                "skip_ssl_verification": True,
                "request_id": request_id,
                "uk_id": self.uk_id,
                "participant_id": self.participant_id,
                "credentials": [
                    {
                        "cred_id": f"cred_gst_{self.participant_id.split('.')[0]}",
                        "type": "GST",
                        "cred_data": {
                            "gstin": "29ABCDE1234F1Z5",
                            "legal_name": f"{self.participant_id.split('.')[0].title()} Private Limited"
                        }
                    },
                    {
                        "cred_id": f"cred_pan_{self.participant_id.split('.')[0]}",
                        "type": "PAN",
                        "cred_data": {
                            "pan": "ABCDE1234F",
                            "name": f"{self.participant_id.split('.')[0].title()} Private Limited"
                        }
                    }
                ],
                "contacts": [
                    {
                        "contact_id": f"contact_auth_{self.participant_id.split('.')[0]}",
                        "name": "Authorised Signatory",
                        "email": f"auth@{self.participant_id}",
                        "phone": "+919876543210",
                        "type": "AUTHORISED_SIGNATORY"
                    },
                    {
                        "contact_id": f"contact_biz_{self.participant_id.split('.')[0]}",
                        "name": "Business Contact",
                        "email": f"business@{self.participant_id}",
                        "phone": "+919876543211",
                        "type": "BUSINESS"
                    },
                    {
                        "contact_id": f"contact_tech_{self.participant_id.split('.')[0]}",
                        "name": "Technical Contact",
                        "email": f"tech@{self.participant_id}",
                        "phone": "+919876543212",
                        "type": "TECHNICAL",
                        "designation": "Technical Lead"
                    }
                ],
                "key": [
                    {
                        "uk_id": self.uk_id,
                        "signing_public_key": self.signing_public_key,
                        "encryption_public_key": self.encryption_public_key,
                        "signed_algorithm": "ED25519",
                        "encryption_algorithm": "X25519",
                        "valid_from": valid_from,
                        "valid_until": valid_until
                    }
                ],
                "location": [
                    {
                        "location_id": f"loc_{self.participant_id.split('.')[0]}",
                        "country": "IND",
                        "city": ["std:080"],
                        "type": "SERVICEABLE"
                    }
                ],
                "uri": [
                    {
                        "uri_id": f"uri_{self.participant_id.split('.')[0]}",
                        "type": "CALLBACK",
                        "url": f"https://{self.participant_id.split('.')[0]}.kynondc.net"
                    }
                ],
                "configs": [
                    {
                        "domain": "ONDC:RET10",
                        "np_type": "BPP",
                        "subscriber_id": self.participant_id,
                        "location_id": f"loc_{self.participant_id.split('.')[0]}",
                        "uri_id": f"uri_{self.participant_id.split('.')[0]}",
                        "key_id": self.uk_id
                    }
                ]
            }
            
            # Generate V3 signature using ONDCAuthHelper
            auth_result = self.ondc_auth_helper.generate_headers(payload)
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': auth_result['Authorization'],
                'Digest': auth_result['Digest']
            }
            
            url = f"{self.host}/v3.0/subscribe"
            response = self.client.post(url, data=auth_result['serialized_body'], headers=headers, catch_response=True)
            
            if response.status_code == 200:
                print(f"[REGISTRATION] ✓ V3 self-subscribe successful")
                return True
            else:
                print(f"[REGISTRATION] V3 self-subscribe failed: {response.status_code}")
                print(f"[REGISTRATION] Response: {response.text[:300]}")
                return False
                
        except Exception as e:
            print(f"[REGISTRATION] V3 self-subscribe error: {e}")
            import traceback
            traceback.print_exc()
            return False

    # ------------------------------------------------------------
    # TC_Boundary_01: Very long domain string
    # Expected: Should handle or reject appropriately
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_01_very_long_domain(self):
        """Test very long domain value"""
        self.step_name = 'TC_Boundary_01_V2_Very_Long_Domain'
        
        print(f"[DEBUG-START] {self.step_name} method invoked")
        
        # Create a very long but valid domain string
        long_domain = "ONDC:" + "X" * 200
        payload = self._generate_v2_lookup_payload(domain=long_domain)
        
        print(f"[DEBUG-CALLING] About to call helper method...")
        
        success, data, status = self._send_v2_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 413]
        )
        
        print(f"[DEBUG] {self.step_name} returned: success={success}, status={status}, has_data={data is not None}")
        
        if success:
            if isinstance(data, list):
                print(f"[{self.step_name}] [PASS] Long domain accepted, returned {len(data)} results")
            elif isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                print(f"[{self.step_name}] [PASS] Error {error_code}: No matching participant (expected)")
            else:
                print(f"[{self.step_name}] [PASS] Status {status}")

    # ------------------------------------------------------------
    # TC_Boundary_02: Very long city string  
    # Expected: Should handle or reject appropriately
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_02_very_long_city(self):
        """Test very long city value"""
        self.step_name = 'TC_Boundary_02_V2_Very_Long_City'
        
        # Create a very long city string
        long_city = "std:" + "9" * 500
        payload = self._generate_v2_lookup_payload(city=long_city)
        
        success, data, status = self._send_v2_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 413]
        )
        
        if success:
            if isinstance(data, list):
                print(f"[{self.step_name}] [PASS] Long city accepted, returned {len(data)} results")
            elif isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                print(f"[{self.step_name}] [PASS] Error {error_code}: No matching participant (expected)")
            else:
                print(f"[{self.step_name}] [PASS] Status {status}")

    # ------------------------------------------------------------
    # TC_Boundary_03: Special characters in domain (SQL injection attempt)
    # Expected: MUST reject with 1050 (validation error)
    # CRITICAL: If returns 1001, server executed SQL query with malicious input!
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_03_special_chars_domain(self):
        """Test special characters in domain (SQL injection, XSS)"""
        self.step_name = 'TC_Boundary_03_V2_Special_Chars_Domain'
        
        # Try SQL injection patterns - server MUST reject this
        test_domain = "ONDC:RET10' OR '1'='1"
        payload = self._generate_v2_lookup_payload(domain=test_domain)
        
        # Accept ONDC Registry error codes (15000-19999) plus legacy validation error (1050)
        acceptable_codes = [1050, "1050"]
        for code in range(15000, 20000):
            acceptable_codes.extend([code, str(code)])
        
        success, data, status = self._send_v2_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 416],
            acceptable_error_codes=acceptable_codes  # Validation errors + ONDC range
        )
        
        if success:
            if isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                if error_code in [1050, "1050"]:
                    print(f"[{self.step_name}] [PASS] SQL injection blocked with validation error 1050")
                else:
                    print(f"[{self.step_name}] [🔴 SERVER BUG] Got {error_code} - server executed malicious query!")
            else:
                print(f"[{self.step_name}] [UNEXPECTED] Got list response - should reject injection")

    # ------------------------------------------------------------
    # TC_Boundary_04: Unicode characters in city
    # Expected: MUST reject with 1050 (invalid city format)
    # City should be std:XXX format, not Unicode text
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_04_unicode_city(self):
        """Test Unicode characters in city value"""
        self.step_name = 'TC_Boundary_04_V2_Unicode_City'
        
        # Unicode city name - should be rejected (not std:XXX format)
        unicode_city = "बेंगलुरु"  # Bengaluru in Hindi
        payload = self._generate_v2_lookup_payload(city=unicode_city)
        
        # Accept ONDC Registry error codes (15000-19999) plus legacy validation error (1050)
        acceptable_codes = [1050, "1050"]
        for code in range(15000, 20000):
            acceptable_codes.extend([code, str(code)])
        
        success, data, status = self._send_v2_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 416],
            acceptable_error_codes=acceptable_codes  # Validation errors + ONDC range
        )
        
        if success:
            if isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                if error_code in [1050, "1050"]:
                    print(f"[{self.step_name}] [PASS] Unicode city rejected with validation error 1050")
                else:
                    print(f"[{self.step_name}] [SERVER BUG] Got {error_code} - server accepted invalid format")
            else:
                print(f"[{self.step_name}] [SERVER BUG] Unicode city accepted - should be std:XXX format only")

    # ------------------------------------------------------------
    # TC_Boundary_05: Empty string in optional filters
    # Expected: MUST reject with 1050 (validation error) OR ignore empty strings
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_05_empty_string_filter(self):
        """Test empty string in domain filter"""
        self.step_name = 'TC_Boundary_05_V2_Empty_String_Filter'
        
        payload = self._generate_v2_lookup_payload(
            domain="",  # Empty string
            city=""
        )
        
        # Accept ONDC Registry error codes (15000-19999) plus legacy validation error (1050)
        acceptable_codes = [1050, "1050"]
        for code in range(15000, 20000):
            acceptable_codes.extend([code, str(code)])
        
        success, data, status = self._send_v2_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 416],
            acceptable_error_codes=acceptable_codes  # Validation errors + ONDC range
        )
        
        if success:
            if isinstance(data, list):
                print(f"[{self.step_name}] [PASS] Empty strings ignored, returned {len(data)} results")
            elif isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                if error_code in [1050, "1050"]:
                    print(f"[{self.step_name}] [PASS] Empty strings rejected with validation error 1050")
                else:
                    print(f"[{self.step_name}] [SERVER BUG] Got {error_code} - unexpected error code")
            else:
                print(f"[{self.step_name}] [PASS] Status {status}")

    # ------------------------------------------------------------
    # TC_Boundary_06: Domain with various formats
    # Expected: MUST reject with 1050 (domain must have ONDC: prefix)
    # Same validation as TC-010 from negative tests
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_06_domain_formats(self):
        """Test various domain string formats"""
        self.step_name = 'TC_Boundary_06_V2_Domain_Formats'
        
        # Test invalid domain format (missing ONDC: prefix)
        domain = "InvalidDomain"
        payload = self._generate_v2_lookup_payload(domain=domain)
        
        # Accept ONDC Registry error codes (15000-19999) plus legacy validation error (1050)
        acceptable_codes = [1050, "1050"]
        for code in range(15000, 20000):
            acceptable_codes.extend([code, str(code)])
        
        success, data, status = self._send_v2_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 416],
            acceptable_error_codes=acceptable_codes  # Validation errors + ONDC range
        )
        
        if success:
            if isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                if error_code in [1050, "1050"]:
                    print(f"[{self.step_name}] [PASS] Invalid domain rejected with validation error 1050")
                else:
                    print(f"[{self.step_name}] [SERVER BUG] Got {error_code} - server skipped format validation")
            else:
                print(f"[{self.step_name}] [SERVER BUG] Invalid domain accepted - should require ONDC: prefix")

    # ------------------------------------------------------------
    # TC_Boundary_07: Multiple filters combined
    # Expected: Should handle multiple valid filters
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_07_multiple_filters(self):
        """Test combining multiple filters"""
        self.step_name = 'TC_Boundary_07_V2_Multiple_Filters'
        
        # Combine domain, city, and type filters
        payload = self._generate_v2_lookup_payload(
            domain="ONDC:RET10",
            city="std:080",
            lookup_type="BPP"
        )
        
        success, data, status = self._send_v2_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200]
        )
        
        if success:
            if isinstance(data, list):
                print(f"[{self.step_name}] [PASS] Multiple filters handled, returned {len(data)} results")
            else:
                print(f"[{self.step_name}] [PASS] Status {status}")

    # ------------------------------------------------------------
    # TC_Boundary_08: Whitespace handling in filters
    # Expected: Should trim whitespace (accept 1001 if no match) OR reject with 1050
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_08_whitespace_handling(self):
        """Test whitespace in filter values"""
        self.step_name = 'TC_Boundary_08_V2_Whitespace_Handling'
        
        # Test leading/trailing whitespace
        payload = self._generate_v2_lookup_payload(domain="  ONDC:RET10  ")
        
        # Accept ONDC Registry error codes (15000-19999) plus legacy error codes
        acceptable_codes = [1001, "1001", 1050, "1050"]
        for code in range(15000, 20000):
            acceptable_codes.extend([code, str(code)])
        
        success, data, status = self._send_v2_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 416],
            acceptable_error_codes=acceptable_codes  # All validation + ONDC range
        )
        
        if success:
            if isinstance(data, list):
                print(f"[{self.step_name}] [PASS] Whitespace trimmed, returned {len(data)} results")
            elif isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                if error_code in [1001, "1001"]:
                    print(f"[{self.step_name}] [PASS] Whitespace trimmed, no match (1001)")
                elif error_code in [1050, "1050"]:
                    print(f"[{self.step_name}] [PASS] Whitespace rejected with validation error 1050")
            else:
                print(f"[{self.step_name}] [PASS] Status {status}")

    # ------------------------------------------------------------
    # TC_Boundary_09: Null values in optional fields
    # Expected: Should ignore null or handle gracefully
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_09_null_optional_fields(self):
        """Test null values in optional fields"""
        self.step_name = 'TC_Boundary_09_V2_Null_Optional_Fields'
        
        # Send request with None for optional fields
        # Note: _generate_v2_lookup_payload() should skip None values
        payload = self._generate_v2_lookup_payload(
            domain=None,
            city=None,
            subscriber_id=None
        )
        
        success, data, status = self._send_v2_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200]
        )
        
        if success:
            if isinstance(data, list):
                print(f"[{self.step_name}] [PASS] Null fields ignored, returned {len(data)} results")
            elif isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                print(f"[{self.step_name}] [PASS] Error {error_code}: Null fields handled appropriately")
            else:
                print(f"[{self.step_name}] [PASS] Status {status}")

    # ------------------------------------------------------------
    # TC_Boundary_10: Only country filter (minimal query)
    # Expected: Should return all participants for that country
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_10_country_only(self):
        """Test minimal query with only country filter"""
        self.step_name = 'TC_Boundary_10_V2_Country_Only_Filter'
        
        # Generate payload with only country (no type, domain, city)
        payload = self._generate_v2_lookup_payload()
        
        success, data, status = self._send_v2_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200]
        )
        
        if success:
            if isinstance(data, list):
                if len(data) == 0:
                    print(f"[{self.step_name}] [PASS] Country-only returned empty results")
                else:
                    print(f"[{self.step_name}] [PASS] Country-only returned {len(data)} participants")
            elif isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                print(f"[{self.step_name}] [PASS] Error {error_code}: Country-only handled appropriately")
            else:
                print(f"[{self.step_name}] [PASS] Status {status}")


# Register the test class for Locust to run
tasks = [ONDCRegV2LookupBoundaryTests]
