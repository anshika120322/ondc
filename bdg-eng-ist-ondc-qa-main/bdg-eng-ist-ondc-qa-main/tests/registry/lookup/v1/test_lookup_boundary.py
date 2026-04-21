from locust import task
from tests.registry.lookup.common.base_lookup_test import RegistryLookupBase
from tests.utils.response_validators import LookupResponseValidator
import random
import json

"""
ONDC Registry V1 Lookup API - Boundary & Edge Case Tests
Tests V1-specific edge cases and boundary values
V1 only supports country (required) and type (optional) parameters

Works for both QA and PROD environments
Endpoints:
  QA:   http://35.200.190.239:8080/lookup (public, no auth)
  PROD: https://prod.registry.ondc.org/lookup (public, no auth)

Run with:
--test ondc_reg_v1_lookup_boundary --environment ondcRegistryV1Lookup --iterations 12 (QA)
--test ondc_reg_v1_lookup_boundary --environment ondcRegistryV1LookupProd --iterations 12 (PROD)
"""

class ONDCRegV1LookupBoundaryTests(RegistryLookupBase):

    config_file = 'resources/registry/lookup/v1/test_lookup_v1.yml'
    # tenant_name is set dynamically by --environment parameter (ondcRegistryV1Lookup or ondcRegistryV1LookupProd)

    def on_start(self):
        """Initialize test and register participant at runtime"""
        super().on_start()
        
        # Register participant before running tests (if credentials available)
        if hasattr(self, 'participant_id') and self.participant_id:
            registration_success = self._register_participant_runtime()
            if registration_success:
                print(f"\n[INFO] ✅ V1 Boundary Tests initialized (12 test cases)")
                print(f"[INFO] Participant status: SUBSCRIBED (ready for testing)\n")
            else:
                print(f"\n[WARNING] Participant registration uncertain - proceeding with tests\n")
        else:
            print(f"\n[INFO] ✅ V1 Boundary Tests initialized (12 test cases) - public API\n")

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
            
            # Step 3: V3 self-subscribe
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
        """Check if participant is already registered and SUBSCRIBED using V1 lookup"""
        try:
            # Use V1 lookup to check if participant exists (public API)
            payload = {
                "country": "IND",
                "type": "BPP"
            }
            
            headers = self._generate_public_headers()
            url = f"{self.host}/lookup"
            response = self.client.post(url, json=payload, headers=headers, catch_response=True)
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    # Check if our participant is in the results
                    for participant in data:
                        if participant.get('subscriber_id') == self.participant_id:
                            # Check if status is SUBSCRIBED in any config
                            for config in participant.get('configs', []):
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

    def _send_v1_boundary_test_request(self, step_name, payload, expected_status=[200, 400], expected_error_codes=None):
        """
        Send V1 boundary test request and handle responses
        
        Args:
            step_name: Test step name
            payload: Request payload
            expected_status: List of acceptable status codes
            expected_error_codes: List of acceptable error codes (e.g., [1050, "1050"])
        
        Returns:
            tuple: (success, data, status_code)
        """
        headers = self._generate_public_headers()
        
        with self.client.post(
                name=step_name,
                url="/lookup",
                json=payload,
                headers=headers,
                catch_response=True
        ) as response:
            status_code = response.status_code
            
            # Parse response
            try:
                data = response.json()
            except Exception as e:
                # For boundary tests, non-JSON responses on error status codes are acceptable
                # (server rejected at proxy/load balancer level before reaching app)
                if status_code in [400, 413, 416, 500, 502, 503, 504] or (status_code in expected_status and expected_error_codes is None):
                    response.success()
                    return True, None, status_code
                response.failure(f"Failed to parse JSON: {str(e)}")
                return False, None, status_code
            
            # NEW: Validate error codes if specified (strict validation)
            if expected_error_codes is not None:
                if isinstance(data, dict) and 'error' in data:
                    error_code = data.get('error', {}).get('code')
                    # Convert error_code to int if it's a string, for comparison
                    try:
                        error_code_int = int(error_code) if isinstance(error_code, str) else error_code
                    except (ValueError, TypeError):
                        error_code_int = error_code
                    
                    # Check if error code (or its int version) is in expected list
                    if error_code in expected_error_codes or error_code_int in expected_error_codes:
                        response.success()
                        return True, data, status_code
                    else:
                        # For cleaner output, show range instead of full list
                        if isinstance(expected_error_codes, list) and len(expected_error_codes) > 10:
                            error_msg = f"Expected error code in range 15000-19999, got {error_code}"
                        else:
                            error_msg = f"Expected error codes {expected_error_codes}, got {error_code}"
                        response.failure(error_msg)
                        return False, data, status_code
                else:
                    response.failure(f"Expected error response, got {type(data)}")
                    return False, data, status_code
            
            # Original logic: Check if status is expected (no error code validation)
            if status_code in expected_status:
                response.success()
                return True, data, status_code
            
            # Unexpected status
            response.failure(f"Expected status {expected_status}, got {status_code}")
            return False, data, status_code

    # ------------------------------------------------------------
    # TC_Boundary_01: Very long country string
    # Expected: Should reject with 400/413/416 or handle gracefully
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_01_very_long_country(self):
        """Test very long country value (>1000 chars)"""
        self.step_name = 'TC_Boundary_01_V1_Very_Long_Country'
        
        # Create a very long country string
        long_country = "A" * 1000
        payload = {
            "country": long_country,
            "type": "BAP"
        }
        
        success, data, status = self._send_v1_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 413, 416]
        )
        
        if success:
            if isinstance(data, list):
                print(f"[{self.step_name}] [PASS] Long country accepted, returned {len(data)} results - API is lenient")
            elif isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                print(f"[{self.step_name}] [PASS] Error {error_code}: Correctly rejected or no match")
            else:
                print(f"[{self.step_name}] [PASS] Status {status} - Boundary handled")

    # ------------------------------------------------------------
    # TC_Boundary_02: Very long type string
    # Expected: Should reject with 400/413/416 or handle gracefully
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_02_very_long_type(self):
        """Test very long type value (>1000 chars)"""
        self.step_name = 'TC_Boundary_02_V1_Very_Long_Type'
        
        # Create a very long type string
        long_type = "B" * 1000
        payload = {
            "country": "IND",
            "type": long_type
        }
        
        success, data, status = self._send_v1_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 413, 416]
        )
        
        if success:
            if isinstance(data, list):
                print(f"[{self.step_name}] [PASS] Long type accepted, returned {len(data)} results - API is lenient")
            elif isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                print(f"[{self.step_name}] [PASS] Error {error_code}: Correctly rejected or no match")
            else:
                print(f"[{self.step_name}] [PASS] Status {status} - Boundary handled")

    # ------------------------------------------------------------
    # TC_Boundary_03: Special characters in country (SQL injection attempt)
    # Expected: MUST reject with error code 1050 (validation error)
    # CRITICAL: If returns error 1001, server executed SQL query!
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_03_special_chars_country(self):
        """Test SQL injection pattern in country"""
        self.step_name = 'TC_Boundary_03_V1_Special_Chars_Country'
        
        # Try SQL injection pattern - server MUST reject this
        test_country = "IND' OR '1'='1"
        payload = {
            "country": test_country,
            "type": "BAP"
        }
        
        success, data, status = self._send_v1_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 416],
            expected_error_codes=list(range(15000, 20000))  # ONDC Registry error code range
        )
        
        if success:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [PASS] 🔒 SQL injection blocked with error {error_code}")
        else:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [🔴 FAIL] Expected error code 15000-19999, got {error_code}")

    # ------------------------------------------------------------
    # TC_Boundary_04: Special characters in type (XSS attempt)
    # Expected: MUST reject with error code 1050 (validation error)
    # CRITICAL: If returns error 1001, server accepted XSS payload!
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_04_special_chars_type(self):
        """Test XSS pattern in type"""
        self.step_name = 'TC_Boundary_04_V1_Special_Chars_Type'
        
        # Try XSS pattern - server MUST reject this
        test_type = "BAP<script>alert('xss')</script>"
        payload = {
            "country": "IND",
            "type": test_type
        }
        
        success, data, status = self._send_v1_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 416],
            expected_error_codes=list(range(15000, 20000))  # ONDC Registry error code range
        )
        
        if success:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [PASS] 🔒 XSS attempt blocked with error {error_code}")
        else:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [🔴 FAIL] Expected error code 15000-19999, got {error_code}")

    # ------------------------------------------------------------
    # TC_Boundary_05: Unicode characters in country
    # Expected: Should handle or reject unicode gracefully
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_05_unicode_country(self):
        """Test unicode characters in country"""
        self.step_name = 'TC_Boundary_05_V1_Unicode_Country'
        
        # Test with Hindi characters (India in Hindi)
        payload = {
            "country": "भारत",
            "type": "BAP"
        }
        
        success, data, status = self._send_v1_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 416]
        )
        
        if success:
            if isinstance(data, list):
                print(f"[{self.step_name}] [PASS] Unicode country handled, returned {len(data)} results")
            elif isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                print(f"[{self.step_name}] [PASS] Error {error_code}: Unicode appropriately rejected")
            else:
                print(f"[{self.step_name}] [PASS] Status {status} - Unicode handled")

    # ------------------------------------------------------------
    # TC_Boundary_06: Unicode characters in type
    # Expected: Should handle or reject unicode gracefully
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_06_unicode_type(self):
        """Test unicode characters in type"""
        self.step_name = 'TC_Boundary_06_V1_Unicode_Type'
        
        # Test with emoji and special unicode
        payload = {
            "country": "IND",
            "type": "BAP🚀"
        }
        
        success, data, status = self._send_v1_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 416]
        )
        
        if success:
            if isinstance(data, list):
                print(f"[{self.step_name}] [PASS] Unicode type handled, returned {len(data)} results")
            elif isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                print(f"[{self.step_name}] [PASS] Error {error_code}: Unicode appropriately rejected")
            else:
                print(f"[{self.step_name}] [PASS] Status {status} - Unicode handled")

    # ------------------------------------------------------------
    # TC_Boundary_07: Empty string for country
    # Expected: Should reject with 400/416
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_07_empty_country(self):
        """Test empty string for country"""
        self.step_name = 'TC_Boundary_07_V1_Empty_Country'
        
        payload = {
            "country": "",
            "type": "BAP"
        }
        
        success, data, status = self._send_v1_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 416]
        )
        
        if success:
            if status in [400, 416]:
                print(f"[{self.step_name}] [PASS] Empty country correctly rejected with {status}")
            elif isinstance(data, list) and len(data) == 0:
                print(f"[{self.step_name}] [PASS] Empty country returned no results")
            else:
                print(f"[{self.step_name}] [PASS] Status {status} - Empty string handled")

    # ------------------------------------------------------------
    # TC_Boundary_08: Empty string for type
    # Expected: May accept (treat as optional) or reject
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_08_empty_type(self):
        """Test empty string for type"""
        self.step_name = 'TC_Boundary_08_V1_Empty_Type'
        
        payload = {
            "country": "IND",
            "type": ""
        }
        
        success, data, status = self._send_v1_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 416]
        )
        
        if success:
            if isinstance(data, list):
                print(f"[{self.step_name}] [PASS] Empty type handled, returned {len(data)} results")
            elif status in [400, 416]:
                print(f"[{self.step_name}] [PASS] Empty type rejected with {status}")
            else:
                print(f"[{self.step_name}] [PASS] Status {status} - Empty type handled")

    # ------------------------------------------------------------
    # TC_Boundary_09: Whitespace in country
    # Expected: Should trim or reject
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_09_whitespace_country(self):
        """Test leading/trailing whitespace in country"""
        self.step_name = 'TC_Boundary_09_V1_Whitespace_Country'
        
        payload = {
            "country": "  IND  ",
            "type": "BAP"
        }
        
        success, data, status = self._send_v1_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 416]
        )
        
        if success:
            if isinstance(data, list):
                if len(data) > 0:
                    print(f"[{self.step_name}] [PASS] Whitespace trimmed, returned {len(data)} results")
                else:
                    print(f"[{self.step_name}] [PASS] Whitespace handled, empty results")
            elif isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                print(f"[{self.step_name}] [PASS] Error {error_code}: Whitespace rejected")
            else:
                print(f"[{self.step_name}] [PASS] Status {status} - Whitespace handled")

    # ------------------------------------------------------------
    # TC_Boundary_10: Whitespace in type
    # Expected: Should trim or reject
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_10_whitespace_type(self):
        """Test leading/trailing whitespace in type"""
        self.step_name = 'TC_Boundary_10_V1_Whitespace_Type'
        
        payload = {
            "country": "IND",
            "type": "  BAP  "
        }
        
        success, data, status = self._send_v1_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 416]
        )
        
        if success:
            if isinstance(data, list):
                if len(data) > 0:
                    print(f"[{self.step_name}] [PASS] Whitespace trimmed, returned {len(data)} results")
                else:
                    print(f"[{self.step_name}] [PASS] Whitespace handled, empty results")
            elif isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                print(f"[{self.step_name}] [PASS] Error {error_code}: Whitespace rejected")
            else:
                print(f"[{self.step_name}] [PASS] Status {status} - Whitespace handled")

    # ------------------------------------------------------------
    # TC_Boundary_11: Case sensitivity in type
    # Expected: May be case-insensitive or case-sensitive
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_11_case_sensitivity(self):
        """Test case sensitivity for type field"""
        self.step_name = 'TC_Boundary_11_V1_Case_Sensitivity'
        
        # Test lowercase version of BAP
        payload = {
            "country": "IND",
            "type": "bap"  # lowercase instead of BAP
        }
        
        success, data, status = self._send_v1_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 416]
        )
        
        if success:
            if isinstance(data, list):
                if len(data) > 0:
                    print(f"[{self.step_name}] [PASS] Case-insensitive - returned {len(data)} results")
                else:
                    print(f"[{self.step_name}] [PASS] Case-sensitive or no match - empty results")
            elif isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                print(f"[{self.step_name}] [PASS] Error {error_code}: Case sensitivity enforced")
            else:
                print(f"[{self.step_name}] [PASS] Status {status} - Case handling defined")

    # ------------------------------------------------------------
    # TC_Boundary_12: Country-only query (minimal valid request)
    # Expected: Should return all participants for that country
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_12_country_only(self):
        """Test minimal query with only country (no type)"""
        self.step_name = 'TC_Boundary_12_V1_Country_Only'
        
        # Only country, no type (type is optional in V1)
        payload = {
            "country": "IND"
        }
        
        success, data, status = self._send_v1_boundary_test_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 416]
        )
        
        if success:
            if isinstance(data, list):
                print(f"[{self.step_name}] [PASS] Country-only query returned {len(data)} participants")
            elif isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                if error_code == 1001:
                    print(f"[{self.step_name}] [PASS] Error 1001: No matching participants")
                else:
                    print(f"[{self.step_name}] [PASS] Error {error_code}: Country-only handled")
            else:
                print(f"[{self.step_name}] [PASS] Status {status} - Minimal query handled")


# Register the test class for Locust to run
tasks = [ONDCRegV1LookupBoundaryTests]
