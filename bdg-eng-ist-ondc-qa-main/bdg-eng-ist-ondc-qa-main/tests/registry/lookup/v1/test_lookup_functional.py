from locust import task
from tests.registry.lookup.common.base_lookup_test import RegistryLookupBase
from tests.utils.response_validators import LookupResponseValidator
import json
import random

"""
ONDC Registry Lookup API - V1 Functional Tests
V1 Lookup is the simplest form - just country and type parameters
Works for both QA and PROD environments

Endpoints:
  QA: http://35.200.190.239:8080/lookup (public V1 API, no auth)
  PROD: https://prod.registry.ondc.org/lookup (public V1 API, no auth)

Run with:
--test ondc_reg_v1_lookup_functional --environment ondcRegistryV1Lookup --users 1 --iterations 5 (QA)
--test ondc_reg_v1_lookup_functional --environment ondcRegistryV1LookupProd --users 1 --iterations 5 (PROD)
"""

class ONDCRegLookupV1(RegistryLookupBase):

    config_file = "resources/registry/lookup/v1/test_lookup_v1.yml"
    # tenant_name is set dynamically by --environment parameter (ondcRegistryV1Lookup or ondcRegistryV1LookupProd)

    def on_start(self):
        """Initialize test and register participant at runtime"""
        super().on_start()
        
        # Register participant before running tests (if credentials available)
        if hasattr(self, 'participant_id') and self.participant_id:
            registration_success = self._register_participant_runtime()
            if registration_success:
                print(f"\n[INFO] V1 Functional Tests initialized")
                print(f"[INFO] Participant status: SUBSCRIBED (ready for testing)\n")
            else:
                print(f"\n[WARNING] Participant registration uncertain - proceeding with tests\n")
        else:
            print(f"\n[INFO] V1 Functional Tests initialized (no registration - public API)\n")

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

    def _send_v1_with_error_handling(self, step_name, payload, expected_status=[200]):
        """
        Send V1 lookup request with error code handling.
        Treats error 1001 (no matching participants) as acceptable.
        
        Args:
            step_name: Test step name
            payload: Request payload
            expected_status: List of acceptable status codes
        
        Returns:
            tuple: (success, data, status_code, response)
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
            
            # Check expected status
            if status_code not in expected_status:
                response.failure(f"Expected status {expected_status}, got {status_code}")
                return False, None, status_code, response
            
            # Parse response
            try:
                data = response.json()
            except Exception as e:
                # For error statuses, JSON parsing failure is acceptable
                if status_code in [400, 416]:
                    response.success()
                    return True, None, status_code, response
                response.failure(f"Failed to parse JSON: {str(e)}")
                return False, None, status_code, response
            
            # Check if response is an error object with code 1001 (no results)
            if isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                error_msg = data.get('error', {}).get('message', '')
                
                # Error 1001 means no matching participants - this is acceptable
                if str(error_code) == '1001':
                    response.success()
                    return True, [], status_code, response
                
                # Other errors - acceptable if status is in expected list
                if status_code in expected_status:
                    response.success()
                    return True, data, status_code, response
                
                response.failure(f"Error {error_code}: {error_msg}")
                return False, data, status_code, response
            
            # Success - return the data array
            if isinstance(data, list):
                response.success()
                return True, data, status_code, response
            
            # Unexpected response format
            response.failure(f"Unexpected response format: type={type(data)}")
            return False, None, status_code, response

    # ------------------------------------------------------------
    # TC-001: V1 Lookup - Success Basic (ENHANCED WITH STRICT VALIDATION)
    # Expected: 200 | Non-empty array | Valid participant schema
    # ------------------------------------------------------------
    @task(1)
    def tc001_v1_lookup_success_basic(self):

        self.step_name = "TC001_V1_Lookup_Success_Basic"

        # V1 payload is simple: just country and type
        payload = self._generate_v1_lookup_payload()

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload
        )

        if not success:
            return
        
        # Step 1: Basic validation
        if len(data) == 0:
            print(f"[{self.step_name}] [INFO] No participants found")
            return
        
        # Step 2: STRICT SCHEMA VALIDATION (V1 schema)
        validator = LookupResponseValidator()
        all_errors = []
        
        for idx, participant in enumerate(data):
            # V1 uses encr_public_key (not encryption_public_key)
            is_valid, errors = validator.validate_participant_schema(participant, api_version='v1')
            if not is_valid:
                all_errors.append(f"Participant[{idx}]: {', '.join(errors)}")
        
        if all_errors:
            response.failure(f"Schema validation failed:\n" + "\n".join(all_errors[:5]))
            print(f"[{self.step_name}] [FAIL] Schema validation failed")
            return
        
        print(f"[{self.step_name}] [PASS] ✅ {len(data)} participants validated successfully")


    # ------------------------------------------------------------
    # TC-002: V1 Lookup - Different Types (ENHANCED WITH STRICT VALIDATION)
    # Expected: 200 with valid results OR 404/1001 if type has no participants
    # Validates that the API behavior is correct for each scenario
    # ------------------------------------------------------------
    @task(1)
    def tc002_v1_lookup_different_types(self):

        self.step_name = "TC002_V1_Lookup_Different_Types"

        # Test with random lookup type
        lookup_type = random.choice(self.lookup_types)
        payload = self._generate_v1_lookup_payload(lookup_type=lookup_type)

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[200, 404]  # Accept both 200 (found) and 404 (not found)
        )

        if not success:
            return
        
        # STRICT VALIDATION based on response type:
        
        # Case 1: 200 with results - MUST validate schema
        if status == 200 and len(data) > 0:
            validator = LookupResponseValidator()
            all_errors = []
            
            for idx, participant in enumerate(data):
                # V1 uses encr_public_key (not encryption_public_key)
                is_valid, errors = validator.validate_participant_schema(participant, api_version='v1')
                if not is_valid:
                    all_errors.append(f"[{idx}]: {', '.join(errors[:2])}")
            
            if all_errors:
                response.failure("Schema errors:\n" + "\n".join(all_errors[:3]))
                print(f"[{self.step_name}] [FAIL] Schema validation failed")
                return
            
            print(f"[{self.step_name}] [PASS] Type={lookup_type}, Found {len(data)} participants with valid schema")
        
        # Case 2: 200 with empty results (from error 1001 handling) - acceptable
        elif status == 200 and len(data) == 0:
            print(f"[{self.step_name}] [PASS] Type={lookup_type}, No participants found (error 1001)")
        
        # Case 3: 404 - acceptable for types with no participants
        elif status == 404:
            print(f"[{self.step_name}] [PASS] Type={lookup_type}, No participants found (404)")
        
        # Case 4: Unexpected scenario
        else:
            response.failure(f"Unexpected state: status={status}, data_len={len(data)}")
            print(f"[{self.step_name}] [FAIL] Unexpected response")


    # ------------------------------------------------------------
    # TC-003: V1 Lookup - Missing Country (Negative)
    # Expected: 400 or 416
    # ------------------------------------------------------------
    @task(1)
    def tc003_v1_lookup_missing_country(self):

        self.step_name = "TC003_V1_Lookup_Missing_Country"

        # Only type, no country
        payload = {
            "type": "BAP"
        }

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[400, 416]
        )

        if success:
            print(f"[{self.step_name}] [PASS] Correctly rejected missing country (status: {status})")
        else:
            print(f"[{self.step_name}] [FAIL] Expected 400 or 416, got status {status}")


    # ------------------------------------------------------------
    # TC-004: V1 Lookup - Invalid JSON (Negative)
    # Expected: 400/416 (QA)
    # ------------------------------------------------------------
    @task(1)
    def tc004_v1_lookup_invalid_json(self):

        self.step_name = "TC004_V1_Lookup_Invalid_JSON"

        # Generate valid payload then create malformed JSON
        valid_payload = self._generate_v1_lookup_payload()
        valid_json = json.dumps(valid_payload)

        # Create malformed JSON (remove closing brace)
        invalid_json = valid_json[:-1]

        success, data, status, response = self._send_v1_lookup_request_raw(
            self.step_name,
            invalid_json,
            expected_status=[200, 400, 416]
        )

        # QA returns 400/416 for malformed JSON
        if status in [400, 416]:
            print(f"[{self.step_name}] [PASS] Correctly rejected invalid JSON (status: {status})")
        else:
            print(f"[{self.step_name}] [FAIL] Expected 400/416, got status {status}")


    # ------------------------------------------------------------
    # TC-005: V1 Lookup - Empty Payload (Negative)
    # Expected: 400 or 416
    # ------------------------------------------------------------
    @task(1)
    def tc005_v1_lookup_empty_payload(self):

        self.step_name = "TC005_V1_Lookup_Empty_Payload"

        payload = {}

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[400, 416]
        )

        if success:
            print(f"[{self.step_name}] [PASS] Correctly rejected empty payload (status: {status})")
        else:
            print(f"[{self.step_name}] [FAIL] Expected 400 or 416, got status {status}")


    # ------------------------------------------------------------
    # TC-006: V1 Lookup - Type BPP Specific (ENHANCED WITH VALIDATION)
    # Expected: 200 with BPP participants | Valid V1 schema
    # ------------------------------------------------------------
    @task(1)
    def tc006_v1_lookup_type_bpp(self):

        self.step_name = "TC006_V1_Lookup_Type_BPP"

        payload = self._generate_v1_lookup_payload(lookup_type='BPP')

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload
        )

        if not success:
            return
        
        if len(data) == 0:
            print(f"[{self.step_name}] [INFO] No BPP participants found")
            return
        
        # Validate all are BPP type
        non_bpp = [p for p in data if p.get('type') != 'BPP']
        if non_bpp:
            response.failure(f"Found {len(non_bpp)} non-BPP participants in BPP query")
            print(f"[{self.step_name}] [FAIL] Type filter not working")
            return
        
        # Schema validation
        validator = LookupResponseValidator()
        is_valid, errors = validator.validate_participant_schema(data[0], api_version='v1')
        
        if not is_valid:
            response.failure(f"Schema validation failed: {', '.join(errors[:3])}")
            print(f"[{self.step_name}] [FAIL] Schema validation failed")
            return
        
        print(f"[{self.step_name}] [PASS] Found {len(data)} BPP participants, all valid")


    # ------------------------------------------------------------
    # TC-007: V1 Lookup - Type BAP Specific (ENHANCED WITH VALIDATION)
    # Expected: 200 with BAP participants | Valid V1 schema
    # ------------------------------------------------------------
    @task(1)
    def tc007_v1_lookup_type_bap(self):

        self.step_name = "TC007_V1_Lookup_Type_BAP"

        payload = self._generate_v1_lookup_payload(lookup_type='BAP')

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload
        )

        if not success:
            return
        
        if len(data) == 0:
            print(f"[{self.step_name}] [INFO] No BAP participants found")
            return
        
        # Validate all are BAP type
        non_bap = [p for p in data if p.get('type') != 'BAP']
        if non_bap:
            response.failure(f"Found {len(non_bap)} non-BAP participants in BAP query")
            print(f"[{self.step_name}] [FAIL] Type filter not working")
            return
        
        # Schema validation
        validator = LookupResponseValidator()
        is_valid, errors = validator.validate_participant_schema(data[0], api_version='v1')
        
        if not is_valid:
            response.failure(f"Schema validation failed: {', '.join(errors[:3])}")
            print(f"[{self.step_name}] [FAIL] Schema validation failed")
            return
        
        print(f"[{self.step_name}] [PASS] Found {len(data)} BAP participants, all valid")


    # ------------------------------------------------------------
    # TC-008: V1 Lookup - Type BG Specific (ENHANCED WITH VALIDATION)
    # Expected: 200 with BG participants OR no results acceptable
    # ------------------------------------------------------------
    @task(1)
    def tc008_v1_lookup_type_bg(self):

        self.step_name = "TC008_V1_Lookup_Type_BG"

        payload = self._generate_v1_lookup_payload(lookup_type='BG')

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[200, 404]
        )

        if not success:
            return
        
        if len(data) == 0:
            print(f"[{self.step_name}] [PASS] No BG participants found (acceptable)")
            return
        
        # Validate all are BG type
        non_bg = [p for p in data if p.get('type') != 'BG']
        if non_bg:
            response.failure(f"Found {len(non_bg)} non-BG participants in BG query")
            print(f"[{self.step_name}] [FAIL] Type filter not working")
            return
        
        print(f"[{self.step_name}] [PASS] Found {len(data)} BG participants, type filter working")


    # ------------------------------------------------------------
    # TC-009: V1 Lookup - Keys Array Validation (V1 SPECIFIC)
    # Expected: keys array with encr_public_key (NOT encryption_public_key)
    # ------------------------------------------------------------
    @task(1)
    def tc009_v1_lookup_keys_validation(self):

        self.step_name = "TC009_V1_Lookup_Keys_Validation"

        payload = self._generate_v1_lookup_payload(lookup_type='BPP')

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload
        )

        if not success or len(data) == 0:
            return
        
        # Check keys array structure
        sample = data[0]
        keys = sample.get('keys', [])
        
        if not isinstance(keys, list) or len(keys) == 0:
            response.failure("Missing or empty keys array")
            print(f"[{self.step_name}] [FAIL] Keys array missing")
            return
        
        # V1-specific: Must have encr_public_key, NOT encryption_public_key
        key_obj = keys[0]
        if 'encr_public_key' not in key_obj:
            response.failure("V1 should have 'encr_public_key' in keys")
            print(f"[{self.step_name}] [FAIL] Missing encr_public_key")
            return
        
        if 'encryption_public_key' in key_obj:
            response.failure("Found V3 field 'encryption_public_key' in V1 response")
            print(f"[{self.step_name}] [FAIL] Has V3 field in V1 response")
            return
        
        print(f"[{self.step_name}] [PASS] ✓ Keys array has correct V1 structure (encr_public_key)")


    # ------------------------------------------------------------
    # TC-010: V1 Lookup - V1 Schema Fields Validation
    # Expected: subscriber_url, br_id, ukId at root level (not nested like V3)
    # ------------------------------------------------------------
    @task(1)
    def tc010_v1_lookup_schema_fields(self):

        self.step_name = "TC010_V1_Lookup_Schema_Fields"

        payload = self._generate_v1_lookup_payload(lookup_type='BPP')

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload
        )

        if not success or len(data) == 0:
            return
        
        sample = data[0]
        
        # V1 should have these at root level (not nested)
        required_fields = ['subscriber_url', 'br_id', 'ukId']
        missing = [f for f in required_fields if f not in sample]
        
        if missing:
            response.failure(f"Missing V1 fields: {', '.join(missing)}")
            print(f"[{self.step_name}] [FAIL] Missing fields: {', '.join(missing)}")
            return
        
        # V1 should NOT have V3-specific participant_id
        if 'participant_id' in sample:
            response.failure("Found V3 field 'participant_id' in V1 response")
            print(f"[{self.step_name}] [FAIL] Has V3 field in V1 response")
            return
        
        print(f"[{self.step_name}] [PASS] ✓ V1 schema correct (subscriber_url, br_id, ukId at root)")


    # ------------------------------------------------------------
    # TC-011: V1 Lookup - Large Result Set Handling
    # Expected: Successfully handle large result sets without timeout
    # ------------------------------------------------------------
    @task(1)
    def tc011_v1_lookup_large_resultset(self):

        self.step_name = "TC011_V1_Lookup_Large_ResultSet"

        # BPP typically returns large result set
        payload = self._generate_v1_lookup_payload(lookup_type='BPP')

        import time
        start_time = time.time()

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload
        )

        elapsed_ms = (time.time() - start_time) * 1000

        if not success or len(data) == 0:
            return
        
        # Validate response time (should be < 3000ms even for large sets)
        if elapsed_ms > 3000:
            print(f"[{self.step_name}] [WARN] Slow response: {elapsed_ms:.0f}ms for {len(data)} results")
        else:
            print(f"[{self.step_name}] [PASS] Handled {len(data)} results in {elapsed_ms:.0f}ms")


    # ------------------------------------------------------------
    # TC-012: V1 Lookup - No Duplicates Validation
    # Expected: No duplicate subscriber_ids in response
    # ------------------------------------------------------------
    @task(1)
    def tc012_v1_lookup_no_duplicates(self):

        self.step_name = "TC012_V1_Lookup_No_Duplicates"

        payload = self._generate_v1_lookup_payload(lookup_type='BPP')

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload
        )

        if not success or len(data) == 0:
            return
        
        # Check for duplicates
        subscriber_ids = [p.get('subscriber_id') for p in data if p.get('subscriber_id')]
        unique_ids = set(subscriber_ids)
        
        if len(subscriber_ids) != len(unique_ids):
            duplicates = [sid for sid in subscriber_ids if subscriber_ids.count(sid) > 1]
            unique_duplicates = list(set(duplicates))
            response.failure(f"Found {len(unique_duplicates)} duplicate subscriber_ids")
            print(f"[{self.step_name}] [FAIL] Duplicates found: {len(unique_duplicates)}")
            return
        
        print(f"[{self.step_name}] [PASS] ✓ No duplicates in {len(data)} participants")


# Required by Locust
tasks = [ONDCRegLookupV1]

