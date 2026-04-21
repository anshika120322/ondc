from locust import task
from tests.registry.lookup.common.base_lookup_test import RegistryLookupBase
from tests.utils.response_validators import LookupResponseValidator
import json
import random

"""
ONDC Registry Lookup API - V2 Tests (Converted from Bruno)
Structure follows existing RegistryLookupBase pattern.

Run with:
--users 1 --iterations 5
"""

class ONDCRegLookupV2(RegistryLookupBase):

    config_file = "resources/registry/lookup/v2/test_lookup_v2.yml"
    tenant_name = "ondcRegistryV2Lookup"

    def on_start(self):
        """Initialize test and register participant at runtime"""
        super().on_start()
        
        # Register participant before running tests
        registration_success = self._register_participant_runtime()
        if registration_success:
            print(f"\n[INFO] V2 Lookup Tests initialized for: {self.participant_id}")
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
            
            url = f"{self.host}/lookup"  # V2 endpoint
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
                '            Content-Type': 'application/json',
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
    # Helper: Validate Error Code Range (15000-19999)
    # ------------------------------------------------------------
    def _validate_error_code_range(self, error_code, min_code=15000, max_code=19999):
        """Validate that error code is in ONDC Registry range (15000-19999)"""
        try:
            code_int = int(error_code)
            return min_code <= code_int <= max_code
        except (ValueError, TypeError):
            return False

    # ------------------------------------------------------------
    # TC-001: V2 Lookup - Success Basic (ENHANCED WITH STRICT VALIDATION)
    # Expected: 200 | Non-empty array | Valid participant schema
    # ------------------------------------------------------------
    @task(1)
    def tc001_v2_lookup_success_basic(self):

        self.step_name = "TC001_V2_Lookup_Success_Basic"

        # Use V2 payload generator with city filter
        city = random.choice(self.default_cities)
        payload = self._generate_v2_lookup_payload(city=city)

        success, data, status, response = self._send_v2_lookup_request(
            self.step_name,
            payload
        )

        # Step 1: Basic validation
        if status != 200 or not isinstance(data, list) or len(data) == 0:
            return response.failure(
                f"Expected HTTP 200 with non-empty array, got status {status}"
            )
        
        # Step 2: STRICT SCHEMA VALIDATION (V2 schema - same as V1)
        validator = LookupResponseValidator()
        all_errors = []
        
        for idx, participant in enumerate(data):
            # V2 uses encr_public_key (same as V1, not V3's encryption_public_key)
            is_valid, errors = validator.validate_participant_schema(participant, api_version='v2')
            if not is_valid:
                all_errors.append(f"Participant[{idx}]: {', '.join(errors)}")
        
        if all_errors:
            return response.failure(
                f"Schema validation failed:\n" + "\n".join(all_errors[:5])
            )
        
        # Step 3: Validate city filter effectiveness
        is_valid, filter_errors = validator.validate_filter_effectiveness(
            data,
            {'city': [city]}
        )
        
        if not is_valid:
            return response.failure(
                f"City filter not working:\n" + "\n".join(filter_errors[:3])
            )
        
        response.success()
        print(f"[{self.step_name}] ✅ PASS - {len(data)} participants validated (city={city})")


    # ------------------------------------------------------------
    # TC-002: V2 Lookup - Auth Failure (Invalid Signature)
    # Expected: 401
    # ------------------------------------------------------------
    @task(1)
    def tc002_v2_lookup_auth_failure(self):

        self.step_name = "TC002_V2_Lookup_Auth_Failure"

        # Use V2 payload generator with type parameter
        payload = self._generate_v2_lookup_payload()

        success, data, status, response = self._send_lookup_request_invalid_signature(
            self.step_name,
            payload,
            version="v2",
            expected_status=[401, 200]  # Accept 401 OR 200 with error code
        )

        if status == 401:
            response.success()
        elif status == 200:
            # V2 may return 200 with error code for auth failures
            error_code = data.get("error", {}).get("code") if isinstance(data, dict) else None
            if error_code:
                # Validate error code is in ONDC Registry range (15000-19999)
                if self._validate_error_code_range(error_code):
                    response.success()
                else:
                    response.failure(
                        f"Error code {error_code} not in valid ONDC Registry range (15000-19999)"
                    )
            else:
                response.failure(
                    f"Expected error code in response for auth failure, got {data}"
                )
        else:
            response.failure(
                f"Expected 401 or 200 with error code, got status {status}, response {data}"
            )


    # ------------------------------------------------------------
    # TC-003: V2 Lookup - Invalid JSON
    # Expected: ONDC Registry error codes (15000-19999) for validation/signature failures
    # STRICT: Server should detect signature mismatch when body is malformed
    # ------------------------------------------------------------
    @task(1)
    def tc003_v2_lookup_invalid_json(self):

        self.step_name = "TC003_V2_Lookup_Invalid_JSON"

        # Generate valid payload then create malformed JSON
        valid_payload = self._generate_v2_lookup_payload()
        valid_json = json.dumps(valid_payload)

        # Create malformed JSON
        invalid_json = valid_json[:-1]

        # Server validates signature before parsing JSON, so signature verification fails
        success, data, status, response = self._send_lookup_request_invalid_json(
            self.step_name,
            invalid_json,
            version="v2",
            expected_status=[200, 401]  # Accept 200 with error code OR 401
        )

        # Server validates signature before JSON parsing
        # Signature won't match because body is different (malformed)
        # Expected: HTTP 200 with ONDC Registry error code (15000-19999)
        if status == 200:
            error_code = data.get("error", {}).get("code") if isinstance(data, dict) else None
            if error_code:
                # Validate error code is in ONDC Registry range (15000-19999)
                if self._validate_error_code_range(error_code):
                    response.success()
                else:
                    response.failure(
                        f"Error code {error_code} not in valid ONDC Registry range (15000-19999)"
                    )
            else:
                response.failure(
                    f"Expected error code in response for invalid JSON, got {data}"
                )
        elif status == 401:  # Some servers may return 401 for signature issues
            response.success()
        else:
            response.failure(
                f"Expected 200 with error code or 401, got status {status}, response {data}"
            )


    # ------------------------------------------------------------
    # TC-004: V2 Lookup - Success Domain Filter (ENHANCED WITH FILTER VALIDATION)
    # Expected: 200 | Non-empty array | Domain filter effectiveness validated
    # ------------------------------------------------------------
    @task(1)
    def tc004_v2_lookup_success_domain(self):

        self.step_name = "TC004_V2_Lookup_Success_Domain"

        # Use V2 payload generator with domain parameter
        domain = random.choice(self.default_domains)
        payload = self._generate_v2_lookup_payload(domain=domain)

        success, data, status, response = self._send_v2_lookup_request(
            self.step_name,
            payload
        )

        # Step 1: Basic validation
        if status != 200 or not isinstance(data, list) or len(data) == 0:
            return response.failure(
                f"Expected HTTP 200 with non-empty array, got status {status}"
            )
        
        # Step 2: STRICT DOMAIN FILTER VALIDATION
        validator = LookupResponseValidator()
        is_valid, errors = validator.validate_filter_effectiveness(
            data,
            {'domain': [domain]}
        )
        
        if not is_valid:
            return response.failure(
                f"Domain filter not working:\n" + "\n".join(errors[:3])
            )
        
        # Step 3: Schema validation (V2 schema - same as V1)
        all_errors = []
        for idx, participant in enumerate(data):
            # V2 uses encr_public_key (same as V1)
            is_valid, schema_errors = validator.validate_participant_schema(participant, api_version='v2')
            if not is_valid:
                all_errors.append(f"[{idx}]: {', '.join(schema_errors[:2])}")
        
        if all_errors:
            return response.failure("Schema errors:\n" + "\n".join(all_errors[:3]))
        
        response.success()
        print(
            f"[{self.step_name}] ✅ PASS - Domain filter '{domain}' working correctly. "
            f"Found {len(data)} participants"
        )


    # ------------------------------------------------------------
    # TC-005: V2 Lookup - Subscriber Not Found (ENHANCED WITH ERROR CODE RANGE VALIDATION)
    # Expected: 404 or 200 with ONDC Registry error code (15000-19999)
    # ------------------------------------------------------------
    @task(1)
    def tc005_v2_lookup_not_found(self):

        self.step_name = "TC005_V2_Lookup_Not_Found"

        # Use V2 payload generator with non-existent subscriber_id
        payload = self._generate_v2_lookup_payload(
            subscriber_id="non-existent-subscriber-12345-xyz"
        )

        success, data, status, response = self._send_v2_lookup_request(
            self.step_name,
            payload,
            expected_status=[404, 200]  # Accept 404 OR 200 with error
        )

        # V2 API modern behavior: 404 or 200 with ONDC Registry error code (15000-19999)
        # Expected error: 15045 (no matching network participant found)
        if status == 404:
            error_code = data.get("error", {}).get("code") if isinstance(data, dict) else None
            if error_code:
                # Validate error code is in ONDC Registry range (15000-19999)
                if self._validate_error_code_range(error_code):
                    response.success()
                else:
                    response.failure(
                        f"Error code {error_code} not in valid ONDC Registry range (15000-19999)"
                    )
            else:
                response.failure(
                    f"Expected error code in 404 response, got {data}"
                )
        elif status == 200:
            # Also accept 200 with ONDC Registry error code (alternative server behavior)
            error_code = data.get("error", {}).get("code") if isinstance(data, dict) else None
            if error_code:
                # Validate error code is in ONDC Registry range (15000-19999)
                if self._validate_error_code_range(error_code):
                    response.success()
                else:
                    response.failure(
                        f"Error code {error_code} not in valid ONDC Registry range (15000-19999)"
                    )
            else:
                response.failure(
                    f"Expected error code in response for not found, got {data}"
                )
        else:
            response.failure(
                f"Expected 404 or 200 with error code, got {status}, response {data}"
            )


    # ------------------------------------------------------------
    # TC-006: V2 Lookup with Max Results (ENHANCED WITH STRICT VALIDATION)
    # Expected: <= max_results | Exactly max_results or less
    # ------------------------------------------------------------
    @task(1)
    def tc006_v2_lookup_max_results(self):

        self.step_name = 'TC006_V2_Lookup_Max_Results'

        # V2 requires country + at least one filter
        payload = self._generate_v2_lookup_payload(city=random.choice(self.default_cities))
        payload["max_results"] = 1

        success, data, status, response = self._send_v2_lookup_request(
            self.step_name,
            payload
        )

        # Step 1: Basic validation
        if status != 200 or not isinstance(data, list):
            return response.failure(f"Expected HTTP 200 with array, got {status}")
        
        # Step 2: STRICT max_results validation
        max_results = 1
        if len(data) > max_results:
            return response.failure(
                f"max_results={max_results} violated. Got {len(data)} results"
            )
        
        # Step 3: Validate filter effectiveness
        validator = LookupResponseValidator()
        is_valid, errors = validator.validate_filter_effectiveness(
            data,
            {'max_results': max_results}
        )
        
        if not is_valid:
            return response.failure("\n".join(errors))
        
        response.success()
        print(
            f"[{self.step_name}] ✅ PASS - max_results working. "
            f"Requested {max_results}, got {len(data)}"
        )


    # ------------------------------------------------------------
    # TC-007: V2 Lookup by Subscriber ID (ENHANCED WITH VALIDATION)
    # Expected: exact participant match | Valid V2 schema
    # ------------------------------------------------------------
    @task(1)
    def tc007_v2_lookup_by_subscriber_id(self):

        self.step_name = 'TC007_V2_Lookup_By_Subscriber_ID'

        # Use our registered participant
        participant_id = self.participant_id

        # V2 requires country + at least one additional filter
        default_payload = self.config.get('default_lookup_payload', {})
        payload = {
            "country": default_payload.get('country', self.countries[0]),
            "type": default_payload.get('type', self.lookup_types[0]),
            "subscriber_id": participant_id
        }

        success, data, status, response = self._send_v2_lookup_request(
            self.step_name,
            payload
        )

        # Step 1: Basic validation
        if status != 200 or not isinstance(data, list) or len(data) < 1:
            return response.failure(f"Expected HTTP 200 with results, got {status}")
        
        # Step 2: Verify subscriber ID match
        if data[0].get("subscriber_id") != participant_id:
            return response.failure(
                f"subscriber_id mismatch: expected {participant_id}, got {data[0].get('subscriber_id')}"
            )
        
        # Step 3: V2 Schema validation (encr_public_key, subscriber_url, br_id at root)
        validator = LookupResponseValidator()
        is_valid, errors = validator.validate_participant_schema(data[0], api_version='v2')
        
        if not is_valid:
            return response.failure(f"Schema validation failed: {', '.join(errors[:3])}")
        
        response.success()
        print(f"[{self.step_name}] ✅ PASS - Participant {participant_id} found and validated")


    # ------------------------------------------------------------
    # TC-008: V2 Lookup Multiple Keys Validation (ENHANCED WITH VALIDATION)
    # Expected: keys array present | Valid V2 schema with encr_public_key
    # ------------------------------------------------------------
    @task(1)
    def tc008_v2_lookup_multiple_keys(self):

        self.step_name = 'TC008_V2_Lookup_Multiple_Keys'

        # Use our registered participant
        participant_id = self.participant_id

        # V2 requires country + at least one additional filter
        payload = {
            "country": "IND",
            "subscriber_id": participant_id
        }

        success, data, status, response = self._send_v2_lookup_request(
            self.step_name,
            payload
        )

        # Step 1: Basic validation
        if status != 200 or not isinstance(data, list) or len(data) < 1:
            return response.failure(f"Expected HTTP 200 with results, got {status}")
        
        # Step 2: Keys validation
        keys = data[0].get("keys")
        if not isinstance(keys, list) or len(keys) == 0:
            return response.failure("keys missing or empty")
        
        # Step 3: V2-specific validation - check for encr_public_key (not encryption_public_key)
        key_obj = keys[0]
        if 'encr_public_key' not in key_obj:
            return response.failure("V2 should have 'encr_public_key' in keys")
        
        if 'encryption_public_key' in key_obj:
            return response.failure("Found V3 field 'encryption_public_key' in V2 response")
        
        # Step 4: V2 Schema validation
        validator = LookupResponseValidator()
        is_valid, errors = validator.validate_participant_schema(data[0], api_version='v2')
        
        if not is_valid:
            return response.failure(f"Schema validation failed: {', '.join(errors[:3])}")
        
        response.success()
        print(f"[{self.step_name}] ✅ PASS - Found {len(keys)} keys with encr_public_key, schema validated")


    # ------------------------------------------------------------
    # TC-009: V2 Lookup City Filter Specific (ENHANCED WITH FILTER VALIDATION)
    # Expected: valid response | City filter effectiveness validated
    # ------------------------------------------------------------
    @task(1)
    def tc009_v2_lookup_city_filter_specific(self):

        self.step_name = 'TC009_V2_Lookup_City_Filter_Specific'

        city = random.choice(self.default_cities)

        payload = self._generate_v2_lookup_payload(
            city=city,
            lookup_type="BPP"
        )

        success, data, status, response = self._send_v2_lookup_request(
            self.step_name,
            payload
        )

        # Basic validation
        if status != 200 or not isinstance(data, list):
            return response.failure(f"Expected HTTP 200 with array, got {status}")
        
        # STRICT FILTER VALIDATION - verify city filter works
        if len(data) > 0:
            validator = LookupResponseValidator()
            is_valid, errors = validator.validate_filter_effectiveness(
                data,
                {'city': [city]}
            )
            
            if not is_valid:
                return response.failure(
                    f"City filter not working:\n" + "\n".join(errors[:3])
                )
        
        response.success()
        print(f"[{self.step_name}] ✅ PASS - City filter '{city}' working correctly")


    # ------------------------------------------------------------
    # TC-010: V2 Lookup Type Filter (ENHANCED WITH VALIDATION)
    # Expected: valid response | Valid V2 schema for all results
    # ------------------------------------------------------------
    @task(1)
    def tc010_v2_lookup_type_filter(self):

        self.step_name = 'TC010_V2_Lookup_Type_Filter'

        # V2 requires country + at least one filter
        payload = {
            "country": "IND",
            "type": "BPP"
        }

        success, data, status, response = self._send_v2_lookup_request(
            self.step_name,
            payload
        )

        # Step 1: Basic validation
        if status != 200 or not isinstance(data, list):
            return response.failure(f"Expected HTTP 200 with array, got {status}")
        
        # Step 2: Validate type filter effectiveness (if results exist)
        if len(data) > 0:
            validator = LookupResponseValidator()
            is_valid, errors = validator.validate_filter_effectiveness(
                data,
                {'type': 'BPP'}
            )
            
            if not is_valid:
                return response.failure(f"Type filter not working: {', '.join(errors[:3])}")
            
            # Step 3: V2 Schema validation (sample first result)
            # V2 has encr_public_key, subscriber_url, br_id at root
            is_valid, errors = validator.validate_participant_schema(data[0], api_version='v2')
            if not is_valid:
                return response.failure(f"Schema validation failed: {', '.join(errors[:3])}")
        
        response.success()
        print(f"[{self.step_name}] ✅ PASS - Found {len(data)} BPP participants, validated")


    # ------------------------------------------------------------
    # TC-011: V2 Lookup Domain Filter (ENHANCED WITH VALIDATION)
    # Expected: valid response | Valid V2 schema
    # ------------------------------------------------------------
    @task(1)
    def tc011_v2_lookup_domain_filter(self):

        self.step_name = 'TC011_V2_Lookup_Domain_Filter'

        domain = random.choice(self.default_domains)
        
        payload = self._generate_v2_lookup_payload(
            domain=domain,
            lookup_type="BPP"
        )

        success, data, status, response = self._send_v2_lookup_request(
            self.step_name,
            payload
        )

        # Step 1: Basic validation
        if status != 200 or not isinstance(data, list) or len(data) == 0:
            return response.failure(f"Expected HTTP 200 with non-empty array, got {status}")
        
        # Step 2: Validate domain filter effectiveness
        validator = LookupResponseValidator()
        is_valid, errors = validator.validate_filter_effectiveness(
            data,
            {'domain': [domain]}
        )
        
        if not is_valid:
            return response.failure(f"Domain filter not working: {', '.join(errors[:3])}")
        
        # Step 3: V2 Schema validation for each participant
        all_errors = []
        
        for idx, participant in enumerate(data):
            # V2 uses encr_public_key and has subscriber_url, br_id, ukId at root
            is_valid, errors = validator.validate_participant_schema(participant, api_version='v2')
            
            if not is_valid:
                all_errors.append(f"Participant[{idx}]: {', '.join(errors[:2])}")
                if len(all_errors) >= 3:  # Limit error reporting
                    break
        
        if all_errors:
            return response.failure(
                f"Schema validation failed:\n" + "\n".join(all_errors)
            )
        
        response.success()
        print(f"[{self.step_name}] ✅ PASS - {len(data)} participants with domain '{domain}' validated")


# Required by Locust
tasks = [ONDCRegLookupV2]
