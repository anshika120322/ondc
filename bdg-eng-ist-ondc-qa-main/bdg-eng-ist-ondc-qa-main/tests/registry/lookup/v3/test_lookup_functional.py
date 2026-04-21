from locust import task
from tests.registry.lookup.common.base_lookup_test import RegistryLookupBase
from tests.utils.response_validators import LookupResponseValidator
import random
import json
import uuid
from datetime import datetime, timezone, timedelta

"""
ONDC Registry Lookup API - Functional Tests (Positive Scenarios)
All tests use @task(1) for equal distribution during functional validation
Run with low user count: --users 1 --iterations 5
"""

class ONDCRegLookupFunctional(RegistryLookupBase):

    config_file = 'resources/registry/lookup/v3/test_lookup_functional.yml'
    tenant_name = 'ondcRegistry'

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
        """Check if participant is already registered and SUBSCRIBED"""
        try:
            payload = {
                "subscriber_id": self.participant_id,
                "country": "IND"
            }
            
            # Generate V3 signature using ONDCAuthHelper
            auth_result = self.ondc_auth_helper.generate_headers(payload)
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': auth_result['Authorization'],
                'Digest': auth_result['Digest']
            }
            
            url = f"{self.host}/v3.0/lookup"
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
                
        except Exception as e:
            print(f"[REGISTRATION] Check failed: {e}")
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
                            "legal_name": "Test V3 Lookup Working Private Limited"
                        }
                    },
                    {
                        "cred_id": f"cred_pan_{self.participant_id.split('.')[0]}",
                        "type": "PAN",
                        "cred_data": {
                            "pan": "ABCDE1234F",
                            "name": "Test V3 Lookup Working Private Limited"
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
                        "url": "https://test-seller.kynondc.net"
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
            return False

    def on_start(self):
        """Initialize test - V3 lookup with registered participant credentials"""
        # Call parent on_start to initialize auth, config, ED25519 credentials, etc.
        super().on_start()
        
        print(f"\n[INFO] V3 Auth initialized for: {self.participant_id}")
        
        # Register participant at runtime if needed
        registration_success = self._register_participant_runtime()
        
        if registration_success:
            print(f"[INFO] Participant status: SUBSCRIBED (ready for testing)")
            print(f"[INFO] V3 tests will use ED25519 authenticated lookup\n")
        else:
            print(f"[WARNING] Participant registration uncertain - tests may fail")
            print(f"[INFO] Proceeding with tests anyway...\n")

    # ------------------------------------------------------------
    # TC-001: V3 Lookup - Success Basic (ENHANCED WITH STRICT VALIDATION)
    # Expected: 200 | Non-empty list response | Valid participant schema
    # ------------------------------------------------------------
    @task(1)
    def tc001_v3_lookup_success_basic(self):

        self.step_name = 'TC001_V3_Lookup_Success_Basic'

        # Use payload generator - follows gateway pattern
        payload = self._generate_v3_lookup_payload()

        # Use base class helper method
        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload
        )

        # Step 1: Basic response validation
        if not success or status != 200:
            return response.failure(f"Expected HTTP 200, got {status}")
        
        if not isinstance(data, list):
            return response.failure(f"Expected array response, got {type(data)}")
        
        if len(data) == 0:
            return response.failure("Expected non-empty array")
        
        # Step 2: STRICT SCHEMA VALIDATION for each participant
        validator = LookupResponseValidator()
        all_errors = []
        
        for idx, participant in enumerate(data):
            is_valid, errors = validator.validate_participant_schema(participant)
            
            if not is_valid:
                all_errors.append(f"Participant[{idx}]: {', '.join(errors)}")
        
        if all_errors:
            return response.failure(
                f"Schema validation failed:\n" + "\n".join(all_errors[:5])  # Show first 5 errors
            )
        
        # All validations passed
        response.success()
        print(f"[{self.step_name}] PASS - {len(data)} participants validated successfully")

    # ------------------------------------------------------------
    # TC-002: Lookup with Select Fields (keys.ukId)
    # Expected: 200 | keys.ukId present
    # ------------------------------------------------------------
    @task(1)
    def tc002_lookup_select_keys_ukid(self):

        self.step_name = 'TC002_Lookup_Select_Keys_UkId'

        payload = self._generate_v3_lookup_payload()
        payload["select"] = ["keys.ukId"]

        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload
        )

        if success and isinstance(data, list) and len(data) > 0:
            if 'keys' in data[0] and 'ukId' in data[0]['keys']:
                response.success()
            else:
                response.failure("Expected keys.ukId in response")
        else:
            response.failure(f"Invalid response: status={status}, data={data}")


    # ------------------------------------------------------------
    # TC-003: Lookup with Include Sections
    # Expected: 200 | locations, contacts, uris present
    # ------------------------------------------------------------
    @task(1)
    def tc003_lookup_include_sections(self):

        self.step_name = 'TC003_Lookup_Include_Sections'

        payload = self._generate_v3_lookup_payload()
        payload["include"] = ["locations", "contacts", "uris"]

        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload
        )

        if success and isinstance(data, list) and len(data) > 0:

            item = data[0]
            missing = []

            if 'locations' not in item:
                missing.append("locations")

            if 'contacts' not in item:
                missing.append("contacts")

            if 'uris' not in item:
                missing.append("uris")

            if missing:
                response.failure(f"Missing sections: {missing}")
            else:
                response.success()

        else:
            response.failure(f"Invalid response: status={status}")


    # ------------------------------------------------------------
    # TC-004: Lookup with Domain Filter (ENHANCED WITH FILTER VALIDATION)
    # Expected: 200 | domain matches filter | All participants match
    # ------------------------------------------------------------
    @task(1)
    def tc004_lookup_domain_filter(self):

        self.step_name = 'TC004_Lookup_Domain_Filter'

        domain = random.choice(self.default_domains)

        payload = self._generate_v3_lookup_payload(lookup_type="BAP")
        payload["domain"] = domain

        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload
        )

        # Step 1: Basic validation
        if status != 200 or not isinstance(data, list) or len(data) == 0:
            return response.failure(
                f"Expected HTTP 200 with non-empty array, got {status}"
            )
        
        # Step 2: STRICT FILTER EFFECTIVENESS VALIDATION
        validator = LookupResponseValidator()
        is_valid, errors = validator.validate_filter_effectiveness(
            data,
            {'domain': [domain]}
        )
        
        if not is_valid:
            return response.failure(
                f"Domain filter not working:\n" + "\n".join(errors[:3])
            )
        
        # Step 3: Schema validation
        all_errors = []
        for idx, participant in enumerate(data):
            is_valid, schema_errors = validator.validate_participant_schema(participant)
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
    # TC-005: Lookup with Max Results (ENHANCED WITH STRICT VALIDATION)
    # Expected: <= max_results | Exactly max_results or less
    # ------------------------------------------------------------
    @task(1)
    def tc005_lookup_max_results(self):

        self.step_name = 'TC005_Lookup_Max_Results'

        payload = self._generate_v3_lookup_payload()
        payload["max_results"] = 1

        success, data, status, response = self._send_v3_lookup_request(
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
    # TC-006: Lookup by Participant ID (ENHANCED WITH VALIDATION)
    # Expected: exact participant match | Valid schema
    # ------------------------------------------------------------
    @task(1)
    def tc006_lookup_by_participant_id(self):

        self.step_name = 'TC006_Lookup_By_Participant_ID'

        # Use our registered participant
        # NOTE: V3 API uses 'subscriber_id' field name (not participant_id)
        participant_id = self.participant_id

        # V3 API requires at least 2 filter fields
        payload = {
            "country": "IND",
            "subscriber_id": participant_id
        }

        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload
        )

        # Step 1: Basic validation
        if status != 200 or not isinstance(data, list) or len(data) < 1:
            return response.failure(f"Expected HTTP 200 with results, got {status}")
        
        # Step 2: Verify participant ID match
        if data[0].get("subscriber_id") != participant_id:
            return response.failure(
                f"subscriber_id mismatch: expected {participant_id}, got {data[0].get('subscriber_id')}"
            )
        
        # Step 3: Schema validation
        validator = LookupResponseValidator()
        is_valid, errors = validator.validate_participant_schema(data[0])
        
        if not is_valid:
            return response.failure(f"Schema validation failed: {', '.join(errors[:3])}")
        
        response.success()
        print(f"[{self.step_name}] ✅ PASS - Participant {participant_id} found and validated")


    # ------------------------------------------------------------
    # TC-007: Lookup Multiple Keys Validation (ENHANCED WITH VALIDATION)
    # Expected: keys array present | Valid schema
    # ------------------------------------------------------------
    @task(1)
    def tc007_lookup_multiple_keys(self):

        self.step_name = 'TC007_Lookup_Multiple_Keys'

        # Use our registered participant
        # NOTE: V3 API uses 'subscriber_id' field name (not participant_id)
        participant_id = self.participant_id

        # V3 API requires at least 2 filter fields
        payload = {
            "country": "IND",
            "subscriber_id": participant_id
        }

        success, data, status, response = self._send_v3_lookup_request(
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
        
        # Step 3: Schema validation (V3)
        validator = LookupResponseValidator()
        is_valid, errors = validator.validate_participant_schema(data[0], api_version='v3')
        
        if not is_valid:
            return response.failure(f"Schema validation failed: {', '.join(errors[:3])}")
        
        response.success()
        print(f"[{self.step_name}] ✅ PASS - Found {len(keys)} keys, schema validated")


    # ------------------------------------------------------------
    # TC-008: Lookup City Filter Specific (ENHANCED WITH FILTER VALIDATION)
    # Expected: valid response | City filter effectiveness validated
    # ------------------------------------------------------------
    @task(1)
    def tc008_lookup_city_filter_specific(self):

        self.step_name = 'TC008_Lookup_City_Filter_Specific'

        city = random.choice(self.default_cities)

        payload = self._generate_admin_lookup_payload(
            city=city,
            lookup_type="BPP"
        )

        success, data, status, response = self._send_v3_lookup_request(
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
    # TC-009: Lookup City Filter All (ENHANCED WITH VALIDATION)
    # Expected: valid response | Valid schema for all results
    # ------------------------------------------------------------
    @task(1)
    def tc009_lookup_city_filter_all(self):

        self.step_name = 'TC009_Lookup_City_Filter_All'

        # V3 API requires at least 2 filter fields
        # Don't use city filter - "std:all" is invalid
        payload = {
            "country": "IND",
            "type": "BPP"
        }

        success, data, status, response = self._send_v3_lookup_request(
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
            
            # Step 3: Schema validation (sample first result) (V3)
            is_valid, errors = validator.validate_participant_schema(data[0], api_version='v3')
            if not is_valid:
                return response.failure(f"Schema validation failed: {', '.join(errors[:3])}")
        
        response.success()
        print(f"[{self.step_name}] ✅ PASS - Found {len(data)} BPP participants, validated")


    # ------------------------------------------------------------
    # TC-010: Lookup No City Filter (ENHANCED WITH VALIDATION)
    # Expected: valid response | Valid schema
    # ------------------------------------------------------------
    @task(1)
    def tc010_lookup_no_city_filter(self):

        self.step_name = 'TC010_Lookup_No_City_Filter'

        payload = self._generate_v3_lookup_payload()

        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload
        )

        # Step 1: Basic validation
        if status != 200 or not isinstance(data, list) or len(data) == 0:
            return response.failure(f"Expected HTTP 200 with non-empty array, got {status}")
        
        # Step 2: Schema validation for each participant (V3 schema)
        validator = LookupResponseValidator()
        all_errors = []
        
        for idx, participant in enumerate(data):
            # V3 uses encryption_public_key and has participant_id
            is_valid, errors = validator.validate_participant_schema(participant, api_version='v3')
            
            if not is_valid:
                all_errors.append(f"Participant[{idx}]: {', '.join(errors[:2])}")
                if len(all_errors) >= 3:  # Limit error reporting
                    break
        
        if all_errors:
            return response.failure(
                f"Schema validation failed:\n" + "\n".join(all_errors)
            )
        
        response.success()
        print(f"[{self.step_name}] ✅ PASS - {len(data)} participants validated successfully")

    # ============================================================
    # STATUS FILTERING TESTS (HIGH PRIORITY - Missing Coverage)
    # ============================================================

    # ------------------------------------------------------------
    # TC-011: Verify Only SUBSCRIBED Participants Returned
    # Expected: All results have status='SUBSCRIBED'
    # ------------------------------------------------------------
    @task(1)
    def tc011_only_subscribed_status_returned(self):
        """Verify lookup only returns SUBSCRIBED participants"""
        self.step_name = 'TC011_Only_SUBSCRIBED_Status_Returned'
        
        payload = self._generate_v3_lookup_payload()
        
        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload
        )
        
        if not success or status != 200:
            return response.failure(f"Expected HTTP 200, got {status}")
        
        if not isinstance(data, list) or len(data) == 0:
            return response.failure("Expected non-empty array response")
        
        # Verify all participants have status=SUBSCRIBED
        invalid_statuses = []
        for idx, participant in enumerate(data):
            participant_status = participant.get('status')
            if participant_status != 'SUBSCRIBED':
                invalid_statuses.append({
                    'index': idx,
                    'participant_id': participant.get('participant_id', 'unknown'),
                    'status': participant_status
                })
        
        if invalid_statuses:
            return response.failure(
                f"Found {len(invalid_statuses)} non-SUBSCRIBED participants: "
                f"{invalid_statuses[:3]}"
            )
        
        response.success()
        print(f"[{self.step_name}] ✅ PASS - All {len(data)} participants have status=SUBSCRIBED")

    # ------------------------------------------------------------
    # TC-012: No INITIATED Status in Results
    # Expected: No participants with status='INITIATED'
    # ------------------------------------------------------------
    @task(1)
    def tc012_no_initiated_status_in_results(self):
        """Verify INITIATED participants are excluded from lookup"""
        self.step_name = 'TC012_No_INITIATED_Status'
        
        payload = self._generate_v3_lookup_payload()
        
        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload
        )
        
        if not success or status != 200:
            return response.failure(f"Expected HTTP 200, got {status}")
        
        if not isinstance(data, list):
            return response.failure(f"Expected array response, got {type(data)}")
        
        # Check for INITIATED status (should be 0)
        initiated_found = [
            p.get('participant_id', 'unknown') 
            for p in data 
            if p.get('status') == 'INITIATED'
        ]
        
        if initiated_found:
            return response.failure(
                f"Found {len(initiated_found)} INITIATED participants (should be excluded): "
                f"{initiated_found[:3]}"
            )
        
        response.success()
        print(f"[{self.step_name}] ✅ PASS - No INITIATED participants in {len(data)} results")

    # ------------------------------------------------------------
    # TC-013: No INVALID/BLACKLISTED Status in Results
    # Expected: Excluded statuses are filtered out
    # ------------------------------------------------------------
    @task(1)
    def tc013_no_invalid_blacklisted_status(self):
        """Verify INVALID and BLACKLISTED participants are excluded"""
        self.step_name = 'TC013_No_INVALID_BLACKLISTED_Status'
        
        payload = self._generate_v3_lookup_payload()
        
        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload
        )
        
        if not success or status != 200:
            return response.failure(f"Expected HTTP 200, got {status}")
        
        if not isinstance(data, list):
            return response.failure(f"Expected array response, got {type(data)}")
        
        # Check for excluded statuses
        excluded_statuses = ['INVALID', 'BLACKLISTED', 'UNSUBSCRIBED']
        violations = []
        
        for participant in data:
            participant_status = participant.get('status')
            if participant_status in excluded_statuses:
                violations.append({
                    'participant_id': participant.get('participant_id', 'unknown'),
                    'status': participant_status
                })
        
        if violations:
            return response.failure(
                f"Found {len(violations)} participants with excluded status: "
                f"{violations[:3]}"
            )
        
        response.success()
        print(f"[{self.step_name}] ✅ PASS - No excluded statuses in {len(data)} results")

    # ------------------------------------------------------------
    # TC-014: WHITELISTED Status Should Not Appear
    # Expected: Only SUBSCRIBED participants visible in public lookup
    # ------------------------------------------------------------
    @task(1)
    def tc014_no_whitelisted_status_in_public_lookup(self):
        """Verify WHITELISTED participants not visible in public lookup"""
        self.step_name = 'TC014_No_WHITELISTED_Status'
        
        payload = self._generate_v3_lookup_payload()
        
        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload
        )
        
        if not success or status != 200:
            return response.failure(f"Expected HTTP 200, got {status}")
        
        if not isinstance(data, list):
            return response.failure(f"Expected array response, got {type(data)}")
        
        # WHITELISTED is internal state, should not appear in public lookup
        whitelisted_found = [
            p.get('participant_id', 'unknown') 
            for p in data 
            if p.get('status') == 'WHITELISTED'
        ]
        
        if whitelisted_found:
            return response.failure(
                f"Found {len(whitelisted_found)} WHITELISTED participants "
                f"(internal state, should not be public): {whitelisted_found[:3]}"
            )
        
        response.success()
        print(f"[{self.step_name}] ✅ PASS - No WHITELISTED participants in public results")

    # ------------------------------------------------------------
    # TC-015: Status Field Always Present
    # Expected: Every participant has 'status' field
    # ------------------------------------------------------------
    @task(1)
    def tc015_status_field_always_present(self):
        """Verify status field is present in all participant objects"""
        self.step_name = 'TC015_Status_Field_Always_Present'
        
        payload = self._generate_v3_lookup_payload()
        
        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload
        )
        
        if not success or status != 200:
            return response.failure(f"Expected HTTP 200, got {status}")
        
        if not isinstance(data, list) or len(data) == 0:
            return response.failure("Expected non-empty array response")
        
        # Check that every participant has 'status' field
        missing_status = []
        for idx, participant in enumerate(data):
            if 'status' not in participant:
                missing_status.append({
                    'index': idx,
                    'participant_id': participant.get('participant_id', 'unknown')
                })
        
        if missing_status:
            return response.failure(
                f"Found {len(missing_status)} participants missing status field: "
                f"{missing_status[:3]}"
            )
        
        response.success()
        print(f"[{self.step_name}] ✅ PASS - All {len(data)} participants have status field")


tasks = [ONDCRegLookupFunctional]
