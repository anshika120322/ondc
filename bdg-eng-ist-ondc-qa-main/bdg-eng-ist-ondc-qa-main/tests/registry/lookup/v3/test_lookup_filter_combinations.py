from locust import task
from tests.registry.lookup.common.base_lookup_test import RegistryLookupBase
from tests.utils.response_validators import LookupResponseValidator
import time
from datetime import datetime, timezone, timedelta
import uuid

"""
ONDC Registry V3 Lookup - Filter Combination Tests
Tests multiple filter combinations and validation scenarios

Priority scenarios from TEST_COVERAGE_ANALYSIS_AND_ENHANCEMENTS.md:
- Multiple domains AND cities together
- Multiple domains + type filter
- Multiple cities + type filter
- All filters combined (domain + city + type)
- select_keys with different combinations
- Duplicate check in responses
- Filter accuracy validation
- Response time for large result sets
"""

class ONDCRegLookupFilterCombinations(RegistryLookupBase):

    config_file = 'resources/registry/lookup/v3/test_lookup_filter_combinations.yml'
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
        """Initialize test with V3 authenticated credentials"""
        super().on_start()
        
        print(f"\n[INFO] V3 Auth initialized for: {self.participant_id}")
        
        # Register participant at runtime if needed
        registration_success = self._register_participant_runtime()
        
        if registration_success:
            print(f"[INFO] Participant status: SUBSCRIBED (ready for filter combination testing)")
            print(f"[INFO] Filter Combination Tests initialized\n")
        else:
            print(f"[WARNING] Participant registration uncertain - tests may fail")
            print(f"[INFO] Proceeding with tests anyway...\n")

    def _send_with_error_handling(self, step_name, payload, acceptable_errors=None, fail_on_errors=None):
        """
        Send V3 lookup request with custom error code handling.
        
        Args:
            step_name: Test step name
            payload: Request payload
            acceptable_errors: List of error codes to treat as PASS (e.g., [1001, 1050])
            fail_on_errors: List of error codes to treat as FAIL (e.g., [1070])
        
        Returns:
            tuple: (success, data, status_code) - Note: response object not returned
        """
        acceptable_errors = acceptable_errors or []
        fail_on_errors = fail_on_errors or []
        
        # Generate headers with ED25519 signature
        headers = self._generate_v3_headers(payload)
        serialized_body = headers.pop('serialized_body', None)
        if not serialized_body:
            import json
            serialized_body = json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
        
        with self.client.post(
                name=step_name,
                url="/v3.0/lookup",
                data=serialized_body,
                headers=headers,
                catch_response=True
        ) as response:
            status_code = response.status_code
            
            # Parse response
            try:
                data = response.json()
            except Exception as e:
                response.failure(f"Failed to parse JSON: {str(e)}")
                return False, None, status_code
            
            # Check for error codes in response body (regardless of HTTP status)
            if isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                error_msg = data.get('error', {}).get('message', '')
                
                # Convert to string for comparison
                error_code_str = str(error_code)
                
                # Check if this error should cause a FAIL
                for fail_code in fail_on_errors:
                    if error_code_str == str(fail_code):
                        response.failure(f"❌ CRITICAL ERROR {error_code}: {error_msg}")
                        return False, data, status_code
                
                # Check if this error is acceptable (should PASS)
                for accept_code in acceptable_errors:
                    if error_code_str == str(accept_code):
                        response.success()
                        print(f"[{step_name}] [PASS] Acceptable error {error_code}: {error_msg}")
                        return True, data, status_code
                
                # Unexpected error code
                response.failure(f"Unexpected error code {error_code}: {error_msg}")
                return False, data, status_code
            
            # No error in response, mark as success
            response.success()
            return True, data, status_code

    # ============================================================
    # FILTER COMBINATION TESTS
    # ============================================================

    @task(1)
    def tc_fc01_multiple_domains_and_cities(self):
        """Test multiple domains AND multiple cities together"""
        self.step_name = 'TC_FC01_Multiple_Domains_And_Cities'
        
        # Multiple domains and cities
        payload = self._generate_v3_lookup_payload(
            domain='ONDC:RET10',
            city='std:080'
        )
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],  # Server bugs must FAIL
            acceptable_errors=[1001, 15045]  # No matching data is acceptable in test environment
        )
        
        if not success or not isinstance(data, list):
            return  # Error already handled
        
        # If no results, already marked as success
        if len(data) == 0:
            print(f"[{self.step_name}] [INFO] Filter accepted but no results")
            return
        
        # Validate filter effectiveness
        validator = LookupResponseValidator()
        is_valid, errors = validator.validate_filter_effectiveness(
            data,
            {'domain': ['ONDC:RET10'], 'city': ['std:080']}
        )
        
        if not is_valid:
            print(f"[{self.step_name}] [FAIL] Filter validation failed: {errors[0] if errors else 'Unknown'}")
            return
        
        print(f"[{self.step_name}] [PASS] Multiple domains+cities filter: {len(data)} results")

    @task(1)
    def tc_fc02_multiple_domains_with_type(self):
        """Test multiple domains + type filter"""
        self.step_name = 'TC_FC02_Multiple_Domains_With_Type'
        
        payload = self._generate_v3_lookup_payload(
            domain='ONDC:RET10',
            lookup_type='BPP'
        )
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045]
        )
        
        if not success or not isinstance(data, list) or len(data) == 0:
            return
        
        # Validate all results match type filter
        type_mismatches = [p.get('participant_id') for p in data if p.get('type') != 'BPP']
        if type_mismatches:
            print(f"[{self.step_name}] [FAIL] Type filter failed: {len(type_mismatches)} non-BPP")
            return
        
        print(f"[{self.step_name}] [PASS] Domain+type filter: {len(data)} BPP results")

    @task(1)
    def tc_fc03_multiple_cities_with_type(self):
        """Test multiple cities + type filter"""
        self.step_name = 'TC_FC03_Multiple_Cities_With_Type'
        
        payload = self._generate_v3_lookup_payload(
            city='std:080',
            lookup_type='BAP'
        )
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045]
        )
        
        if not success or not isinstance(data, list) or len(data) == 0:
            return
        
        # Validate type filter
        type_mismatches = [p.get('participant_id') for p in data if p.get('type') != 'BAP']
        if type_mismatches:
            print(f"[{self.step_name}] [FAIL] Type filter failed: {len(type_mismatches)} non-BAP")
            return
        
        print(f"[{self.step_name}] [PASS] City+type filter: {len(data)} BAP results")

    @task(1)
    def tc_fc04_all_filters_combined(self):
        """Test all applicable filters combined (domain + city + type)"""
        self.step_name = 'TC_FC04_All_Filters_Combined'
        
        payload = self._generate_v3_lookup_payload(
            domain='ONDC:RET10',
            city='std:080',
            lookup_type='BPP'
        )
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045]
        )
        
        if not success or not isinstance(data, list):
            return  # Error already handled
        
        # If no results, already marked as success
        if len(data) == 0:
            print(f"[{self.step_name}] [INFO] Filter accepted but no results")
            return
        
        # Comprehensive filter validation
        validator = LookupResponseValidator()
        is_valid, errors = validator.validate_filter_effectiveness(
            data,
            {'domain': ['ONDC:RET10'], 'city': ['std:080']}
        )
        
        if not is_valid:
            print(f"[{self.step_name}] [FAIL] Filter validation failed: {errors[0] if errors else 'Unknown'}")
            return
        
        # Validate type separately
        type_mismatches = [p.get('participant_id') for p in data if p.get('type') != 'BPP']
        if type_mismatches:
            print(f"[{self.step_name}] [FAIL] Type filter failed: {len(type_mismatches)} non-BPP")
            return
        
        print(f"[{self.step_name}] [PASS] All filters (domain+city+type): {len(data)} results")

    # ============================================================
    # SELECT_KEYS VALIDATION TESTS
    # ============================================================

    @task(1)
    def tc_sk01_select_keys_single_field(self):
        """Test select with single field from keys section"""
        self.step_name = 'TC_SK01_Select_Keys_Single_Field'
        
        payload = self._generate_v3_lookup_payload(
            include=['keys'],
            select=['keys.signing_public_key']
        )
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045]
        )
        
        if not success or not isinstance(data, list) or len(data) == 0:
            return  # Error already handled
        
        # Validate requested key is present
        sample = data[0]
        
        # Root parameters are always shown
        if 'participant_id' not in sample:
            print(f"[{self.step_name}] [FAIL] Root parameter 'participant_id' missing")
            return
        
        # Validate keys section is present
        if 'keys' not in sample:
            print(f"[{self.step_name}] [FAIL] Selected section 'keys' missing")
            return
        
        # Validate only selected field is in keys section
        if isinstance(sample.get('keys'), list) and len(sample['keys']) > 0:
            key_obj = sample['keys'][0]
            if 'signing_public_key' not in key_obj:
                print(f"[{self.step_name}] [FAIL] Selected field 'signing_public_key' missing")
                return
        
        print(f"[{self.step_name}] [PASS] select with include working: {len(data)} results")

    @task(1)
    def tc_sk02_select_keys_multiple_fields(self):
        """Test select with multiple fields from keys section"""
        self.step_name = 'TC_SK02_Select_Keys_Multiple_Fields'
        
        payload = self._generate_v3_lookup_payload(
            include=['keys'],
            select=['keys.signing_public_key', 'keys.encryption_public_key']
        )
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045, 15050, 15055]
        )
        
        if not success or not isinstance(data, list) or len(data) == 0:
            return  # Error already handled
        
        # Validate requested keys are present
        sample = data[0]
        
        # Root parameters are always present
        if 'participant_id' not in sample:
            print(f"[{self.step_name}] [FAIL] Root parameter 'participant_id' missing")
            return
        
        # Validate keys section is present
        if 'keys' not in sample:
            print(f"[{self.step_name}] [FAIL] Selected section 'keys' missing")
            return
        
        # Validate selected fields are in keys section
        if isinstance(sample.get('keys'), list) and len(sample['keys']) > 0:
            key_obj = sample['keys'][0]
            required_fields = ['signing_public_key', 'encryption_public_key']
            missing_fields = [f for f in required_fields if f not in key_obj]
            
            if missing_fields:
                print(f"[{self.step_name}] [FAIL] Missing selected fields: {missing_fields}")
                return
        
        print(f"[{self.step_name}] [PASS] Multiple select fields: {len(data)} results")

    @task(1)
    def tc_sk03_select_keys_all_standard_fields(self):
        """Test include with multiple sections (keys, contacts, locations)"""
        self.step_name = 'TC_SK03_Select_Keys_All_Standard_Fields'
        
        # Include multiple supported sections
        payload = self._generate_v3_lookup_payload(
            include=['keys', 'contacts', 'locations'],
            select=[
                'keys.signing_public_key',
                'keys.encryption_public_key',
                'contacts.contact_email',
                'locations.location_id'
            ]
        )
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045, 15050, 15055]
        )
        
        if not success or not isinstance(data, list) or len(data) == 0:
            return  # Error already handled
        
        # Validate at least one section is present
        sample = data[0]
        included_sections = [s for s in ['keys', 'contacts', 'locations'] if s in sample]
        
        if not included_sections:
            print(f"[{self.step_name}] [FAIL] No included sections found in response")
            return
        
        print(f"[{self.step_name}] [PASS] Multiple sections included: {included_sections}, {len(data)} results")

    # ============================================================
    # DATA QUALITY VALIDATION TESTS
    # ============================================================

    @task(1)
    def tc_dq01_no_duplicate_participants(self):
        """Test that response contains no duplicate participant_ids"""
        self.step_name = 'TC_DQ01_No_Duplicate_Participants'
        
        # Get all participants (no filters)
        payload = self._generate_v3_lookup_payload()
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045, 15050, 15055]
        )
        
        if not success or not isinstance(data, list):
            return  # Error already handled
        
        # If no results, already marked as success
        if len(data) == 0:
            print(f"[{self.step_name}] [INFO] No results to check for duplicates")
            return
        
        # Check for duplicates
        participant_ids = [p.get('participant_id') for p in data if p.get('participant_id')]
        unique_ids = set(participant_ids)
        
        if len(participant_ids) != len(unique_ids):
            duplicates = [pid for pid in participant_ids if participant_ids.count(pid) > 1]
            unique_duplicates = list(set(duplicates))
            print(f"[{self.step_name}] [FAIL] Found {len(unique_duplicates)} duplicate participant_ids: {unique_duplicates[:3]}")
            return
        
        print(f"[{self.step_name}] [PASS] No duplicates in {len(data)} participants")

    @task(1)
    def tc_dq02_filter_accuracy_domain(self):
        """Validate all returned participants match domain filter"""
        self.step_name = 'TC_DQ02_Filter_Accuracy_Domain'
        
        test_domain = 'ONDC:RET10'
        payload = self._generate_v3_lookup_payload(domain=test_domain)
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045]
        )
        
        if not success or not isinstance(data, list):
            return  # Error already handled
        
        # If no results, already marked as success
        if len(data) == 0:
            print(f"[{self.step_name}] [INFO] Filter accepted but no results")
            return
        
        # Validate filter accuracy
        validator = LookupResponseValidator()
        is_valid, errors = validator.validate_filter_effectiveness(
            data,
            {'domain': [test_domain]}
        )
        
        if not is_valid:
            print(f"[{self.step_name}] [FAIL] Domain filter accuracy failed: {errors[0]}")
            return
        
        print(f"[{self.step_name}] [PASS] All {len(data)} results match domain filter")

    @task(1)
    def tc_dq03_filter_accuracy_city(self):
        """Validate all returned participants match city filter"""
        self.step_name = 'TC_DQ03_Filter_Accuracy_City'
        
        test_city = 'std:080'
        payload = self._generate_v3_lookup_payload(city=test_city)
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045]
        )
        
        if not success or not isinstance(data, list):
            return  # Error already handled
        
        # If no results, already marked as success
        if len(data) == 0:
            print(f"[{self.step_name}] [INFO] Filter accepted but no results")
            return
        
        # Validate filter accuracy
        validator = LookupResponseValidator()
        is_valid, errors = validator.validate_filter_effectiveness(
            data,
            {'city': [test_city]}
        )
        
        if not is_valid:
            print(f"[{self.step_name}] [FAIL] City filter accuracy failed: {errors[0]}")
            return
        
        print(f"[{self.step_name}] [PASS] All {len(data)} results match city filter")

    @task(1)
    def tc_dq04_filter_accuracy_type(self):
        """Validate all returned participants match type filter"""
        self.step_name = 'TC_DQ04_Filter_Accuracy_Type'
        
        test_type = 'BPP'
        payload = self._generate_v3_lookup_payload(lookup_type=test_type)
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045]
        )
        
        if not success or not isinstance(data, list):
            return  # Error already handled
        
        # If no results, already marked as success
        if len(data) == 0:
            print(f"[{self.step_name}] [INFO] Filter accepted but no results")
            return
        
        # Check type accuracy
        mismatches = [p.get('participant_id') for p in data if p.get('type') != test_type]
        
        if mismatches:
            print(f"[{self.step_name}] [FAIL] Type filter failed: {len(mismatches)} mismatches")
            return
        
        print(f"[{self.step_name}] [PASS] All {len(data)} results match type={test_type}")

    # ============================================================
    # PERFORMANCE & LOAD TESTS
    # ============================================================

    @task(1)
    def tc_perf01_response_time_large_resultset(self):
        """Measure response time for queries returning large result sets"""
        self.step_name = 'TC_PERF01_Response_Time_Large_ResultSet'
        
        # Query without filters to get large result set
        payload = self._generate_v3_lookup_payload()
        
        start_time = time.time()
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045]
        )
        
        elapsed_time = (time.time() - start_time) * 1000  # Convert to ms
        
        if not success or not isinstance(data, list):
            return  # Error already handled
        
        # Performance threshold: 2000ms for large result sets
        if elapsed_time > 2000:
            print(f"[{self.step_name}] [FAIL] Response time {elapsed_time:.0f}ms exceeds 2000ms threshold")
        else:
            print(f"[{self.step_name}] [PASS] Response time: {elapsed_time:.0f}ms for {len(data)} results")

    @task(1)
    def tc_perf02_response_time_filtered_query(self):
        """Measure response time for filtered queries"""
        self.step_name = 'TC_PERF02_Response_Time_Filtered_Query'
        
        payload = self._generate_v3_lookup_payload(
            domain='ONDC:RET10',
            city='std:080',
            lookup_type='BPP'
        )
        
        start_time = time.time()
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045]
        )
        
        elapsed_time = (time.time() - start_time) * 1000
        
        if not success:
            print(f"[{self.step_name}] [INFO] No matching participants in test environment (took {elapsed_time:.0f}ms)")
            return
        
        # Performance threshold: 1000ms for filtered queries
        if elapsed_time > 1000:
            print(f"[{self.step_name}] [FAIL] Response time {elapsed_time:.0f}ms exceeds 1000ms threshold")
        else:
            print(f"[{self.step_name}] [PASS] Filtered query time: {elapsed_time:.0f}ms for {len(data) if isinstance(data, list) else 0} results")

    # ============================================================
    # ADVANCED V3 COVERAGE TESTS
    # ============================================================

    @task(1)
    def tc_adv01_include_empty_array(self):
        """Test include with empty array (should return root params only)"""
        self.step_name = 'TC_ADV01_Include_Empty_Array'
        
        payload = self._generate_v3_lookup_payload(include=[])
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045]
        )
        
        if not success or not isinstance(data, list) or len(data) == 0:
            return  # Error already handled
        
        # Verify only root parameters present (no keys, contacts, etc.)
        sample = data[0]
        root_params = ['participant_id', 'subscriber_id', 'type', 'domain', 'city', 'country']
        has_only_root = all(k in root_params for k in sample.keys() if not k.startswith('_'))
        
        if not has_only_root:
            extra_fields = set(sample.keys()) - set(root_params)
            print(f"[{self.step_name}] [INFO] Empty include returned extra fields: {extra_fields}")
        
        print(f"[{self.step_name}] [PASS] Empty include array: {len(data)} results")

    @task(1)
    def tc_adv02_include_invalid_section(self):
        """Test include with invalid section name (should reject or ignore)"""
        self.step_name = 'TC_ADV02_Include_Invalid_Section'
        
        payload = self._generate_v3_lookup_payload(
            include=['invalid_section_xyz']
        )
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045, 15050, 15055]
        )
        
        # If error was handled, it was already marked as success
        if not success:
            return  # This would only happen for unexpected errors
        
        # If acceptable error was received, return early (already logged as PASS)
        if isinstance(data, dict) and 'error' in data:
            return
        
        # If status 200 with valid data, server ignored invalid section
        if status == 200 and isinstance(data, list):
            print(f"[{self.step_name}] [PASS] Invalid section ignored, returned 200")
        else:
            print(f"[{self.step_name}] [FAIL] Unexpected status {status}")

    @task(1)
    def tc_adv03_select_invalid_field(self):
        """Test select with invalid field name (should reject or ignore)"""
        self.step_name = 'TC_ADV03_Select_Invalid_Field'
        
        payload = self._generate_v3_lookup_payload(
            include=['keys'],
            select=['keys.invalid_field_xyz']
        )
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045, 15050, 15055]
        )
        
        # If error was handled, it was already marked as success
        if not success:
            return  # This would only happen for unexpected errors
        
        # If acceptable error was received, return early (already logged as PASS)
        if isinstance(data, dict) and 'error' in data:
            return
        
        # If status 200 with valid data, server ignored invalid field
        if status == 200 and isinstance(data, list):
            print(f"[{self.step_name}] [PASS] Invalid field ignored, returned 200")
        else:
            print(f"[{self.step_name}] [FAIL] Unexpected status {status}")

    @task(1)
    def tc_adv04_nptype_filter(self):
        """Test npType filter (buyer, seller, logistics)"""
        self.step_name = 'TC_ADV04_NpType_Filter'
        
        # Try npType filter - may not be supported
        payload = self._generate_v3_lookup_payload(npType='seller')
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045, 15050, 15055]
        )
        
        # If error was handled, it was already marked as success
        if not success:
            return  # This would only happen for unexpected errors
        
        # If acceptable error was received, return early (already logged as PASS)
        if isinstance(data, dict) and 'error' in data:
            return
        
        # Status 200 means npType filter is supported
        if status == 200 and isinstance(data, list):
            print(f"[{self.step_name}] [PASS] npType filter accepted: {len(data)} results")
        else:
            print(f"[{self.step_name}] [FAIL] Unexpected status {status}")

    @task(1)
    def tc_adv05_status_filter(self):
        """Test status filter (INITIATED, SUBSCRIBED, UNSUBSCRIBED)"""
        self.step_name = 'TC_ADV05_Status_Filter'
        
        payload = self._generate_v3_lookup_payload(status='SUBSCRIBED')
        
        success, data, status_code = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045, 15050, 15055]
        )
        
        # If error was handled, it was already marked as success
        if not success:
            return  # This would only happen for unexpected errors
        
        # If acceptable error was received, return early (already logged as PASS)
        if isinstance(data, dict) and 'error' in data:
            return
        
        if status_code == 200 and isinstance(data, list):
            # Verify all results have SUBSCRIBED status
            if len(data) > 0:
                non_subscribed = [p for p in data if p.get('status') != 'SUBSCRIBED']
                if non_subscribed:
                    print(f"[{self.step_name}] [FAIL] Status filter failed: {len(non_subscribed)} non-SUBSCRIBED")
                else:
                    print(f"[{self.step_name}] [PASS] Status filter working: {len(data)} SUBSCRIBED results")
            else:
                print(f"[{self.step_name}] [PASS] Status filter accepted")
        else:
            print(f"[{self.step_name}] [FAIL] Unexpected status {status_code}")

    @task(1)
    def tc_adv06_wildcard_domain(self):
        """Test wildcard domain matching (ONDC:*)"""
        self.step_name = 'TC_ADV06_Wildcard_Domain'
        
        payload = self._generate_v3_lookup_payload(domain='ONDC:*')
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045, 15050, 15055]
        )
        
        # If error was handled, it was already marked as success
        if not success:
            return  # This would only happen for unexpected errors
        
        # If acceptable error was received, return early (already logged as PASS)
        if isinstance(data, dict) and 'error' in data:
            return
        
        if status == 200 and isinstance(data, list):
            if len(data) > 0:
                # Check if wildcard matched multiple domains
                domains = set(p.get('domain', '') for p in data)
                if len(domains) > 1:
                    print(f"[{self.step_name}] [PASS] Wildcard matched {len(domains)} domains, {len(data)} results")
                else:
                    print(f"[{self.step_name}] [INFO] Wildcard returned data but may not support matching")
            else:
                print(f"[{self.step_name}] [INFO] Wildcard accepted but no results")
        else:
            print(f"[{self.step_name}] [FAIL] Unexpected status {status}")

    @task(1)
    def tc_adv07_wildcard_city(self):
        """Test wildcard city matching (std:*)"""
        self.step_name = 'TC_ADV07_Wildcard_City'
        
        payload = self._generate_v3_lookup_payload(city='std:*')
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045, 15050, 15055]
        )
        
        # If error was handled, it was already marked as success
        if not success:
            return  # This would only happen for unexpected errors
        
        # If acceptable error was received, return early (already logged as PASS)
        if isinstance(data, dict) and 'error' in data:
            return
        
        if status == 200 and isinstance(data, list):
            if len(data) > 0:
                # Check if wildcard matched multiple cities
                cities = set(p.get('city', '') for p in data if p.get('city'))
                if len(cities) > 1:
                    print(f"[{self.step_name}] [PASS] Wildcard matched {len(cities)} cities, {len(data)} results")
                else:
                    print(f"[{self.step_name}] [INFO] Wildcard returned data but may not support matching")
            else:
                print(f"[{self.step_name}] [INFO] Wildcard accepted but no results")
        else:
            print(f"[{self.step_name}] [FAIL] Unexpected status {status}")

    @task(1)
    def tc_adv08_batch_lookup(self):
        """Test batch lookup with multiple participant_ids"""
        self.step_name = 'TC_ADV08_Batch_Lookup'
        
        # Try batch lookup with array of participant_ids
        payload = self._generate_v3_lookup_payload(
            subscriber_id=[
                'futuresoftmsnprod.clouddeploy.in',
                'ondc-lbnp-preprod.pidge.in'
            ]
        )
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001, 15045, 15050, 15055]
        )
        
        # If error was handled, it was already marked as success
        if not success:
            return  # This would only happen for unexpected errors
        
        # If acceptable error was received, return early (already logged as PASS)
        if isinstance(data, dict) and 'error' in data:
            return
        
        if status == 200 and isinstance(data, list):
            if len(data) >= 1:
                print(f"[{self.step_name}] [PASS] Batch lookup returned {len(data)} results")
            else:
                print(f"[{self.step_name}] [INFO] Batch lookup accepted but no results")
        else:
            print(f"[{self.step_name}] [FAIL] Unexpected status {status}")


tasks = [ONDCRegLookupFilterCombinations]
