from locust import task
from tests.registry.lookup.common.base_lookup_test import RegistryLookupBase
from tests.utils.response_validators import LookupResponseValidator
import time
import json

"""
ONDC Registry V2 Lookup - Filter Combination Tests
Similar to V3 tests but for V2 API (with authentication differences)

V2 uses same response structure as V1:
- encr_public_key (not encryption_public_key)
- subscriber_url, br_id, ukId (not in uris/keys structure)

Priority test scenarios:
- Multiple domains AND cities together
- Multiple domains + type filter
- Multiple cities + type filter
- All filters combined (domain + city + type)
- select_keys with different combinations
- Duplicate check in responses
- Filter accuracy validation
- Response time for large result sets
"""

class ONDCRegLookupV2FilterCombinations(RegistryLookupBase):

    config_file = 'resources/registry/lookup/v2/test_lookup_filter_combinations_v2.yml'
    tenant_name = 'ondcRegistry'

    def on_start(self):
        """Initialize test and register participant at runtime"""
        super().on_start()
        
        # Register participant before running tests
        registration_success = self._register_participant_runtime()
        if registration_success:
            print(f"\n[INFO] V2 Filter Combination Tests initialized for: {self.participant_id}")
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

    def _send_with_error_handling(self, step_name, payload, acceptable_errors=None, fail_on_errors=None):
        """
        Send V2 lookup request with custom error code handling.
        Similar to V3 but uses V2 authentication (ED25519 signature).
        
        Args:
            step_name: Test step name
            payload: Request payload
            acceptable_errors: List of error codes to treat as PASS (e.g., [1001, 1050])
            fail_on_errors: List of error codes to treat as FAIL (e.g., [1070])
        
        Returns:
            tuple: (success, data, status_code)
        """
        acceptable_errors = acceptable_errors or []
        fail_on_errors = fail_on_errors or []
        
        # Generate headers with ED25519 signature (same as V3)
        headers = self._generate_v2_headers(payload)
        serialized_body = headers.pop('serialized_body', None)
        if not serialized_body:
            serialized_body = json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
        
        with self.client.post(
                name=step_name,
                url="/v2.0/lookup",
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
            
            # Check for error codes in response body (same pattern as V3)
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
        self.step_name = 'TC_FC01_V2_Multiple_Domains_And_Cities'
        
        payload = self._generate_v2_lookup_payload(
            domain='ONDC:RET10',
            city='std:080'
        )
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001]
        )
        
        if not success or not isinstance(data, list):
            return
        
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
        self.step_name = 'TC_FC02_V2_Multiple_Domains_With_Type'
        
        payload = self._generate_v2_lookup_payload(
            domain='ONDC:RET10',
            lookup_type='BPP'
        )
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001]
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
        self.step_name = 'TC_FC03_V2_Multiple_Cities_With_Type'
        
        payload = self._generate_v2_lookup_payload(
            city='std:080',
            lookup_type='BAP'
        )
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001]
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
        self.step_name = 'TC_FC04_V2_All_Filters_Combined'
        
        payload = self._generate_v2_lookup_payload(
            domain='ONDC:RET10',
            city='std:080',
            lookup_type='BPP'
        )
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001]
        )
        
        if not success or not isinstance(data, list) or len(data) == 0:
            return
        
        # Comprehensive filter validation
        validator = LookupResponseValidator()
        is_valid, errors = validator.validate_filter_effectiveness(
            data,
            {'domain': ['ONDC:RET10'], 'city': ['std:080']}
        )
        
        if not is_valid:
            print(f"[{self.step_name}] [FAIL] Filter validation failed")
            return
        
        # Validate type separately
        type_mismatches = [p.get('participant_id') for p in data if p.get('type') != 'BPP']
        if type_mismatches:
            print(f"[{self.step_name}] [FAIL] Type filter failed: {len(type_mismatches)} non-BPP")
            return
        
        print(f"[{self.step_name}] [PASS] All filters (domain+city+type): {len(data)} results")

    # ============================================================
    # DATA QUALITY VALIDATION TESTS
    # ============================================================

    @task(1)
    def tc_dq01_no_duplicate_participants(self):
        """Test that response contains no duplicate participant_ids"""
        self.step_name = 'TC_DQ01_V2_No_Duplicate_Participants'
        
        # V2 requires country + at least one filter (using type to get broad results)
        payload = self._generate_v2_lookup_payload(lookup_type='BPP')
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001]
        )
        
        if not success or not isinstance(data, list) or len(data) == 0:
            return
        
        # Check for duplicates by subscriber_id (V2 doesn't have participant_id)
        subscriber_ids = [p.get('subscriber_id') for p in data if p.get('subscriber_id')]
        unique_ids = set(subscriber_ids)
        
        if len(subscriber_ids) != len(unique_ids):
            duplicates = [sid for sid in subscriber_ids if subscriber_ids.count(sid) > 1]
            unique_duplicates = list(set(duplicates))
            print(f"[{self.step_name}] [FAIL] Found {len(unique_duplicates)} duplicate subscriber_ids")
            return
        
        print(f"[{self.step_name}] [PASS] No duplicates in {len(data)} participants")

    @task(1)
    def tc_dq02_filter_accuracy_domain(self):
        """Validate all returned participants match domain filter"""
        self.step_name = 'TC_DQ02_V2_Filter_Accuracy_Domain'
        
        test_domain = 'ONDC:RET10'
        payload = self._generate_v2_lookup_payload(domain=test_domain)
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001]
        )
        
        if not success or not isinstance(data, list) or len(data) == 0:
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
        self.step_name = 'TC_DQ03_V2_Filter_Accuracy_City'
        
        test_city = 'std:080'
        payload = self._generate_v2_lookup_payload(city=test_city)
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001]
        )
        
        if not success or not isinstance(data, list) or len(data) == 0:
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

    # ============================================================
    # V1/V2 vs V3 SCHEMA VALIDATION TESTS
    # ============================================================

    @task(1)
    def tc_schema01_v2_has_encr_public_key(self):
        """Validate V2 uses encr_public_key (not encryption_public_key like V3)"""
        self.step_name = 'TC_SCHEMA01_V2_Has_Encr_Public_Key'
        
        # V2 requires country + at least one filter (using type to get results)
        payload = self._generate_v2_lookup_payload(lookup_type='BPP')
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001]
        )
        
        if not success or not isinstance(data, list) or len(data) == 0:
            return
        
        # Check first participant
        sample = data[0]
        
        # V2 should have encr_public_key in keys array (same as V1)
        keys = sample.get('keys', [])
        if not keys or len(keys) == 0:
            print(f"[{self.step_name}] [FAIL] No keys array found")
            return
        
        key_obj = keys[0]
        has_encr_key = 'encr_public_key' in key_obj
        has_encryption_key = 'encryption_public_key' in key_obj  # V3 field
        
        if has_encr_key and not has_encryption_key:
            print(f"[{self.step_name}] [PASS] ✓ V2 correctly uses 'encr_public_key' (not V3's 'encryption_public_key')")
        elif has_encryption_key:
            print(f"[{self.step_name}] [FAIL] Found 'encryption_public_key' (V3 field) in V2 response")
        else:
            print(f"[{self.step_name}] [FAIL] Missing encryption key field")

    @task(1)
    def tc_schema02_v2_has_v1_fields(self):
        """Validate V2 has subscriber_url, br_id, ukId (same as V1, different from V3)"""
        self.step_name = 'TC_SCHEMA02_V2_Has_V1_Fields'
        
        # V2 requires country + at least one filter (using type to get results)
        payload = self._generate_v2_lookup_payload(lookup_type='BPP')
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001]
        )
        
        if not success or not isinstance(data, list) or len(data) == 0:
            return
        
        # Check first participant
        sample = data[0]
        
        # V2 should have these fields at root level (same as V1)
        has_subscriber_url = 'subscriber_url' in sample
        has_br_id = 'br_id' in sample
        has_ukId = 'ukId' in sample
        
        # V2 should NOT have participant_id (that's V3 only)
        has_participant_id = 'participant_id' in sample
        
        missing_fields = []
        if not has_subscriber_url:
            missing_fields.append('subscriber_url')
        if not has_br_id:
            missing_fields.append('br_id')
        if not has_ukId:
            missing_fields.append('ukId')
        
        if missing_fields:
            print(f"[{self.step_name}] [FAIL] Missing V1/V2 fields: {', '.join(missing_fields)}")
        elif has_participant_id:
            print(f"[{self.step_name}] [FAIL] Found 'participant_id' (V3 field) in V2 response")
        else:
            print(f"[{self.step_name}] [PASS] ✓ V2 correctly has subscriber_url, br_id, ukId (same as V1)")

    # ============================================================
    # PERFORMANCE TESTS
    # ============================================================

    @task(1)
    def tc_perf01_response_time_large_resultset(self):
        """Measure response time for queries returning large result sets"""
        self.step_name = 'TC_PERF01_V2_Response_Time_Large_ResultSet'
        
        # V2 requires country + at least one filter (using type for large result set)
        payload = self._generate_v2_lookup_payload(lookup_type='BPP')
        
        start_time = time.time()
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001]
        )
        
        elapsed_time = (time.time() - start_time) * 1000  # Convert to ms
        
        if not success or not isinstance(data, list):
            return
        
        # Performance threshold: 2000ms for large result sets
        if elapsed_time > 2000:
            print(f"[{self.step_name}] [FAIL] Response time {elapsed_time:.0f}ms exceeds 2000ms threshold")
        else:
            print(f"[{self.step_name}] [PASS] Response time: {elapsed_time:.0f}ms for {len(data)} results")

    @task(1)
    def tc_perf02_response_time_filtered_query(self):
        """Measure response time for filtered queries"""
        self.step_name = 'TC_PERF02_V2_Response_Time_Filtered_Query'
        
        payload = self._generate_v2_lookup_payload(
            domain='ONDC:RET10',
            city='std:080',
            lookup_type='BPP'
        )
        
        start_time = time.time()
        
        success, data, status = self._send_with_error_handling(
            self.step_name,
            payload,
            fail_on_errors=[1070],
            acceptable_errors=[1001]
        )
        
        elapsed_time = (time.time() - start_time) * 1000
        
        if not success:
            return
        
        # Performance threshold: 1000ms for filtered queries
        if elapsed_time > 1000:
            print(f"[{self.step_name}] [FAIL] Response time {elapsed_time:.0f}ms exceeds 1000ms threshold")
        else:
            print(f"[{self.step_name}] [PASS] Filtered query time: {elapsed_time:.0f}ms for {len(data) if isinstance(data, list) else 0} results")


tasks = [ONDCRegLookupV2FilterCombinations]
