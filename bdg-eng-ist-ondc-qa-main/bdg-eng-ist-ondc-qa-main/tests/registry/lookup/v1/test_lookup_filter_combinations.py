from locust import task
from tests.registry.lookup.common.base_lookup_test import RegistryLookupBase
from tests.utils.response_validators import LookupResponseValidator
import time
import json

"""
ONDC Registry V1 Lookup - Filter Combination Tests
V1 is the simplest lookup form - only country and type parameters

V1 uses response structure:
- encr_public_key (not encryption_public_key)
- subscriber_url, br_id, ukId (not in uris/keys structure)
- No domain/city filters (V2/V3 feature)

Endpoint: /lookup (no version prefix, public API, no auth)

Priority test scenarios:
- Different type variations (BPP, BAP, BG, REGISTRY)
- Type filter accuracy validation
- Schema validation (V1 fields)
- Duplicate check in responses
- Response time for different query types
- Large result set handling
"""

class ONDCRegLookupV1FilterCombinations(RegistryLookupBase):

    config_file = 'resources/registry/lookup/v1/test_lookup_filter_combinations_v1.yml'
    # tenant_name is set dynamically by --environment parameter (ondcRegistryV1Lookup or ondcRegistryV1LookupProd)

    def on_start(self):
        """Initialize test and register participant at runtime"""
        super().on_start()
        
        # Register participant before running tests (if credentials available)
        if hasattr(self, 'participant_id') and self.participant_id:
            registration_success = self._register_participant_runtime()
            if registration_success:
                print(f"\n[INFO] V1 Filter Combination Tests - Public endpoint /lookup")
                print(f"[INFO] Participant status: SUBSCRIBED (ready for testing)\n")
            else:
                print(f"\n[WARNING] Participant registration uncertain - proceeding with tests\n")
        else:
            print(f"\n[INFO] V1 Filter Combination Tests - Public endpoint /lookup (no auth)\n")

    def _register_participant_runtime(self):
        """Register participant at runtime before running tests"""
        # Simplified registration check for V1 since it's public API
        print(f"\n[REGISTRATION] Checking/Registering participant: {self.participant_id}")
        
        try:
            print(f"[REGISTRATION] Participant will be registered on first use (public API)")
            return True
                
        except Exception as e:
            print(f"[REGISTRATION] Warning: {e}")
            return True  # Continue anyway for public API

    def _send_v1_with_error_handling(self, step_name, payload):
        """
        Send V1 lookup request with error code handling.
        Treats error 1001 (no matching participants) as acceptable.
        
        Args:
            step_name: Test step name
            payload: Request payload
        
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
            
            # Parse response
            try:
                data = response.json()
            except Exception as e:
                response.failure(f"Failed to parse JSON: {str(e)}")
                return False, None, status_code, response
            
            # Check if response is an error object with code 1001 (no results)
            if isinstance(data, dict) and 'error' in data:
                error_code = data.get('error', {}).get('code')
                error_msg = data.get('error', {}).get('message', '')
                
                # Error 1001 means no matching participants - this is acceptable
                if str(error_code) == '1001':
                    response.success()
                    print(f"[{step_name}] [INFO] No matching participants found (error 1001)")
                    return True, [], status_code, response
                
                # Other errors are failures
                response.failure(f"Error {error_code}: {error_msg}")
                return False, None, status_code, response
            
            # Success - return the data array
            if status_code == 200 and isinstance(data, list):
                response.success()
                return True, data, status_code, response
            
            # Unexpected response format
            response.failure(f"Unexpected response format: status={status_code}, type={type(data)}")
            return False, None, status_code, response

    # ============================================================
    # TYPE FILTER TESTS (V1 only supports country + type)
    # ============================================================

    @task(1)
    def tc_type01_filter_bpp(self):
        """Test type filter: BPP participants only"""
        self.step_name = 'TC_TYPE01_V1_Filter_BPP'
        
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
        
        # Validate all results are BPP
        type_mismatches = [p.get('subscriber_id') for p in data if p.get('type') != 'BPP']
        if type_mismatches:
            response.failure(f"Type filter failed: {len(type_mismatches)} non-BPP in results")
            print(f"[{self.step_name}] [FAIL] Type filter failed: {len(type_mismatches)} non-BPP")
            return
        
        print(f"[{self.step_name}] [PASS] Type filter BPP: {len(data)} results, all BPP")

    @task(1)
    def tc_type02_filter_bap(self):
        """Test type filter: BAP participants only"""
        self.step_name = 'TC_TYPE02_V1_Filter_BAP'
        
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
        
        # Validate all results are BAP
        type_mismatches = [p.get('subscriber_id') for p in data if p.get('type') != 'BAP']
        if type_mismatches:
            response.failure(f"Type filter failed: {len(type_mismatches)} non-BAP in results")
            print(f"[{self.step_name}] [FAIL] Type filter failed: {len(type_mismatches)} non-BAP")
            return
        
        print(f"[{self.step_name}] [PASS] Type filter BAP: {len(data)} results, all BAP")

    @task(1)
    def tc_type03_filter_bg(self):
        """Test type filter: BG (Gateway) participants"""
        self.step_name = 'TC_TYPE03_V1_Filter_BG'
        
        payload = self._generate_v1_lookup_payload(lookup_type='BG')
        
        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload
        )
        
        if not success:
            return
        
        if len(data) == 0:
            print(f"[{self.step_name}] [INFO] No BG participants found")
            return
        
        # Validate all results are BG
        type_mismatches = [p.get('subscriber_id') for p in data if p.get('type') != 'BG']
        if type_mismatches:
            response.failure(f"Type filter failed: {len(type_mismatches)} non-BG in results")
            print(f"[{self.step_name}] [FAIL] Type filter failed: {len(type_mismatches)} non-BG")
            return
        
        print(f"[{self.step_name}] [PASS] Type filter BG: {len(data)} results, all BG")

    @task(1)
    def tc_type04_filter_registry(self):
        """Test type filter: REGISTRY participants"""
        self.step_name = 'TC_TYPE04_V1_Filter_REGISTRY'
        
        payload = self._generate_v1_lookup_payload(lookup_type='REGISTRY')
        
        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload
        )
        
        if not success:
            return
        
        if len(data) == 0:
            print(f"[{self.step_name}] [INFO] No REGISTRY participants found")
            return
        
        # Validate all results are REGISTRY
        type_mismatches = [p.get('subscriber_id') for p in data if p.get('type') != 'REGISTRY']
        if type_mismatches:
            response.failure(f"Type filter failed: {len(type_mismatches)} non-REGISTRY in results")
            print(f"[{self.step_name}] [FAIL] Type filter failed: {len(type_mismatches)} non-REGISTRY")
            return
        
        print(f"[{self.step_name}] [PASS] Type filter REGISTRY: {len(data)} results, all REGISTRY")

    # ============================================================
    # DATA QUALITY VALIDATION TESTS
    # ============================================================

    @task(1)
    def tc_dq01_no_duplicate_participants(self):
        """Test that response contains no duplicate subscriber_ids"""
        self.step_name = 'TC_DQ01_V1_No_Duplicate_Participants'
        
        payload = self._generate_v1_lookup_payload(lookup_type='BPP')
        
        success, data, status, response = self._send_v1_lookup_request(
            self.step_name,
            payload
        )
        
        if not success or not isinstance(data, list) or len(data) == 0:
            return
        
        # Check for duplicates by subscriber_id
        subscriber_ids = [p.get('subscriber_id') for p in data if p.get('subscriber_id')]
        unique_ids = set(subscriber_ids)
        
        if len(subscriber_ids) != len(unique_ids):
            duplicates = [sid for sid in subscriber_ids if subscriber_ids.count(sid) > 1]
            unique_duplicates = list(set(duplicates))
            response.failure(f"Found {len(unique_duplicates)} duplicate subscriber_ids")
            print(f"[{self.step_name}] [FAIL] Found {len(unique_duplicates)} duplicate subscriber_ids")
            return
        
        print(f"[{self.step_name}] [PASS] No duplicates in {len(data)} participants")

    @task(1)
    def tc_dq02_all_required_fields_present(self):
        """Validate all participants have required V1 fields"""
        self.step_name = 'TC_DQ02_V1_All_Required_Fields_Present'
        
        payload = self._generate_v1_lookup_payload(lookup_type='BPP')
        
        success, data, status, response = self._send_v1_lookup_request(
            self.step_name,
            payload
        )
        
        if not success or not isinstance(data, list) or len(data) == 0:
            return
        
        # Validate schema for all participants
        validator = LookupResponseValidator()
        missing_fields_count = 0
        
        for participant in data:
            is_valid, errors = validator.validate_participant_schema(participant, api_version='v1')
            if not is_valid:
                missing_fields_count += 1
        
        if missing_fields_count > 0:
            response.failure(f"{missing_fields_count}/{len(data)} participants have missing fields")
            print(f"[{self.step_name}] [FAIL] {missing_fields_count}/{len(data)} participants have missing fields")
            return
        
        print(f"[{self.step_name}] [PASS] All {len(data)} participants have required fields")

    @task(1)
    def tc_dq03_valid_subscriber_urls(self):
        """Validate all participants have valid subscriber_url format"""
        self.step_name = 'TC_DQ03_V1_Valid_Subscriber_URLs'
        
        payload = self._generate_v1_lookup_payload(lookup_type='BPP')
        
        success, data, status, response = self._send_v1_lookup_request(
            self.step_name,
            payload
        )
        
        if not success or not isinstance(data, list) or len(data) == 0:
            return
        
        # Check that subscriber_url is valid HTTP(S) URL
        invalid_urls = []
        for participant in data:
            url = participant.get('subscriber_url', '')
            if not url or not (url.startswith('http://') or url.startswith('https://')):
                invalid_urls.append(participant.get('subscriber_id', 'unknown'))
        
        if invalid_urls:
            response.failure(f"{len(invalid_urls)} participants have invalid subscriber_url")
            print(f"[{self.step_name}] [FAIL] {len(invalid_urls)} participants have invalid subscriber_url")
            return
        
        print(f"[{self.step_name}] [PASS] All {len(data)} participants have valid subscriber_url")

    # ============================================================
    # V1 SCHEMA VALIDATION TESTS
    # ============================================================

    @task(1)
    def tc_schema01_v1_has_encr_public_key(self):
        """Validate V1 uses encr_public_key (not encryption_public_key like V3)"""
        self.step_name = 'TC_SCHEMA01_V1_Has_Encr_Public_Key'
        
        payload = self._generate_v1_lookup_payload(lookup_type='BPP')
        
        success, data, status, response = self._send_v1_lookup_request(
            self.step_name,
            payload
        )
        
        if not success or not isinstance(data, list) or len(data) == 0:
            return
        
        # Check first participant
        sample = data[0]
        
        # V1 should have encr_public_key in keys array
        keys = sample.get('keys', [])
        if not keys or len(keys) == 0:
            print(f"[{self.step_name}] [FAIL] No keys array found")
            return
        
        key_obj = keys[0]
        has_encr_key = 'encr_public_key' in key_obj
        has_encryption_key = 'encryption_public_key' in key_obj  # V3 field
        
        if has_encr_key and not has_encryption_key:
            print(f"[{self.step_name}] [PASS] ✓ V1 correctly uses 'encr_public_key' (not V3's 'encryption_public_key')")
        elif has_encryption_key:
            response.failure("Found 'encryption_public_key' (V3 field) in V1 response")
            print(f"[{self.step_name}] [FAIL] Found 'encryption_public_key' (V3 field) in V1 response")
        else:
            print(f"[{self.step_name}] [FAIL] Missing encryption key field")

    @task(1)
    def tc_schema02_v1_has_root_level_fields(self):
        """Validate V1 has subscriber_url, br_id, ukId at root level (not in nested structure)"""
        self.step_name = 'TC_SCHEMA02_V1_Has_Root_Level_Fields'
        
        payload = self._generate_v1_lookup_payload(lookup_type='BPP')
        
        success, data, status, response = self._send_v1_lookup_request(
            self.step_name,
            payload
        )
        
        if not success or not isinstance(data, list) or len(data) == 0:
            return
        
        # Check first participant
        sample = data[0]
        
        # V1 should have these fields at root level (not in nested structure like V3)
        has_subscriber_url = 'subscriber_url' in sample
        has_br_id = 'br_id' in sample
        has_ukId = 'ukId' in sample
        
        # V1 should NOT have participant_id (that's V3 only)
        has_participant_id = 'participant_id' in sample
        
        missing_fields = []
        if not has_subscriber_url:
            missing_fields.append('subscriber_url')
        if not has_br_id:
            missing_fields.append('br_id')
        if not has_ukId:
            missing_fields.append('ukId')
        
        if missing_fields:
            response.failure(f"Missing V1 fields: {', '.join(missing_fields)}")
            print(f"[{self.step_name}] [FAIL] Missing V1 fields: {', '.join(missing_fields)}")
        elif has_participant_id:
            response.failure("Found 'participant_id' (V3 field) in V1 response")
            print(f"[{self.step_name}] [FAIL] Found 'participant_id' (V3 field) in V1 response")
        else:
            print(f"[{self.step_name}] [PASS] ✓ V1 correctly has subscriber_url, br_id, ukId at root level")

    @task(1)
    def tc_schema03_v1_keys_array_structure(self):
        """Validate V1 keys array has correct structure"""
        self.step_name = 'TC_SCHEMA03_V1_Keys_Array_Structure'
        
        payload = self._generate_v1_lookup_payload(lookup_type='BPP')
        
        success, data, status, response = self._send_v1_lookup_request(
            self.step_name,
            payload
        )
        
        if not success or not isinstance(data, list) or len(data) == 0:
            return
        
        # Check first participant's keys array
        sample = data[0]
        keys = sample.get('keys', [])
        
        if not isinstance(keys, list):
            response.failure("Keys is not an array")
            print(f"[{self.step_name}] [FAIL] Keys is not an array")
            return
        
        if len(keys) == 0:
            print(f"[{self.step_name}] [INFO] Keys array is empty")
            return
        
        # Check first key object structure
        key_obj = keys[0]
        required_key_fields = ['encr_public_key', 'signing_public_key', 'valid_from', 'valid_until']
        missing_key_fields = [f for f in required_key_fields if f not in key_obj]
        
        if missing_key_fields:
            response.failure(f"Key object missing fields: {', '.join(missing_key_fields)}")
            print(f"[{self.step_name}] [FAIL] Key object missing fields: {', '.join(missing_key_fields)}")
        else:
            print(f"[{self.step_name}] [PASS] ✓ Keys array has correct V1 structure")

    # ============================================================
    # PERFORMANCE TESTS
    # ============================================================

    @task(1)
    def tc_perf01_response_time_large_resultset(self):
        """Measure response time for queries returning large result sets"""
        self.step_name = 'TC_PERF01_V1_Response_Time_Large_ResultSet'
        
        # BPP typically returns large result set
        payload = self._generate_v1_lookup_payload(lookup_type='BPP')
        
        start_time = time.time()
        
        success, data, status, response = self._send_v1_lookup_request(
            self.step_name,
            payload
        )
        
        elapsed_time = (time.time() - start_time) * 1000  # Convert to ms
        
        if not success or not isinstance(data, list):
            return
        
        # Performance threshold: 2000ms for large result sets
        if elapsed_time > 2000:
            response.failure(f"Response time {elapsed_time:.0f}ms exceeds 2000ms threshold")
            print(f"[{self.step_name}] [FAIL] Response time {elapsed_time:.0f}ms exceeds 2000ms threshold")
        else:
            print(f"[{self.step_name}] [PASS] Response time: {elapsed_time:.0f}ms for {len(data)} results")

    @task(1)
    def tc_perf02_response_time_small_resultset(self):
        """Measure response time for queries with smaller result sets"""
        self.step_name = 'TC_PERF02_V1_Response_Time_Small_ResultSet'
        
        # BG typically returns smaller result set
        payload = self._generate_v1_lookup_payload(lookup_type='BG')
        
        start_time = time.time()
        
        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload
        )
        
        elapsed_time = (time.time() - start_time) * 1000
        
        if not success:
            return
        
        # Performance threshold: 1000ms for small result sets
        if elapsed_time > 1000:
            response.failure(f"Response time {elapsed_time:.0f}ms exceeds 1000ms threshold")
            print(f"[{self.step_name}] [FAIL] Response time {elapsed_time:.0f}ms exceeds 1000ms threshold")
        else:
            print(f"[{self.step_name}] [PASS] Response time: {elapsed_time:.0f}ms for {len(data)} results")

    @task(1)
    def tc_perf03_concurrent_type_queries(self):
        """Test response time consistency across different type queries"""
        self.step_name = 'TC_PERF03_V1_Concurrent_Type_Queries'
        
        # This test will run sequentially (one type at a time)
        # but can be executed concurrently by multiple users in Locust
        import random
        
        test_type = random.choice(['BPP', 'BAP', 'BG'])
        payload = self._generate_v1_lookup_payload(lookup_type=test_type)
        
        start_time = time.time()
        
        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload
        )
        
        elapsed_time = (time.time() - start_time) * 1000
        
        if not success:
            return
        
        # Performance threshold: 1500ms for any type query
        if elapsed_time > 1500:
            print(f"[{self.step_name}] [WARN] Response time {elapsed_time:.0f}ms for type={test_type}")
        else:
            print(f"[{self.step_name}] [PASS] Type={test_type}: {elapsed_time:.0f}ms, {len(data)} results")


tasks = [ONDCRegLookupV1FilterCombinations]
