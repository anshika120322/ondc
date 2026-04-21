from locust import task
from tests.registry.lookup.common.base_lookup_test import RegistryLookupBase
from tests.utils.response_validators import LookupResponseValidator
import random
import json

"""
ONDC Registry Lookup API - Boundary & Edge Case Tests
Tests edge cases, boundary values, and security scenarios
Run with: --users 1 --iterations 10 (minimum 10 to ensure all 10 test cases execute once)
"""

class ONDCRegLookupBoundaryTests(RegistryLookupBase):

    config_file = 'resources/registry/lookup/v3/test_lookup_functional.yml'
    tenant_name = 'ondcRegistry'

    def on_start(self):
        """Initialize test - V3 lookup with registered participant credentials"""
        super().on_start()
        print(f"\n[INFO] ✅ Boundary Tests initialized for: {self.participant_id}")

    def _validate_error_code_range(self, error_code, min_code=15000, max_code=19999):
        """
        Validate that error code is within ONDC Registry range (15000-19999).
        
        Args:
            error_code: Error code to validate (can be string or int)
            min_code: Minimum valid error code (default: 15000)
            max_code: Maximum valid error code (default: 19999)
        
        Returns:
            bool: True if error code is in valid range, False otherwise
        """
        try:
            code_int = int(error_code)
            return min_code <= code_int <= max_code
        except (ValueError, TypeError):
            return False

    # ------------------------------------------------------------
    # TC_Boundary_01: max_results=0
    # Expected: Empty array (200) OR validation error (400)
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_01_max_results_zero(self):
        """Test max_results=0 (should return empty array or reject)"""
        self.step_name = 'TC_Boundary_01_Max_Results_Zero'
        
        payload = self._generate_v3_lookup_payload(max_results=0)
        
        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload,
            expected_status=[200, 400]
        )
        
        if status == 200:
            # Should return empty array
            if not isinstance(data, list):
                return response.failure(f"Expected list, got {type(data)}")
            
            if len(data) != 0:
                return response.failure(
                    f"max_results=0 should return empty array, got {len(data)} items"
                )
            
            response.success()
            print(f"[{self.step_name}] [PASS] max_results=0 returned empty array")
            
        elif status == 400:
            # Server rejects with validation error - also valid
            error_code = data.get("error", {}).get("code") if isinstance(data, dict) else None
            
            # Validate error code is in ONDC Registry range
            if not self._validate_error_code_range(error_code):
                response.failure(
                    f"Error code {error_code} not in valid ONDC Registry range (15000-19999)"
                )
                print(f"[{self.step_name}] [FAIL] Invalid error code: {error_code}")
                return
            
            if error_code in [1050, "1050", "15050", "15055"]:
                response.success()
                print(f"[{self.step_name}] [PASS] Server rejected max_results=0 with error {error_code}")
            else:
                response.failure(
                    f"Expected error code 1050/15050/15055 for invalid max_results, got {error_code}"
                )
        else:
            response.failure(f"Unexpected status {status}, expected 200 or 400")

    # ------------------------------------------------------------
    # TC_Boundary_02: max_results=-1 (negative)
    # Expected: 400 with error code 1050
    # ------------------------------------------------------------
    # TC_Boundary_02: max_results=-1 (negative)
    # Expected: 400 or 416 with error code 1050
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_02_max_results_negative(self):
        """Test max_results=-1 (should be rejected)"""
        self.step_name = 'TC_Boundary_02_Max_Results_Negative'
        
        payload = self._generate_v3_lookup_payload(max_results=-1)
        
        # Generate headers with signature
        headers = self._generate_v3_headers(payload)
        serialized_body = headers.pop('serialized_body', None)
        if not serialized_body:
            import json
            serialized_body = json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
        
        # Send request directly to properly handle error response
        with self.client.post(
                name=self.step_name,
                url="/v3.0/lookup",
                data=serialized_body,
                headers=headers,
                catch_response=True
        ) as response:
            
            # Accept both 400 (Bad Request) and 416 (Range Not Satisfiable)
            if response.status_code in [400, 416]:
                try:
                    data = response.json()
                    error_code = str(data.get("error", {}).get("code"))
                    
                    # Validate error code is in ONDC Registry range
                    if not self._validate_error_code_range(error_code):
                        response.failure(
                            f"Error code {error_code} not in valid ONDC Registry range (15000-19999)"
                        )
                        print(f"[{self.step_name}] [FAIL] Invalid error code: {error_code}")
                        return
                    
                    # Accept ONDC Registry validation error codes (15050-15059)
                    if error_code in ["1050", "15050", "15055"]:
                        response.success()  # Mark as SUCCESS since we expected this error
                        print(f"[{self.step_name}] [PASS] Negative max_results rejected with status {response.status_code}, error {error_code}")
                    else:
                        response.failure(f"Expected error code 1050/15050/15055, got {error_code}")
                        print(f"[{self.step_name}] [FAIL] Wrong error code: {error_code}")
                except Exception as e:
                    response.failure(f"Failed to parse response: {e}")
            else:
                response.failure(f"Expected status 400 or 416, got {response.status_code}")
                print(f"[{self.step_name}] [FAIL] Expected 400/416, got {response.status_code}")
    # ------------------------------------------------------------
    # TC_Boundary_03: max_results=999999 (extreme value)
    # Expected: Capped at server limit (200) OR rejected (400)
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_03_max_results_extreme(self):
        """Test max_results=999999 (should be limited or rejected)"""
        self.step_name = 'TC_Boundary_03_Max_Results_Extreme'
        
        payload = self._generate_v3_lookup_payload(max_results=999999)
        
        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload,
            expected_status=[200, 400]
        )
        
        if status == 200:
            # Should be capped at server maximum (typically 1000)
            if not isinstance(data, list):
                return response.failure(f"Expected list, got {type(data)}")
            
            if len(data) > 10000:  # Reasonable upper limit
                return response.failure(
                    f"Excessive results returned: {len(data)}. "
                    f"Server should cap at reasonable limit"
                )
            
            response.success()
            print(
                f"[{self.step_name}] [PASS] Extreme max_results capped at {len(data)} items"
            )
            
        elif status == 400:
            # Server rejects as invalid
            error_code = data.get("error", {}).get("code") if isinstance(data, dict) else None
            
            # Validate error code is in ONDC Registry range
            if not self._validate_error_code_range(error_code):
                response.failure(
                    f"Error code {error_code} not in valid ONDC Registry range (15000-19999)"
                )
                print(f"[{self.step_name}] [FAIL] Invalid error code: {error_code}")
                return
            
            if error_code in [1050, "1050", "15050", "15055"]:
                response.success()
                print(f"[{self.step_name}] [PASS] Server rejected extreme max_results with error {error_code}")
            else:
                response.failure(f"Unexpected error code: {error_code}")
        else:
            response.failure(f"Unexpected status {status}")

    # ------------------------------------------------------------
    # TC_Boundary_04: Very long city array (100+ cities)
    # Expected: 200 (handles large arrays) OR 400 (rejects as too large)
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_04_very_long_city_array(self):
        """Test with 100+ cities in filter (stress test)"""
        self.step_name = 'TC_Boundary_04_Very_Long_City_Array'
        
        # Generate 100 city codes
        cities = [f"std:{100+i:03d}" for i in range(100)]
        
        payload = self._generate_v3_lookup_payload(city=cities)
        
        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload,
            expected_status=[200, 400, 413]  # 413 = Payload Too Large
        )
        
        if status == 200:
            # Server accepted and processed
            if not isinstance(data, list):
                return response.failure(f"Expected list, got {type(data)}")
            
            response.success()
            print(
                f"[{self.step_name}] [PASS] Server handled 100 cities, "
                f"returned {len(data)} participants"
            )
            
        elif status in [400, 413]:
            # Server rejected as too large
            response.success()
            print(f"[{self.step_name}] [PASS] Server rejected large city array with {status}")
        else:
            response.failure(f"Unexpected status {status}")

    # ------------------------------------------------------------
    # TC_Boundary_05: Empty string in filter
    # Expected: 400 with validation error
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_05_empty_string_in_filter(self):
        """Test domain filter with empty string (should be rejected)"""
        self.step_name = 'TC_Boundary_05_Empty_String_Filter'
        
        # Empty string in domain array
        payload = self._generate_v3_lookup_payload(domain=[""])
        
        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload,
            expected_status=[400]
        )
        
        if status == 400:
            response.success()
            print(f"[{self.step_name}] [PASS] Empty string in filter rejected correctly")
        else:
            response.failure(
                f"Empty string should be rejected with 400, got {status}"
            )

    # ------------------------------------------------------------
    # TC_Boundary_06: Duplicate domains in array
    # Expected: 200 (deduplicates) OR 400 (rejects duplicates)
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_06_duplicate_domains(self):
        """Test with duplicate domains in array"""
        self.step_name = 'TC_Boundary_06_Duplicate_Domains'
        
        # Same domain three times + one different
        payload = self._generate_v3_lookup_payload(
            domain=['ONDC:RET10', 'ONDC:RET10', 'ONDC:RET10', 'ONDC:RET11']
        )
        
        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload,
            expected_status=[200, 400]
        )
        
        if status == 200:
            # Server accepted (likely deduplicated)
            if not isinstance(data, list):
                return response.failure(f"Expected list, got {type(data)}")
            
            response.success()
            print(
                f"[{self.step_name}] [PASS] Server accepted duplicate domains "
                f"(likely deduplicated)"
            )
            
        elif status == 400:
            # Server rejected duplicates
            response.success()
            print(f"[{self.step_name}] [PASS] Server rejected duplicate domains")
        else:
            response.failure(f"Unexpected status {status}")

    # ------------------------------------------------------------
    # TC_Boundary_07: Special characters & Security Tests
    # Expected: 400 or 404 (reject malicious input)
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_07_special_characters_security(self):
        """Test participant_id with special characters (security)"""
        self.step_name = 'TC_Boundary_07_Special_Chars_Security'
        
        # Test various security attack vectors
        test_cases = [
            ("SQL Injection", "test';DROP TABLE participants;--"),
            ("XSS Attack", "<script>alert('xss')</script>.com"),
            ("Path Traversal", "test/../../../etc/passwd"),
            ("Null Byte", "test\x00null.com"),
            ("Command Injection", "test; rm -rf /"),
        ]
        
        all_passed = True
        
        for attack_name, malicious_input in test_cases:
            payload = self._generate_v3_lookup_payload(participant_id=malicious_input)
            
            success, data, status, response = self._send_v3_lookup_request(
                f"{self.step_name}_{attack_name.replace(' ', '_')}",
                payload,
                expected_status=[200, 400, 404]
            )
            
            # Should be rejected (400), not found (404), or return empty (200 with error)
            # Accept 200 with error code 15045 (no matching participant) - means input was sanitized
            if status == 200:
                if isinstance(data, dict) and 'error' in data:
                    error_code = data.get('error', {}).get('code')
                    
                    # Validate error code is in ONDC Registry range
                    if not self._validate_error_code_range(error_code):
                        all_passed = False
                        print(
                            f"[{self.step_name}] [FAIL] Error code {error_code} "
                            f"not in valid ONDC Registry range (15000-19999)"
                        )
                        break
                    
                    if error_code in ['15045', 15045]:
                        # Sanitized and searched, no match - this is acceptable
                        pass
                    else:
                        all_passed = False
                        print(
                            f"[{self.step_name}] [FAIL] Unexpected error code: {error_code}"
                        )
                        break
                elif isinstance(data, list) and len(data) == 0:
                    # Empty results - acceptable
                    pass
                else:
                    all_passed = False
                    print(
                        f"[{self.step_name}] [FAIL] Security issue: "
                        f"{attack_name} returned data with status {status}"
                    )
                    break
            elif status not in [400, 404]:
                all_passed = False
                print(
                    f"[{self.step_name}] [FAIL] Security issue: "
                    f"{attack_name} accepted with status {status}"
                )
                break
        
        if all_passed:
            response.success()
            print(
                f"[{self.step_name}] [PASS] All security attack vectors handled correctly"
            )
        else:
            response.failure("Security vulnerability detected - malicious input returned data")

    # ------------------------------------------------------------
    # TC_Boundary_08: Unicode characters in city filter
    # Expected: 200 (handles Unicode) OR 400 (rejects non-ASCII)
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_08_unicode_in_city(self):
        """Test city filter with Unicode characters"""
        self.step_name = 'TC_Boundary_08_Unicode_City'
        
        # Mix of ASCII and Unicode city codes
        payload = self._generate_v3_lookup_payload(
            city=["std:080", "std:मुंबई", "std:北京", "std:café"]
        )
        
        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload,
            expected_status=[200, 400]
        )
        
        if status == 200:
            # Server accepted and handled Unicode
            if not isinstance(data, list):
                return response.failure(f"Expected list, got {type(data)}")
            
            response.success()
            print(f"[{self.step_name}] [PASS] Server handled Unicode in city filter")
            
        elif status == 400:
            # Server rejected non-ASCII characters
            response.success()
            print(f"[{self.step_name}] [PASS] Server rejected Unicode characters (ASCII-only)")
        else:
            response.failure(f"Unexpected status {status}")

    # ------------------------------------------------------------
    # TC_Boundary_09: Null values in optional fields
    # Expected: Handled gracefully
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_09_null_in_optional_fields(self):
        """Test payload with explicit null values"""
        self.step_name = 'TC_Boundary_09_Null_Optional_Fields'
        
        # Create payload with explicit null values for optional fields
        payload = self._generate_v3_lookup_payload()
        payload['select_keys'] = None
        payload['include_sections'] = None
        payload['max_results'] = None
        
        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload,
            expected_status=[200, 400]
        )
        
        if status in [200, 400]:
            response.success()
            print(f"[{self.step_name}] [PASS] Null values handled with status {status}")
        else:
            response.failure(f"Unexpected status {status}")

    # ------------------------------------------------------------
    # TC_Boundary_10: Conflicting filters
    # Expected: 400 OR empty result (no matches)
    # ------------------------------------------------------------
    @task(1)
    def tc_boundary_10_conflicting_filters(self):
        """Test conflicting filter values"""
        self.step_name = 'TC_Boundary_10_Conflicting_Filters'
        
        # Create payload that's logically impossible
        payload = self._generate_v3_lookup_payload()
        
        # Set conflicting type values via custom payload construction
        # Note: Standard payload generator won't allow this, so we construct manually
        payload['type'] = 'BPP'  # Set first type
        
        # Then try to add conflicting data (this tests API's handling of impossible queries)
        # In reality, we can't send type=BPP AND type=BAP in same request
        # But we can test other conflicts like participant_id + too specific filters
        
        # Test: Request specific participant but filter by domain they don't have
        payload['participant_id'] = self.participant_id  # Our test participant
        payload['domain'] = ['ONDC:MOBILITY']  # Unlikely domain for our participant
        
        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload,
            expected_status=[200, 400]
        )
        
        if status == 200:
            # Should return empty array (no matches) or the participant (ignoring domain)
            if not isinstance(data, list):
                return response.failure(f"Expected list, got {type(data)}")
            
            response.success()
            print(
                f"[{self.step_name}] [PASS] Conflicting filters handled, "
                f"returned {len(data)} items"
            )
            
        elif status == 400:
            # Server detected and rejected conflict
            response.success()
            print(f"[{self.step_name}] [PASS] Server rejected conflicting filters")
        else:
            response.failure(f"Unexpected status {status}")


tasks = [ONDCRegLookupBoundaryTests]

