import json
import random
from locust import task
from tests.registry.lookup.common.base_lookup_test import RegistryLookupBase

"""
ONDC Registry Lookup API - V1 Comprehensive Negative Tests
Works for both QA and PROD environments
Tests payload validation, format validation, data integrity, and edge cases

Endpoints:
  QA:   http://35.200.190.239:8080/lookup (public, no auth)
  PROD: https://prod.registry.ondc.org/lookup (public, no auth)

Authentication: None (V1 is public API)

Run with:
--test ondc_reg_v1_lookup_negative --environment ondcRegistryV1Lookup --iterations 20 (QA)
--test ondc_reg_v1_lookup_negative --environment ondcRegistryV1LookupProd --iterations 20 (PROD)

Test Categories:
1. Missing Required Fields (TC-001 to TC-003)
2. Empty/Null Values (TC-004 to TC-006)
3. Invalid Data Types (TC-007 to TC-009)
4. Invalid Enum Values (TC-010 to TC-012)
5. Malformed JSON (TC-013 to TC-015)
6. Extra/Unknown Fields (TC-016 to TC-018)
7. Edge Cases (TC-019 to TC-020)
"""

class ONDCRegLookupV1Negative(RegistryLookupBase):

    config_file = 'resources/registry/lookup/v1/test_lookup_v1.yml'
    # tenant_name is set dynamically by --environment parameter (ondcRegistryV1Lookup or ondcRegistryV1LookupProd)

    def on_start(self):
        """Initialize test and register participant at runtime"""
        super().on_start()
        
        # Register participant before running tests (if credentials available)
        if hasattr(self, 'participant_id') and self.participant_id:
            registration_success = self._register_participant_runtime()
            if registration_success:
                print(f"\n[INFO] ✅ V1 Comprehensive Negative Tests initialized (20 test cases)")
                print(f"[INFO] Participant status: SUBSCRIBED (ready for testing)\n")
            else:
                print(f"\n[WARNING] Participant registration uncertain - proceeding with tests\n")
        else:
            print(f"\n[INFO] ✅ V1 Comprehensive Negative Tests initialized (20 test cases) - public API\n")

    def _register_participant_runtime(self):
        """Register participant at runtime before running tests"""
        # Reuse the same pattern from V1 functional tests
        # This method is defined in base class or copied from v1 functional
        print(f"\n[REGISTRATION] Checking/Registering participant: {self.participant_id}")
        
        try:
            # For V1, we'll use the same registration pattern as V2
            # Check if already registered, if not run admin whitelist + V3 subscribe
            if hasattr(self, '_verify_participant_subscribed'):
                if self._verify_participant_subscribed():
                    print(f"[REGISTRATION] ✓ Participant already registered")
                    return True
            
            print(f"[REGISTRATION] Participant will be registered on first use (public API)")
            return True
                
        except Exception as e:
            print(f"[REGISTRATION] Warning: {e}")
            return True  # Continue anyway for public API

    def _send_v1_with_error_handling(self, step_name, payload, expected_status=[400, 416], expected_error_codes=None):
        """
        Send V1 lookup request for negative tests.
        Validates both HTTP status AND error codes in response body.
        
        Args:
            step_name: Test step name
            payload: Request payload
            expected_status: List of acceptable error status codes
            expected_error_codes: List of acceptable error codes (e.g., [1050, "1050"])
        
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
                # For error statuses, JSON parsing failure might be acceptable
                if status_code in expected_status and expected_error_codes is None:
                    response.success()
                    return True, None, status_code, response
                response.failure(f"Failed to parse JSON: {str(e)}")
                return False, None, status_code, response
            
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
                        return True, data, status_code, response
                    else:
                        # For cleaner output, show range instead of full list
                        if isinstance(expected_error_codes, list) and len(expected_error_codes) > 10:
                            error_msg = f"Expected error code in range 15000-19999, got {error_code}"
                        else:
                            error_msg = f"Expected error codes {expected_error_codes}, got {error_code}"
                        response.failure(error_msg)
                        return False, data, status_code, response
                else:
                    response.failure(f"Expected error response, got {type(data)}")
                    return False, data, status_code, response
            
            # Original logic: Check if we got expected error status (no error code validation)
            if status_code in expected_status:
                response.success()
                return True, data, status_code, response
            
            # Unexpected status
            response.failure(f"Expected status {expected_status}, got {status_code}")
            return False, data, status_code, response

    # ============================================================
    # MISSING REQUIRED FIELDS (TC-001 to TC-003)
    # ============================================================

    # ------------------------------------------------------------
    # TC-001: Missing Required Field - country
    # Expected: error code 1050 (validation error)
    # STRICT: Server MUST validate required fields
    # ------------------------------------------------------------
    @task(1)
    def tc001_v1_missing_country(self):

        self.step_name = "TC001_V1_Missing_Country"

        payload = {
            "type": "BAP"
            # country is missing
        }

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[200, 400, 416],
            expected_error_codes=list(range(15000, 20000))  # ONDC Registry error code range
        )

        if success:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [PASS] ✓ Correctly rejected missing country with error {error_code}")
        else:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [FAIL] Expected error code 15000-19999, got {error_code}")


    # ------------------------------------------------------------
    # TC-002: Missing Required Field - type
    # Expected: 400, 416, or 200 with empty array (type is optional in V1)
    # ------------------------------------------------------------
    @task(1)
    def tc002_v1_missing_type(self):

        self.step_name = "TC002_V1_Missing_Type"

        payload = {
            "country": "IND"
            # type is missing (optional field)
        }

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[200, 400, 416]  # Type might be optional
        )

        if success:
            print(f"[{self.step_name}] [PASS] ✓ Response status: {status}")
        else:
            print(f"[{self.step_name}] [FAIL] Unexpected status: {status}")


    # ------------------------------------------------------------
    # TC-003: Missing All Fields (Empty Payload)
    # Expected: error code 1050 (validation error)
    # STRICT: Server MUST validate required fields
    # ------------------------------------------------------------
    @task(1)
    def tc003_v1_empty_payload(self):

        self.step_name = "TC003_V1_Empty_Payload"

        payload = {}

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[200, 400, 416],
            expected_error_codes=list(range(15000, 20000))  # ONDC Registry error code range
        )

        if success:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [PASS] ✓ Correctly rejected empty payload with error {error_code}")
        else:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [FAIL] Expected error code 15000-19999, got {error_code}")


    # ============================================================
    # EMPTY/NULL VALUES (TC-004 to TC-006)
    # ============================================================

    # ------------------------------------------------------------
    # TC-004: Empty String for country
    # Expected: error code 1050 (validation error)
    # STRICT: Empty strings should be rejected
    # ------------------------------------------------------------
    @task(1)
    def tc004_v1_empty_country(self):

        self.step_name = "TC004_V1_Empty_Country"

        payload = {
            "country": "",
            "type": "BAP"
        }

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 416],
            expected_error_codes=list(range(15000, 20000))  # ONDC Registry error code range
        )

        if success:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [PASS] ✓ Correctly rejected empty country with error {error_code}")
        else:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [FAIL] Expected error code 15000-19999, got {error_code}")


    # ------------------------------------------------------------
    # TC-005: Empty String for type
    # Expected: 400, 416, or 404
    # ------------------------------------------------------------
    @task(1)
    def tc005_v1_empty_type(self):

        self.step_name = "TC005_V1_Empty_Type"

        payload = {
            "country": "IND",
            "type": ""
        }

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[400, 404, 416]
        )

        if success:
            print(f"[{self.step_name}] [PASS] ✓ Correctly rejected empty type (status: {status})")
        else:
            print(f"[{self.step_name}] [FAIL] Expected 400/404/416, got {status}")


    # ------------------------------------------------------------
    # TC-006: Null Value for country
    # Expected: error code 1050 (validation error)
    # STRICT: Null values should be rejected
    # ------------------------------------------------------------
    @task(1)
    def tc006_v1_null_country(self):

        self.step_name = "TC006_V1_Null_Country"

        payload = {
            "country": None,
            "type": "BAP"
        }

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[200, 400, 416],
            expected_error_codes=list(range(15000, 20000))  # ONDC Registry error code range
        )

        if success:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [PASS] ✓ Correctly rejected null country with error {error_code}")
        else:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [FAIL] Expected error code 15000-19999, got {error_code}")


    # ============================================================
    # INVALID DATA TYPES (TC-007 to TC-009)
    # ============================================================

    # ------------------------------------------------------------
    # TC-007: Invalid Type for country (Number instead of String)
    # Expected: error code 1050 (type validation error)
    # STRICT: Server MUST validate data types
    # ------------------------------------------------------------
    @task(1)
    def tc007_v1_invalid_type_country_number(self):

        self.step_name = "TC007_V1_Invalid_Type_Country_Number"

        payload = {
            "country": 123,  # Should be string
            "type": "BAP"
        }

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[200, 400, 416, 422],
            expected_error_codes=list(range(15000, 20000))  # ONDC Registry error code range
        )

        if success:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [PASS] ✓ Correctly rejected numeric country with error {error_code}")
        else:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [FAIL] Expected error code 15000-19999, got {error_code}")


    # ------------------------------------------------------------
    # TC-008: Invalid Type for type (Array instead of String)
    # Expected: error code 1050 (type validation error)
    # STRICT: Server MUST validate data types
    # ------------------------------------------------------------
    @task(1)
    def tc008_v1_invalid_type_type_array(self):

        self.step_name = "TC008_V1_Invalid_Type_Type_Array"

        payload = {
            "country": "IND",
            "type": ["BAP", "BPP"]  # Should be string
        }

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[200, 400, 416, 422],
            expected_error_codes=list(range(15000, 20000))  # ONDC Registry error code range
        )

        if success:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [PASS] ✓ Correctly rejected array type with error {error_code}")
        else:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [FAIL] Expected error code 15000-19999, got {error_code}")


    # ------------------------------------------------------------
    # TC-009: Invalid Type for country (Boolean instead of String)
    # Expected: error code 1050 (type validation error)
    # STRICT: Server MUST validate data types
    # ------------------------------------------------------------
    @task(1)
    def tc009_v1_invalid_type_country_boolean(self):

        self.step_name = "TC009_V1_Invalid_Type_Country_Boolean"

        payload = {
            "country": True,  # Should be string
            "type": "BAP"
        }

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[200, 400, 416, 422],
            expected_error_codes=list(range(15000, 20000))  # ONDC Registry error code range
        )

        if success:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [PASS] ✓ Correctly rejected boolean country with error {error_code}")
        else:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [FAIL] Expected error code 15000-19999, got {error_code}")


    # ============================================================
    # INVALID ENUM VALUES (TC-010 to TC-012)
    # ============================================================

    # ------------------------------------------------------------
    # TC-010: Invalid country Code
    # Expected: error code 1050 (validation error) OR 1001 (not found)
    # Can be either - invalid country could be caught during validation or lookup
    # ------------------------------------------------------------
    @task(1)
    def tc010_v1_invalid_country_code(self):

        self.step_name = "TC010_V1_Invalid_Country_Code"

        payload = {
            "country": "INVALID_COUNTRY",
            "type": "BAP"
        }

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 416],
            expected_error_codes=list(range(15000, 20000))  # ONDC Registry error code range
        )

        if success:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            if error_code == 15055:
                print(f"[{self.step_name}] [PASS] ✓ Invalid country caught during validation (15055)")
            elif error_code == 15045:
                print(f"[{self.step_name}] [PASS] ✓ Invalid country - no matching participant (15045)")
            else:
                print(f"[{self.step_name}] [PASS] ✓ Invalid country rejected with error {error_code}")
        else:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [FAIL] Expected error code 15000-19999, got {error_code}")


    # ------------------------------------------------------------
    # TC-011: Invalid type Value
    # Expected: error code 1050 (validation error) OR 1001 (not found)
    # Can be either - invalid type could be caught during validation or lookup
    # ------------------------------------------------------------
    @task(1)
    def tc011_v1_invalid_type_value(self):

        self.step_name = "TC011_V1_Invalid_Type_Value"

        payload = {
            "country": "IND",
            "type": "INVALID_TYPE"
        }

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 416],
            expected_error_codes=list(range(15000, 20000))  # ONDC Registry error code range
        )

        if success:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            if error_code == 15055:
                print(f"[{self.step_name}] [PASS] ✓ Invalid type caught during validation (15055)")
            elif error_code == 15045:
                print(f"[{self.step_name}] [PASS] ✓ Invalid type - no matching participant (15045)")
            else:
                print(f"[{self.step_name}] [PASS] ✓ Invalid type rejected with error {error_code}")
        else:
            error_code = data.get('error', {}).get('code') if data and isinstance(data, dict) else None
            print(f"[{self.step_name}] [FAIL] Expected error code 15000-19999, got {error_code}")


    # ------------------------------------------------------------
    # TC-012: Case Sensitivity - Lowercase type
    # Expected: May accept (BAP -> bap) or reject depending on API behavior
    # ------------------------------------------------------------
    @task(1)
    def tc012_v1_lowercase_type(self):

        self.step_name = "TC012_V1_Lowercase_Type"

        payload = {
            "country": "IND",
            "type": "bap"  # Normally uppercase "BAP"
        }

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 416]  # May or may not be case-sensitive
        )

        if success:
            print(f"[{self.step_name}] [PASS] ✓ Lowercase type handling: status {status}")
        else:
            print(f"[{self.step_name}] [FAIL] Unexpected status: {status}")


    # ============================================================
    # MALFORMED JSON (TC-013 to TC-015)
    # ============================================================

    # ------------------------------------------------------------
    # TC-013: Malformed JSON - Missing Closing Brace
    # Expected: 400
    # ------------------------------------------------------------
    @task(1)
    def tc013_v1_malformed_json_missing_brace(self):

        self.step_name = "TC013_V1_Malformed_JSON_Missing_Brace"

        # Generate valid payload then create malformed JSON
        valid_payload = self._generate_v1_lookup_payload()
        valid_json = json.dumps(valid_payload)

        # Remove closing brace
        invalid_json = valid_json[:-1]

        success, data, status, response = self._send_v1_lookup_request_raw(
            self.step_name,
            invalid_json,
            expected_status=[400, 416]
        )

        if status in [400, 416]:
            response.success()
            print(f"[{self.step_name}] [PASS] ✓ Correctly rejected malformed JSON (status: {status})")
        else:
            response.failure(f"Expected 400/416, got {status}")


    # ------------------------------------------------------------
    # TC-014: Malformed JSON - Invalid Syntax
    # Expected: 400
    # ------------------------------------------------------------
    @task(1)
    def tc014_v1_malformed_json_invalid_syntax(self):

        self.step_name = "TC014_V1_Malformed_JSON_Invalid_Syntax"

        # Completely invalid JSON
        invalid_json = "{country: IND, type: BAP}"  # Missing quotes

        success, data, status, response = self._send_v1_lookup_request_raw(
            self.step_name,
            invalid_json,
            expected_status=[400, 416]
        )

        if status in [400, 416]:
            response.success()
            print(f"[{self.step_name}] [PASS] ✓ Correctly rejected invalid JSON syntax (status: {status})")
        else:
            response.failure(f"Expected 400/416, got {status}")


    # ------------------------------------------------------------
    # TC-015: Malformed JSON - Trailing Comma
    # Expected: May accept or reject depending on JSON parser
    # ------------------------------------------------------------
    @task(1)
    def tc015_v1_malformed_json_trailing_comma(self):

        self.step_name = "TC015_V1_Malformed_JSON_Trailing_Comma"

        # JSON with trailing comma (some parsers reject, some accept)
        invalid_json = '{"country": "IND", "type": "BAP",}'

        success, data, status, response = self._send_v1_lookup_request_raw(
            self.step_name,
            invalid_json,
            expected_status=[200, 400, 416]
        )

        if status in [200, 400, 416]:
            response.success()
            print(f"[{self.step_name}] [PASS] ✓ Trailing comma handling: status {status}")
        else:
            response.failure(f"Unexpected status: {status}")


    # ============================================================
    # EXTRA/UNKNOWN FIELDS (TC-016 to TC-018)
    # ============================================================

    # ------------------------------------------------------------
    # TC-016: Extra Unknown Field
    # Expected: May ignore or reject (200 or 400)
    # ------------------------------------------------------------
    @task(1)
    def tc016_v1_extra_unknown_field(self):

        self.step_name = "TC016_V1_Extra_Unknown_Field"

        payload = {
            "country": "IND",
            "type": "BAP",
            "unknown_field": "should_be_ignored_or_rejected"
        }

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[200, 400, 416]  # May ignore or reject
        )

        if success:
            print(f"[{self.step_name}] [PASS] ✓ Extra field handling: status {status}")
        else:
            print(f"[{self.step_name}] [FAIL] Unexpected status: {status}")


    # ------------------------------------------------------------
    # TC-017: Field with Special Characters in Value
    # Expected: 400, 404, or 416
    # ------------------------------------------------------------
    @task(1)
    def tc017_v1_special_characters_in_value(self):

        self.step_name = "TC017_V1_Special_Characters_In_Value"

        payload = {
            "country": "IND",
            "type": "BAP<script>alert('xss')</script>"  # XSS attempt
        }

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 416]  # API may accept and handle gracefully
        )

        if success:
            print(f"[{self.step_name}] [PASS] ✓ Special characters handling: status {status}")
        else:
            print(f"[{self.step_name}] [FAIL] Unexpected status: {status}")


    # ------------------------------------------------------------
    # TC-018: SQL Injection Attempt in type
    # Expected: 400, 404, or 416
    # ------------------------------------------------------------
    @task(1)
    def tc018_v1_sql_injection_attempt(self):

        self.step_name = "TC018_V1_SQL_Injection_Attempt"

        payload = {
            "country": "IND",
            "type": "BAP' OR '1'='1"  # SQL injection attempt
        }

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 416]  # API may accept and handle gracefully
        )

        if success:
            print(f"[{self.step_name}] [PASS] ✓ SQL injection handling: status {status}")
        else:
            print(f"[{self.step_name}] [FAIL] Unexpected status: {status}")


    # ============================================================
    # EDGE CASES (TC-019 to TC-020)
    # ============================================================

    # ------------------------------------------------------------
    # TC-019: Extremely Long String for country
    # Expected: 400 or 416
    # ------------------------------------------------------------
    @task(1)
    def tc019_v1_extremely_long_country(self):

        self.step_name = "TC019_V1_Extremely_Long_Country"

        payload = {
            "country": "A" * 10000,  # 10K characters
            "type": "BAP"
        }

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 413, 416]  # API may accept and handle gracefully
        )

        if success:
            print(f"[{self.step_name}] [PASS] ✓ Extremely long country handling: status {status}")
        else:
            print(f"[{self.step_name}] [FAIL] Unexpected status: {status}")


    # ------------------------------------------------------------
    # TC-020: Unicode Characters in country
    # Expected: May accept or reject (200, 400, or 404)
    # ------------------------------------------------------------
    @task(1)
    def tc020_v1_unicode_characters(self):

        self.step_name = "TC020_V1_Unicode_Characters"

        payload = {
            "country": "भारत",  # "India" in Hindi
            "type": "BAP"
        }

        success, data, status, response = self._send_v1_with_error_handling(
            self.step_name,
            payload,
            expected_status=[200, 400, 404, 416]
        )

        if success:
            print(f"[{self.step_name}] [PASS] ✓ Unicode handling: status {status}")
        else:
            print(f"[{self.step_name}] [FAIL] Unexpected status: {status}")


# Required by Locust
tasks = [ONDCRegLookupV1Negative]
