from locust import task
from tests.registry.lookup.common.base_lookup_test import RegistryLookupBase
from tests.utils.response_validators import LookupResponseValidator
import json

"""
ONDC Registry API Version Comparison Tests
Validates the differences between V1, V2, and V3 according to specifications:

Expected Differences:
1. V1 & V2 should be EXACTLY same except authentication
   - V1: No authentication (public API)
   - V2: ED25519 signature authentication (same as V3)

2. Encryption Key Field:
   - V1/V2: encr_public_key
   - V3: encryption_public_key

3. Participant Identifier:
   - V1/V2: subscriber_id
   - V3: participant_id (in addition to subscriber_id)

4. Additional Fields:
   - V1/V2: subscriber_url, br_id, ukId at root level
   - V3: subscriber_url in uris structure, ukId in keys structure, br_id omitted

Run with:
python driver.py --test ondc_reg_version_comparison --environment ondcRegistry --iterations 1 -u 1
"""

class ONDCRegVersionComparison(RegistryLookupBase):

    config_file = 'resources/registry/lookup/common/test_version_comparison.yml'
    tenant_name = 'ondcRegistry'

    def on_start(self):
        """Initialize test"""
        super().on_start()
        print(f"\n[INFO] API Version Comparison Tests - Participant: {self.participant_id}\n")

    # ============================================================
    # V1 vs V2 COMPARISON TESTS
    # ============================================================

    @task(1)
    def tc_v1_v2_01_authentication_difference_only(self):
        """
        Validate V1 & V2 are same except authentication.
        V1: No auth (public API)
        V2: ED25519 signature auth
        """
        self.step_name = 'TC_V1_V2_01_Authentication_Difference'
        
        # Test V1 (no auth)
        v1_payload = self._generate_v1_lookup_payload()
        v1_success, v1_data, v1_status, v1_response = self._send_v1_lookup_request(
            "V1_Lookup",
            v1_payload,
            expected_status=[200]
        )
        
        # Test V2 (with auth)
        v2_payload = self._generate_v2_lookup_payload(
            country=v1_payload.get('country'),
            lookup_type=v1_payload.get('type')
        )
        v2_success, v2_data, v2_status, v2_response = self._send_v2_lookup_request(
            "V2_Lookup",
            v2_payload,
            expected_status=[200]
        )
        
        # Both should return data
        if v1_status != 200 or not isinstance(v1_data, list):
            v1_response.failure("V1 request failed")
            return
        
        if v2_status != 200 or not isinstance(v2_data, list):
            v2_response.failure("V2 request failed")
            return
        
        # If both have data, compare schema structure
        if len(v1_data) > 0 and len(v2_data) > 0:
            v1_sample = v1_data[0]
            v2_sample = v2_data[0]
            
            # Compare field existence (ignoring values)
            v1_fields = set(v1_sample.keys())
            v2_fields = set(v2_sample.keys())
            
            differences = v1_fields.symmetric_difference(v2_fields)
            
            if differences:
                v1_response.failure(f"V1 and V2 response structure differs: {differences}")
                v2_response.failure(f"V1 and V2 response structure differs: {differences}")
                print(f"[{self.step_name}] [FAIL] V1/V2 structure mismatch: {differences}")
            else:
                v1_response.success()
                v2_response.success()
                print(f"[{self.step_name}] [PASS] ✓ V1 and V2 have identical response structure (only auth differs)")
        else:
            v1_response.success()
            v2_response.success()
            print(f"[{self.step_name}] [INFO] Insufficient data to compare")

    @task(1)
    def tc_v1_v2_02_same_encryption_key_field(self):
        """Validate V1 & V2 both use 'encr_public_key'"""
        self.step_name = 'TC_V1_V2_02_Same_Encryption_Key'
        
        # Test V2 (V1 would be same)
        v2_payload = self._generate_v2_lookup_payload()
        success, data, status, response = self._send_v2_lookup_request(
            self.step_name,
            v2_payload,
            expected_status=[200]
        )
        
        if status != 200 or not isinstance(data, list) or len(data) == 0:
            response.success()  # No data to validate
            return
        
        sample = data[0]
        keys = sample.get('keys', [])
        
        if not keys or len(keys) == 0:
            response.failure("No keys array found")
            return
        
        key_obj = keys[0]
        has_encr_key = 'encr_public_key' in key_obj
        has_encryption_key = 'encryption_public_key' in key_obj  # V3 field
        
        if has_encr_key and not has_encryption_key:
            response.success()
            print(f"[{self.step_name}] [PASS] ✓ V1/V2 correctly use 'encr_public_key'")
        elif has_encryption_key:
            response.failure("Found V3 field 'encryption_public_key' in V1/V2 response")
        else:
            response.failure("Missing encryption key field")

    # ============================================================
    # V2 vs V3 COMPARISON TESTS
    # ============================================================

    @task(1)
    def tc_v2_v3_01_encryption_key_difference(self):
        """
        Validate encryption key field difference:
        V2: encr_public_key
        V3: encryption_public_key
        """
        self.step_name = 'TC_V2_V3_01_Encryption_Key_Difference'
        
        # Test V2
        v2_payload = self._generate_v2_lookup_payload()
        v2_success, v2_data, v2_status, v2_response = self._send_v2_lookup_request(
            "V2_Lookup",
            v2_payload,
            expected_status=[200]
        )
        
        # Test V3 with same filters
        v3_payload = self._generate_v3_lookup_payload(
            country=v2_payload.get('country'),
            lookup_type=v2_payload.get('type')
        )
        v3_success, v3_data, v3_status, v3_response = self._send_v3_lookup_request(
            "V3_Lookup",
            v3_payload,
            expected_status=[200]
        )
        
        # Validate V2 has encr_public_key
        v2_has_correct_field = False
        if v2_status == 200 and isinstance(v2_data, list) and len(v2_data) > 0:
            v2_keys = v2_data[0].get('keys', [])
            if v2_keys and len(v2_keys) > 0:
                v2_has_correct_field = 'encr_public_key' in v2_keys[0]
        
        # Validate V3 has encryption_public_key
        v3_has_correct_field = False
        if v3_status == 200 and isinstance(v3_data, list) and len(v3_data) > 0:
            v3_keys = v3_data[0].get('keys', [])
            if v3_keys and len(v3_keys) > 0:
                v3_has_correct_field = 'encryption_public_key' in v3_keys[0]
        
        if v2_has_correct_field and v3_has_correct_field:
            v2_response.success()
            v3_response.success()
            print(f"[{self.step_name}] [PASS] ✓ V2 uses 'encr_public_key', V3 uses 'encryption_public_key'")
        else:
            if not v2_has_correct_field:
                v2_response.failure("V2 missing 'encr_public_key'")
            if not v3_has_correct_field:
                v3_response.failure("V3 missing 'encryption_public_key'")

    @task(1)
    def tc_v2_v3_02_participant_id_difference(self):
        """
        Validate participant identifier:
        V2: subscriber_id only
        V3: participant_id (new field)
        """
        self.step_name = 'TC_V2_V3_02_Participant_ID_Difference'
        
        # Test V2
        v2_payload = self._generate_v2_lookup_payload()
        v2_success, v2_data, v2_status, v2_response = self._send_v2_lookup_request(
            "V2_Lookup",
            v2_payload,
            expected_status=[200]
        )
        
        # Test V3
        v3_payload = self._generate_v3_lookup_payload(
            country=v2_payload.get('country'),
            lookup_type=v2_payload.get('type')
        )
        v3_success, v3_data, v3_status, v3_response = self._send_v3_lookup_request(
            "V3_Lookup",
            v3_payload,
            expected_status=[200]
        )
        
        # Check V2: should NOT have participant_id
        v2_correct = False
        if v2_status == 200 and isinstance(v2_data, list) and len(v2_data) > 0:
            v2_sample = v2_data[0]
            v2_correct = 'participant_id' not in v2_sample and 'subscriber_id' in v2_sample
        
        # Check V3: should have participant_id
        v3_correct = False
        if v3_status == 200 and isinstance(v3_data, list) and len(v3_data) > 0:
            v3_sample = v3_data[0]
            v3_correct = 'participant_id' in v3_sample
        
        if v2_correct and v3_correct:
            v2_response.success()
            v3_response.success()
            print(f"[{self.step_name}] [PASS] ✓ V2 has subscriber_id only, V3 has participant_id")
        else:
            if not v2_correct:
                v2_response.failure("V2 has unexpected participant_id field")
            if not v3_correct:
                v3_response.failure("V3 missing participant_id field")

    @task(1)
    def tc_v2_v3_03_additional_fields_difference(self):
        """
        Validate additional fields:
        V2: subscriber_url, br_id, ukId at root level
        V3: subscriber_url in uris, ukId in keys, br_id omitted
        """
        self.step_name = 'TC_V2_V3_03_Additional_Fields_Difference'
        
        # Test V2
        v2_payload = self._generate_v2_lookup_payload()
        v2_success, v2_data, v2_status, v2_response = self._send_v2_lookup_request(
            "V2_Lookup",
            v2_payload,
            expected_status=[200]
        )
        
        # Test V3
        v3_payload = self._generate_v3_lookup_payload(
            country=v2_payload.get('country'),
            lookup_type=v2_payload.get('type')
        )
        v3_success, v3_data, v3_status, v3_response = self._send_v3_lookup_request(
            "V3_Lookup",
            v3_payload,
            expected_status=[200]
        )
        
        # Check V2: should have subscriber_url, br_id, ukId at root
        v2_correct = False
        if v2_status == 200 and isinstance(v2_data, list) and len(v2_data) > 0:
            v2_sample = v2_data[0]
            has_subscriber_url = 'subscriber_url' in v2_sample
            has_br_id = 'br_id' in v2_sample
            has_ukId = 'ukId' in v2_sample
            
            v2_correct = has_subscriber_url and has_br_id and has_ukId
            
            if not v2_correct:
                missing = []
                if not has_subscriber_url: missing.append('subscriber_url')
                if not has_br_id: missing.append('br_id')
                if not has_ukId: missing.append('ukId')
                print(f"[{self.step_name}] V2 missing fields at root: {missing}")
        
        # Check V3: should NOT have subscriber_url/br_id/ukId at root
        v3_correct = False
        if v3_status == 200 and isinstance(v3_data, list) and len(v3_data) > 0:
            v3_sample = v3_data[0]
            
            # V3 should NOT have these at root level
            has_subscriber_url_root = 'subscriber_url' in v3_sample
            has_br_id_root = 'br_id' in v3_sample
            has_ukId_root = 'ukId' in v3_sample
            
            # V3 should have uris structure with subscriber_url
            uris = v3_sample.get('uris', [])
            has_uris_structure = len(uris) > 0 if isinstance(uris, list) else False
            
            # V3 should have ukId in keys structure
            keys = v3_sample.get('keys', [])
            has_ukId_in_keys = False
            if keys and len(keys) > 0:
                has_ukId_in_keys = 'ukId' in keys[0]
            
            v3_correct = (
                not has_subscriber_url_root and 
                not has_br_id_root and  # br_id omitted in V3
                not has_ukId_root and
                has_uris_structure and
                has_ukId_in_keys
            )
            
            if not v3_correct:
                issues = []
                if has_subscriber_url_root: issues.append('subscriber_url at root (should be in uris)')
                if has_br_id_root: issues.append('br_id at root (should be omitted)')
                if has_ukId_root: issues.append('ukId at root (should be in keys)')
                if not has_uris_structure: issues.append('missing uris structure')
                if not has_ukId_in_keys: issues.append('ukId not in keys structure')
                print(f"[{self.step_name}] V3 issues: {issues}")
        
        if v2_correct and v3_correct:
            v2_response.success()
            v3_response.success()
            print(f"[{self.step_name}] [PASS] ✓ V2 has subscriber_url/br_id/ukId at root, V3 restructured correctly")
        else:
            if not v2_correct:
                v2_response.failure("V2 missing expected fields at root level")
            if not v3_correct:
                v3_response.failure("V3 structure incorrect (subscriber_url should be in uris, ukId in keys, br_id omitted)")

    # ============================================================
    # COMPREHENSIVE VERSION VALIDATION
    # ============================================================

    @task(1)
    def tc_comprehensive_01_all_version_differences(self):
        """
        Comprehensive test validating ALL differences between V1, V2, and V3
        """
        self.step_name = 'TC_COMPREHENSIVE_01_All_Version_Differences'
        
        # Fetch data from all three versions
        v1_payload = self._generate_v1_lookup_payload()
        v1_success, v1_data, v1_status, v1_response = self._send_v1_lookup_request(
            "V1_Lookup",
            v1_payload,
            expected_status=[200]
        )
        
        v2_payload = self._generate_v2_lookup_payload(
            country=v1_payload.get('country'),
            lookup_type=v1_payload.get('type')
        )
        v2_success, v2_data, v2_status, v2_response = self._send_v2_lookup_request(
            "V2_Lookup",
            v2_payload,
            expected_status=[200]
        )
        
        v3_payload = self._generate_v3_lookup_payload(
            country=v1_payload.get('country'),
            lookup_type=v1_payload.get('type')
        )
        v3_success, v3_data, v3_status, v3_response = self._send_v3_lookup_request(
            "V3_Lookup",
            v3_payload,
            expected_status=[200]
        )
        
        all_passed = True
        summary = []
        
        # Check if all returned data
        if not (v1_status == 200 and isinstance(v1_data, list) and len(v1_data) > 0):
            v1_response.success()
            v2_response.success()
            v3_response.success()
            print(f"[{self.step_name}] [INFO] Insufficient data for comparison")
            return
        
        if not (v2_status == 200 and isinstance(v2_data, list) and len(v2_data) > 0):
            v1_response.success()
            v2_response.success()
            v3_response.success()
            print(f"[{self.step_name}] [INFO] Insufficient V2 data for comparison")
            return
        
        if not (v3_status == 200 and isinstance(v3_data, list) and len(v3_data) > 0):
            v1_response.success()
            v2_response.success()
            v3_response.success()
            print(f"[{self.step_name}] [INFO] Insufficient V3 data for comparison")
            return
        
        v1_sample = v1_data[0]
        v2_sample = v2_data[0]
        v3_sample = v3_data[0]
        
        # 1. V1 vs V2: Should have identical structure
        v1_fields = set(v1_sample.keys())
        v2_fields = set(v2_sample.keys())
        if v1_fields == v2_fields:
            summary.append("✓ V1 and V2 have identical structure")
        else:
            all_passed = False
            summary.append(f"✗ V1/V2 structure differs: {v1_fields.symmetric_difference(v2_fields)}")
        
        # 2. Encryption key field names
        v1_keys = v1_sample.get('keys', [])
        v2_keys = v2_sample.get('keys', [])
        v3_keys = v3_sample.get('keys', [])
        
        v1_has_encr = 'encr_public_key' in v1_keys[0] if v1_keys else False
        v2_has_encr = 'encr_public_key' in v2_keys[0] if v2_keys else False
        v3_has_encryption = 'encryption_public_key' in v3_keys[0] if v3_keys else False
        
        if v1_has_encr and v2_has_encr and v3_has_encryption:
            summary.append("✓ V1/V2 use encr_public_key, V3 uses encryption_public_key")
        else:
            all_passed = False
            summary.append(f"✗ Encryption key fields incorrect (V1:{v1_has_encr}, V2:{v2_has_encr}, V3:{v3_has_encryption})")
        
        # 3. Participant ID
        v2_no_participant_id = 'participant_id' not in v2_sample
        v3_has_participant_id = 'participant_id' in v3_sample
        
        if v2_no_participant_id and v3_has_participant_id:
            summary.append("✓ V2 has no participant_id, V3 has participant_id")
        else:
            all_passed = False
            summary.append(f"✗ participant_id issue (V2 should not have it, V3 should)")
        
        # 4. Additional fields
        v2_has_subscriber_url = 'subscriber_url' in v2_sample
        v2_has_br_id = 'br_id' in v2_sample
        v2_has_ukId = 'ukId' in v2_sample
        
        v3_no_subscriber_url_root = 'subscriber_url' not in v3_sample
        v3_no_br_id = 'br_id' not in v3_sample
        v3_has_uris = 'uris' in v3_sample
        v3_ukId_in_keys = 'ukId' in v3_keys[0] if v3_keys else False
        
        if v2_has_subscriber_url and v2_has_br_id and v2_has_ukId:
            summary.append("✓ V2 has subscriber_url, br_id, ukId at root")
        else:
            all_passed = False
            summary.append("✗ V2 missing expected root fields")
        
        if v3_no_subscriber_url_root and v3_no_br_id and v3_has_uris and v3_ukId_in_keys:
            summary.append("✓ V3 restructured: subscriber_url in uris, ukId in keys, br_id omitted")
        else:
            all_passed = False
            summary.append("✗ V3 structure incorrect")
        
        # Print summary
        print(f"\n[{self.step_name}] Version Comparison Summary:")
        for line in summary:
            print(f"  {line}")
        
        if all_passed:
            v1_response.success()
            v2_response.success()
            v3_response.success()
            print(f"\n[{self.step_name}] [PASS] ✓ All version differences validated correctly")
        else:
            v1_response.failure("Version comparison found issues")
            v2_response.failure("Version comparison found issues")
            v3_response.failure("Version comparison found issues")


tasks = [ONDCRegVersionComparison]
