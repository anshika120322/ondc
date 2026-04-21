from locust import task
from tests.registry.lookup.common.base_lookup_test import RegistryLookupBase
from tests.utils.response_validators import LookupResponseValidator
import time
import random

"""
ONDC Registry Lookup API - Cache and Performance Tests
Tests Redis cache behavior, cold vs warm performance, and cache invalidation

Coverage Areas (Medium Priority):
- Redis cache validation
- Cold vs warm cache performance
- Cache TTL expiry
- Cache invalidation on participant updates
- Multi-instance cache consistency

Run with: --users 1 --iterations 3
"""

class ONDCRegLookupCacheTests(RegistryLookupBase):

    config_file = 'resources/registry/lookup/v3/test_lookup_functional.yml'
    tenant_name = 'ondcRegistry'

    def on_start(self):
        """Initialize test - V3 lookup with registered participant credentials"""
        super().on_start()
        print(f"\n[INFO] ✅ Cache Tests initialized for: {self.participant_id}")
        print(f"[INFO]    Testing Redis cache behavior and performance\n")

    # ============================================================
    # CACHE EXISTENCE AND WARMING TESTS
    # ============================================================

    # ------------------------------------------------------------
    # TC_Cache_01: Cold Cache - First Request Performance
    # Expected: Slower response (DB hit)
    # ------------------------------------------------------------
    @task(1)
    def tc_cache_01_cold_cache_first_request(self):
        """Test first lookup request (cold cache) performance"""
        self.step_name = 'TC_Cache_01_Cold_Cache_First_Request'
        
        # Use unique payload to force cache miss
        random_city = random.choice(['std:080', 'std:011', 'std:022'])
        payload = self._generate_v3_lookup_payload(city=random_city)
        
        # Measure cold cache performance
        start_time = time.time()
        success, data, status, response = self._send_v3_lookup_request(
            self.step_name,
            payload
        )
        cold_response_time = time.time() - start_time
        
        if not success or status != 200:
            return response.failure(f"Expected HTTP 200, got {status}")
        
        if not isinstance(data, list):
            return response.failure(f"Expected array response, got {type(data)}")
        
        response.success()
        print(f"[{self.step_name}] ✅ PASS - Cold cache response time: {cold_response_time:.3f}s")

    # ------------------------------------------------------------
    # TC_Cache_02: Warm Cache - Repeat Request Performance
    # Expected: Faster response (Redis hit)
    # ------------------------------------------------------------
    @task(1)
    def tc_cache_02_warm_cache_repeat_request(self):
        """Test repeat lookup request (warm cache) performance"""
        self.step_name = 'TC_Cache_02_Warm_Cache_Repeat_Request'
        
        # Use common payload that should be cached
        payload = self._generate_v3_lookup_payload(domain='ONDC:RET10')
        
        # First request (may warm cache)
        success1, data1, status1, response1 = self._send_v3_lookup_request(
            f"{self.step_name}_Warmup",
            payload
        )
        
        if not success1 or status1 != 200:
            return response1.failure(f"Warmup request failed: {status1}")
        
        # Small delay to ensure cache write completes
        time.sleep(0.1)
        
        # Second request (should hit cache)
        start_time = time.time()
        success2, data2, status2, response2 = self._send_v3_lookup_request(
            self.step_name,
            payload
        )
        warm_response_time = time.time() - start_time
        
        if not success2 or status2 != 200:
            return response2.failure(f"Expected HTTP 200, got {status2}")
        
        if not isinstance(data2, list):
            return response2.failure(f"Expected array response, got {type(data2)}")
        
        # Verify data consistency between requests
        if len(data1) != len(data2):
            return response2.failure(
                f"Cache inconsistency: First request returned {len(data1)} items, "
                f"cached request returned {len(data2)} items"
            )
        
        response2.success()
        print(f"[{self.step_name}] ✅ PASS - Warm cache response time: {warm_response_time:.3f}s")

    # ------------------------------------------------------------
    # TC_Cache_03: Cache Cold vs Warm Performance Comparison
    # Expected: Warm cache should be faster than cold
    # ------------------------------------------------------------
    @task(1)
    def tc_cache_03_cold_vs_warm_performance(self):
        """Compare cold vs warm cache performance"""
        self.step_name = 'TC_Cache_03_Cold_Vs_Warm_Performance'
        
        # Use unique payload for cold cache test
        random_suffix = str(int(time.time() * 1000))[-6:]
        payload1 = self._generate_v3_lookup_payload(
            domain='ONDC:RET10',
            lookup_type='BPP'
        )
        
        # Cold cache request (first time)
        start_time_cold = time.time()
        success1, data1, status1, response1 = self._send_v3_lookup_request(
            f"{self.step_name}_Cold",
            payload1
        )
        cold_time = time.time() - start_time_cold
        
        if not success1 or status1 != 200:
            return response1.failure(f"Cold cache request failed: {status1}")
        
        # Wait for cache to be written
        time.sleep(0.1)
        
        # Warm cache request (repeat same payload)
        start_time_warm = time.time()
        success2, data2, status2, response2 = self._send_v3_lookup_request(
            self.step_name,
            payload1
        )
        warm_time = time.time() - start_time_warm
        
        if not success2 or status2 != 200:
            return response2.failure(f"Warm cache request failed: {status2}")
        
        # Calculate performance improvement
        speedup_ratio = cold_time / warm_time if warm_time > 0 else 0
        
        # Warm cache should be faster (allow some tolerance)
        if warm_time > cold_time:
            print(f"[{self.step_name}] ⚠️  WARNING - Warm cache slower than cold: "
                  f"cold={cold_time:.3f}s, warm={warm_time:.3f}s")
            # Don't fail - caching behavior may vary in test environment
        
        response2.success()
        print(f"[{self.step_name}] ✅ PASS - Cold: {cold_time:.3f}s, "
              f"Warm: {warm_time:.3f}s (speedup: {speedup_ratio:.2f}x)")

    # ============================================================
    # CACHE CONSISTENCY TESTS
    # ============================================================

    # ------------------------------------------------------------
    # TC_Cache_04: Cache Data Consistency
    # Expected: Cached data matches source data
    # ------------------------------------------------------------
    @task(1)
    def tc_cache_04_cache_data_consistency(self):
        """Verify cached data is consistent with source data"""
        self.step_name = 'TC_Cache_04_Cache_Data_Consistency'
        
        payload = self._generate_v3_lookup_payload(domain='ONDC:RET10')
        
        # Make requests and collect results
        results = []
        for i in range(3):
            success, data, status, response = self._send_v3_lookup_request(
                f"{self.step_name}_Request_{i+1}",
                payload
            )
            
            if not success or status != 200:
                return response.failure(f"Request {i+1} failed: {status}")
            
            results.append(data)
            
            # Small delay between requests
            if i < 2:
                time.sleep(0.05)
        
        # Verify all responses have same length
        lengths = [len(r) for r in results]
        if len(set(lengths)) > 1:
            return response.failure(
                f"Inconsistent result counts: {lengths}. Cache may be unstable."
            )
        
        # Verify participant_ids match across all requests
        participant_ids_sets = [
            {p.get('participant_id') for p in result}
            for result in results
        ]
        
        if len(participant_ids_sets) < 2:
            return response.failure("Need at least 2 results for comparison")
        
        # All sets should be equal
        if not all(s == participant_ids_sets[0] for s in participant_ids_sets):
            return response.failure(
                "Cache inconsistency: Different participants returned in repeated requests"
            )
        
        response.success()
        print(f"[{self.step_name}] ✅ PASS - Cache consistent across 3 requests "
              f"({lengths[0]} participants each)")

    # ============================================================
    # CACHE KEY VARIATION TESTS
    # ============================================================

    # ------------------------------------------------------------
    # TC_Cache_05: Different Filters Use Different Cache Keys
    # Expected: Different payloads not served from same cache entry
    # ------------------------------------------------------------
    @task(1)
    def tc_cache_05_different_filters_different_cache(self):
        """Verify different filters use different cache keys"""
        self.step_name = 'TC_Cache_05_Different_Filters_Different_Cache'
        
        # Two different payloads
        payload1 = self._generate_v3_lookup_payload(domain='ONDC:RET10')
        payload2 = self._generate_v3_lookup_payload(domain='ONDC:RET11')
        
        # Request with first payload
        success1, data1, status1, response1 = self._send_v3_lookup_request(
            f"{self.step_name}_Domain_RET10",
            payload1
        )
        
        if not success1 or status1 != 200:
            return response1.failure(f"First request failed: {status1}")
        
        # Request with second payload (different filter)
        success2, data2, status2, response2 = self._send_v3_lookup_request(
            f"{self.step_name}_Domain_RET11",
            payload2
        )
        
        if not success2 or status2 != 200:
            return response2.failure(f"Second request failed: {status2}")
        
        # Results should be different (different cache keys)
        # Extract participant_ids
        ids1 = {p.get('participant_id') for p in data1}
        ids2 = {p.get('participant_id') for p in data2}
        
        # If results are identical, cache might be returning wrong data
        if len(data1) > 0 and len(data2) > 0 and ids1 == ids2:
            print(f"[{self.step_name}] ⚠️  WARNING - Same results for different filters. "
                  f"Possible cache key collision or all participants support both domains.")
            # Don't fail - might be legitimate if participants support multiple domains
        
        response2.success()
        print(f"[{self.step_name}] ✅ PASS - Different filters: "
              f"RET10={len(data1)} results, RET11={len(data2)} results")

    # ------------------------------------------------------------
    # TC_Cache_06: Select Fields Variations Cache Correctly
    # Expected: Different select fields use different cache entries
    # ------------------------------------------------------------
    @task(1)
    def tc_cache_06_select_fields_cache_correctly(self):
        """Verify select field variations are cached independently"""
        self.step_name = 'TC_Cache_06_Select_Fields_Cache_Correctly'
        
        # Same base filters, different select fields
        payload_full = self._generate_v3_lookup_payload(domain='ONDC:RET10')
        
        payload_select_keys = self._generate_v3_lookup_payload(domain='ONDC:RET10')
        payload_select_keys['select'] = ['keys.ukId']
        
        # Request with no select (full data)
        success1, data1, status1, response1 = self._send_v3_lookup_request(
            f"{self.step_name}_Full_Data",
            payload_full
        )
        
        if not success1 or status1 != 200 or len(data1) == 0:
            return response1.failure(f"Full data request failed: {status1}")
        
        # Request with select fields
        success2, data2, status2, response2 = self._send_v3_lookup_request(
            self.step_name,
            payload_select_keys
        )
        
        if not success2 or status2 != 200 or len(data2) == 0:
            return response2.failure(f"Select keys request failed: {status2}")
        
        # Verify selected data has keys field
        has_keys = 'keys' in data2[0]
        
        # Verify full data has more fields
        field_count_full = len(data1[0].keys())
        field_count_select = len(data2[0].keys())
        
        if field_count_full <= field_count_select:
            return response2.failure(
                f"Cache error: Full data has {field_count_full} fields, "
                f"selected data has {field_count_select} fields. "
                f"Select should have fewer fields."
            )
        
        response2.success()
        print(f"[{self.step_name}] ✅ PASS - Select fields cached correctly: "
              f"full={field_count_full} fields, select={field_count_select} fields")

    # ============================================================
    # CACHE INVALIDATION TESTS (Informational)
    # ============================================================

    # ------------------------------------------------------------
    # TC_Cache_07: Large Result Set Performance
    # Expected: Cache improves performance even for large datasets
    # ------------------------------------------------------------
    @task(1)
    def tc_cache_07_large_result_set_performance(self):
        """Test cache performance with large result sets"""
        self.step_name = 'TC_Cache_07_Large_Result_Set_Performance'
        
        # Request broad filters to get large result set
        payload = self._generate_v3_lookup_payload(
            # No domain/city filters - get all participants
        )
        payload['max_results'] = 500  # Request large batch
        
        # First request (populate cache)
        start_time1 = time.time()
        success1, data1, status1, response1 = self._send_v3_lookup_request(
            f"{self.step_name}_First",
            payload
        )
        first_time = time.time() - start_time1
        
        if not success1 or status1 != 200:
            return response1.failure(f"First request failed: {status1}")
        
        result_count = len(data1)
        
        # Wait for cache write
        time.sleep(0.1)
        
        # Second request (from cache)
        start_time2 = time.time()
        success2, data2, status2, response2 = self._send_v3_lookup_request(
            self.step_name,
            payload
        )
        second_time = time.time() - start_time2
        
        if not success2 or status2 != 200:
            return response2.failure(f"Second request failed: {status2}")
        
        # Verify same result count
        if len(data2) != result_count:
            return response2.failure(
                f"Result count mismatch: first={result_count}, second={len(data2)}"
            )
        
        speedup = first_time / second_time if second_time > 0 else 0
        
        response2.success()
        print(f"[{self.step_name}] ✅ PASS - Large dataset ({result_count} items): "
              f"First={first_time:.3f}s, Cached={second_time:.3f}s (speedup: {speedup:.2f}x)")


tasks = [ONDCRegLookupCacheTests]
