from locust import task
from tests.registry.subscribe.common.admin_subscribe_base import AdminSubscribeBase
from tests.utils.ondc_auth_helper import ONDCAuthHelper
import yaml
import uuid
import time
import copy
import logging
from datetime import datetime

"""
================================================================================
ONDC Policy + Lookup Integration Test Suite
================================================================================
Test File:   test_policy_lookup_integration.py
Base Class:  AdminSubscribeBase (admin_subscribe_base.py)
YAML Config: resources/registry/policy/test_policy_lookup_integration.yml

Comprehensive end-to-end policy workflow with lookup verification:
  1. Register participant via /admin/subscribe
  2. Create policy via POST /admin/policies
  3. Verify policy via GET /admin/policies?participant_id=xxx
  4. Verify participant in lookup by participant_id
  5. Verify participant in lookup by subscriber_id23ww
  6. Verify participant in lookup by domain/type/city
  7. Test all lookup query combinations

Run with: python driver.py --test ondc_policy_lookup --environment ondcRegistry --users 1 --iterations 1
================================================================================
"""

class ONDCPolicyLookupIntegration(AdminSubscribeBase):
    """Policy + Lookup integration test suite for ONDC Registry"""
    
    config_file = 'resources/registry/subscribe/test_subscribe_functional.yml'
    test_cases_file = 'resources/registry/policy/test_policy_lookup_integration.yml'
    tenant_name = 'ondcRegistry'
    
    def on_start(self):
        """Initialize and load test cases from YAML"""
        super().on_start()
        
        # Load test cases from YAML
        try:
            with open(self.test_cases_file, 'r', encoding='utf-8') as f:
                test_config = yaml.safe_load(f)
                self.test_cases = test_config.get('tests', [])
                self.test_suite_info = test_config.get('test_suite', {})
                self.config_info = test_config.get('config', {})
                
                # Get lookup configuration
                lookup_config = test_config.get('lookup_config', {})
                self.lookup_host = lookup_config.get('host', 'http://35.244.48.178:8080')
                self.core_version = lookup_config.get('core_version', '1.2.0')
                
            print(f"\n[YAML] Loaded {len(self.test_cases)} test cases from {self.test_cases_file}")
            print(f"[YAML] Suite: {self.test_suite_info.get('name')}")
            print(f"[YAML] Lookup Host: {self.lookup_host}")
            
            # Initialize test results tracking
            self.test_results = []
            
            # Track created participants for cleanup
            self.created_participants = []
            
        except Exception as e:
            print(f"[ERROR] Failed to load test cases from YAML: {e}")
            import traceback
            traceback.print_exc()
            self.test_cases = []
    
    def on_stop(self):
        """Display test summary"""
        super().on_stop()
        
        if not self.test_results:
            return
        
        # Display summary table
        print("\n" + "="*100)
        print("POLICY + LOOKUP INTEGRATION TEST RESULTS SUMMARY")
        print("="*100)
        
        passed = sum(1 for r in self.test_results if r['status'] == 'PASS')
        failed = sum(1 for r in self.test_results if r['status'] == 'FAIL')
        skipped = sum(1 for r in self.test_results if r['status'] == 'SKIP')
        
        total = len(self.test_results)
        print(f"Total: {total} | Passed: {passed} | Failed: {failed} | Skipped: {skipped}")
        print("-"*100)
        
        for result in self.test_results:
            status_icon = {
                'PASS': '[PASS]',
                'FAIL': '[FAIL]',
                'SKIP': '[SKIP]'
            }.get(result['status'], '?')
            
            print(f"{status_icon} {result['test_id']:8} | {result['test_name']:65} | {result['status']:12} | {result['message']}")
        
        print("="*100)
    
    @task
    def run_yaml_tests(self):
        """Execute all tests defined in YAML configuration"""
        if not self.test_cases:
            print("[ERROR] No test cases loaded from YAML")
            return
        
        print(f"\n{'='*100}")
        print(f"{self.test_suite_info.get('name', 'Policy + Lookup Integration Test Suite')}")
        print(f"{'='*100}")
        print(f"Total Tests: {len(self.test_cases)}")
        print(f"{'='*100}\n")
        
        for test_case in self.test_cases:
            self._execute_test_case(test_case)
    
    def _execute_test_case(self, test_case):
        """Execute a single test case from YAML configuration"""
        test_id = test_case.get('id', 'UNKNOWN')
        test_name = test_case.get('name', 'Unnamed Test')
        
        self.step_name = f"{test_id}_{test_name.replace(' ', '_').replace('(', '').replace(')', '').replace('→', '').replace('/', '_')}"
        
        print(f"\n[{self.step_name}] > Test {test_id}: {test_name}")
        
        try:
            # Execute workflow test
            success = self._execute_workflow(test_case, test_id, test_name)
            
            if success:
                print(f"[{self.step_name}] [PASS] {test_id}: Test passed")
                self._record_test_result(test_id, test_name, "PASS", "Test successful")
            else:
                print(f"[{self.step_name}] [FAIL] {test_id}: Test failed")
                self._record_test_result(test_id, test_name, "FAIL", "Test failed")
        
        except Exception as e:
            print(f"[{self.step_name}] [FAIL] {test_id}: Exception - {str(e)}")
            import traceback
            traceback.print_exc()
            self._record_test_result(test_id, test_name, "FAIL", f"Exception: {str(e)}")
        
        time.sleep(1)
    
    def _record_test_result(self, test_id, test_name, status, message):
        """Record test result for summary"""
        self.test_results.append({
            'test_id': test_id,
            'test_name': test_name,
            'status': status,
            'message': message
        })
    
    def _execute_workflow(self, test_case, test_id, test_name):
        """Execute a multi-step workflow test"""
        steps = test_case.get('steps', [])
        
        if not steps:
            print(f"[{self.step_name}] No steps defined for workflow")
            return False
        
        # Generate test participant data once for entire workflow
        test_data = self._setup_test_participant()
        
        # Display test participant info prominently
        print(f"\n{'='*80}")
        print(f"[{test_id}] TEST PARTICIPANT INFO:")
        print(f"  → Participant ID: {test_data['participant_id']}")
        print(f"  → Subscriber ID:  {test_data['participant_id']}  (same as participant_id)")
        print(f"  → UK ID:          {test_data['uk_id']}")
        print(f"  → Signing Public Key: {test_data['signing_public_key'][:40]}...")
        print(f"  → Private Key (hex): {test_data['private_key_seed'][:16]}...{test_data['private_key_seed'][-16:]}")
        print(f"{'='*80}\n")
        
        # Initialize ONDC Auth Helper for ED25519 signatures
        try:
            private_key_bytes = bytes.fromhex(test_data['private_key_seed'])
            self.ondc_auth_helper = ONDCAuthHelper(
                test_data['participant_id'],
                test_data['uk_id'],
                private_key_bytes
            )
            print(f"[{self.step_name}] ✓ Initialized ED25519 auth helper")
        except Exception as e:
            print(f"[{self.step_name}] Warning: Failed to initialize auth helper: {e}")
            self.ondc_auth_helper = None
        
        # Store participant for potential cleanup
        self.created_participants.append(test_data['participant_id'])
        
        # Store policy_id for later steps
        created_policy_id = None
        
        # Execute each step in sequence
        for step_idx, step in enumerate(steps):
            step_name = step.get('name', f'Step {step_idx + 1}')
            step_type = step.get('type', 'api')  # api or lookup
            method = step.get('method', 'POST')
            expected_status = step.get('expected_status', 200)
            auth_type = step.get('auth_type', 'admin')
            
            # Normalize expected_status to list
            if not isinstance(expected_status, list):
                expected_status = [expected_status]
            
            print(f"[{self.step_name}] Step {step_idx + 1}/{len(steps)}: {step_name}")
            
            # Execute based on step type
            if step_type == 'lookup':
                # Lookup query step
                success = self._execute_lookup_step(step, test_data, created_policy_id)
            else:
                # Regular API step
                success, data = self._execute_api_step(step, test_data, step_idx, method, expected_status, auth_type)
                
                # Save policy_id if this step created a policy
                if success and method == 'POST' and step.get('endpoint') == '/admin/policies':
                    if data and isinstance(data, dict):
                        created_policy_id = data.get('policy_id')
                        print(f"\n{'─'*80}")
                        print(f"[{test_id}] POLICY CREATED:")
                        print(f"  → Policy ID:      {created_policy_id}")
                        print(f"  → For Participant: {test_data['participant_id']}")
                        print(f"{'─'*80}\n")
                
                # Add delay after registration to allow lookup service to sync
                if success and method == 'POST' and step.get('endpoint') == '/admin/subscribe':
                    import time
                    sync_delay = 5  # Wait 5 seconds for lookup service sync
                    print(f"[{self.step_name}] Waiting {sync_delay}s for lookup service sync...")
                    time.sleep(sync_delay)
            
            # Check step result
            if not success:
                print(f"[{self.step_name}] Step '{step_name}' failed")
                return False
        
        return True
    
    def _execute_api_step(self, step, test_data, step_idx, method, expected_status, auth_type):
        """Execute a standard API step"""
        # Build payload for this step
        payload = self._build_step_payload(step, test_data)
        
        # Get endpoint from step
        endpoint = step.get('endpoint', '/admin/subscribe')
        
        # Execute API call
        if method == 'GET':
            query_params = step.get('query_params', {})
            # Replace placeholders in query params
            query_params = self._replace_placeholders(query_params, test_data)
            
            success, data, status_code, response = self._send_admin_get_request(
                f"{self.step_name}_Step{step_idx+1}",
                endpoint,
                query_params=query_params,
                expected_status=expected_status,
                auth_type=auth_type
            )
        elif method == 'POST':
            if endpoint == '/admin/policies':
                success, data, status_code, response = self._send_admin_policy_request(
                    f"{self.step_name}_Step{step_idx+1}",
                    endpoint,
                    payload,
                    expected_status=expected_status,
                    auth_type=auth_type
                )
            else:
                success, data, status_code, response = self._send_admin_subscribe_request(
                    f"{self.step_name}_Step{step_idx+1}",
                    payload,
                    expected_status=expected_status,
                    auth_type=auth_type
                )
        elif method == 'PATCH':
            success, data, status_code, response = self._send_admin_patch_request(
                f"{self.step_name}_Step{step_idx+1}",
                payload,
                expected_status=expected_status
            )
        else:
            print(f"[{self.step_name}] [FAIL] Unsupported method: {method}")
            return False, {}
        
        # Validate response if step has validation rules
        if success and 'validate' in step:
            if not self._validate_response(step, data, test_data):
                print(f"[{self.step_name}] Step validation failed")
                return False, data
        
        return success, data
    
    def _execute_lookup_step(self, step, test_data, created_policy_id):
        """Execute a lookup query step with retry logic"""
        import time
        
        lookup_type = step.get('lookup_type', 'participant_id')  # participant_id, subscriber_id, or domain
        max_retries = 5  # Retry up to 5 times
        retry_delay = 4  # Wait 4 seconds between retries
        
        # Build lookup payload based on type
        # V3 lookup API uses participant_id (not subscriber_id), type (not core_version)
        if lookup_type == 'participant_id':
            # Query by specific participant_id
            payload = {
                "participant_id": test_data['participant_id'],
                "country": "IND",
                "type": "BPP"  # Required field for v3
            }
        elif lookup_type == 'subscriber_id':
            # Query by specific subscriber_id (same as participant_id in ONDC)
            payload = {
                "participant_id": test_data['participant_id'],  # participant_id is subscriber_id
                "country": "IND",
                "type": "BPP"  # Required field for v3
            }
        elif lookup_type == 'domain':
            print(f"[{self.step_name}] >>> ENTERING DOMAIN LOOKUP BLOCK - CODE VERSION 2024-03-18-v2 <<<")
            
            # Get domain/type/city from step config
            domain = step.get('domain', 'ONDC:RET12')
            np_type = step.get('np_type', 'BPP')
            city = step.get('city', 'std:080')
            
            # DEBUG: Log extracted values
            print(f"[{self.step_name}] DEBUG: raw step values - domain={domain}, city={city}, np_type={np_type}")
            print(f"[{self.step_name}] DEBUG: domain type={type(domain)}, city type={type(city)}")
            
            # Query by domain/type/city filters
            # V3 API expects domain/city as strings, not arrays
            payload = {
                "domain": domain,  # String, not array
                "type": np_type,
                "city": city,  # String, not array
                "country": "IND"
            }
            
            print(f"[{self.step_name}] DEBUG: built payload  = {payload}")
            print(f"[{self.step_name}] DEBUG: payload['domain'] = {payload['domain']}, type = {type(payload['domain'])}")
        else:
            print(f"[{self.step_name}] Unknown lookup_type: {lookup_type}")
            return False
        
        # Retry loop with delays for sync
        for attempt in range(1, max_retries + 1):
            # Send lookup request with validation
            success, data, status_code = self._send_lookup_request(
                f"{self.step_name}_Lookup_{lookup_type}",
                payload,
                expected_participant_id=test_data['participant_id']  # Validate inside request
            )
            
            if success:
                print(f"[{self.step_name}] ✓ Participant found in lookup ({lookup_type}) on attempt {attempt}")
                return True
            else:
                # Lookup failed (either HTTP error or participant not found)
                if attempt < max_retries:
                    print(f"[{self.step_name}] Lookup attempt {attempt} failed, retrying in {retry_delay}s...")
                    time.sleep(retry_delay)
                    continue
                else:
                    # All retries exhausted
                    if status_code != 200:
                        print(f"[{self.step_name}] ❌ LOOKUP FAILED after {max_retries} attempts: {lookup_type}, status: {status_code}")
                        print(f"[{self.step_name}] DIAGNOSTIC: HTTP request failed")
                        print(f"[{self.step_name}]   - Lookup service URL: {self.lookup_host}")
                        print(f"[{self.step_name}]   - Check if lookup service is running")
                    else:
                        print(f"[{self.step_name}] ❌ LOOKUP INTEGRATION FAILURE after {max_retries} attempts ({lookup_type})")
                        print(f"[{self.step_name}] DIAGNOSTIC: Lookup returned 200 OK but participant not in results")
                        print(f"[{self.step_name}]   - This indicates lookup service is NOT syncing with registry")
                        print(f"[{self.step_name}]   - Participant registered successfully but not indexed in lookup")
                        print(f"[{self.step_name}]   - Participant ID: {test_data['participant_id']}")
                        print(f"[{self.step_name}]   - Query payload: {payload}")
                        print(f"[{self.step_name}] ACTION REQUIRED: Verify lookup service configuration and sync mechanism")
                    return False  # FAIL test - now properly tracked by Locust
        
        return False
    
    def _send_lookup_request(self, step_name, payload, expected_participant_id=None):
        """Send request to lookup service with ED25519 authentication
        
        Args:
            step_name: Name for Locust tracking
            payload: Lookup request payload
            expected_participant_id: If provided, validates participant exists in response
        """
        try:
            # Generate authenticated headers and serialized body
            if self.ondc_auth_helper:
                try:
                    auth_data = self.ondc_auth_helper.generate_headers(payload)
                    headers = {
                        'Authorization': auth_data['Authorization'],
                        'Content-Type': auth_data['Content-Type']
                    }
                    # Use pre-serialized body to ensure signature matches
                    body = auth_data['serialized_body']
                    print(f"[{step_name}] Using ED25519 authenticated request")
                except Exception as e:
                    print(f"[{step_name}] Warning: Failed to generate auth headers: {e}")
                    headers = {'Content-Type': 'application/json'}
                    body = None
            else:
                print(f"[{step_name}] Warning: No auth helper available, sending unauthenticated request")
                headers = {'Content-Type': 'application/json'}
                body = None
            
            # Send request with authentication
            with self.client.post(
                name=step_name,
                url=f"{self.lookup_host}/v3.0/lookup",
                data=body if body else None,
                json=payload if not body else None,
                headers=headers,
                catch_response=True
            ) as response:
                
                print(f"[{step_name}] Lookup request: POST {self.lookup_host}/v3.0/lookup")
                print(f"[{step_name}] Lookup payload: {payload}")
                print(f"[{step_name}] Lookup response status: {response.status_code}")
                
                if response.status_code != 200:
                    error_body = response.text[:500] if response.text else "No response body"
                    print(f"[{step_name}] Lookup error response: {error_body}")
                    response.failure(f"Lookup failed: Status {response.status_code}")
                    return False, None, response.status_code
                
                try:
                    data = response.json() if response.content else None
                    print(f"[{step_name}] Lookup response data type: {type(data)}")
                    if isinstance(data, list):
                        print(f"[{step_name}] Lookup returned {len(data)} participants")
                        # DEBUG: Print full response for diagnosis
                        if len(data) == 0:
                            print(f"[{step_name}] ⚠️  EMPTY LIST RETURNED - Response body:")
                            print(f"[{step_name}] {response.text[:1000]}")
                        else:
                            print(f"[{step_name}] First participant in response:")
                            import json
                            print(f"[{step_name}] {json.dumps(data[0], indent=2)[:500]}")
                    elif isinstance(data, dict):
                        print(f"[{step_name}] Lookup returned single participant object")
                        import json
                        print(f"[{step_name}] Response: {json.dumps(data, indent=2)[:500]}")
                    else:
                        print(f"[{step_name}] ⚠️  Unexpected response type!")
                        print(f"[{step_name}] Raw response: {response.text[:1000]}")
                    
                    # Validate participant exists if expected_participant_id provided
                    if expected_participant_id:
                        participant_found = self._validate_lookup_response(data, expected_participant_id)
                        if not participant_found:
                            response.failure(f"Participant {expected_participant_id} not found in lookup response")
                            return False, data, response.status_code
                    
                    response.success()
                    return True, data, response.status_code
                except Exception as e:
                    print(f"[{step_name}] Failed to parse lookup response: {str(e)}")
                    print(f"[{step_name}] Raw response text: {response.text[:500]}")
                    response.failure(f"Failed to parse lookup response: {str(e)}")
                    return False, None, response.status_code
                    
        except Exception as e:
            print(f"[{step_name}] Lookup request exception: {str(e)}")
            return False, None, 0
    
    def _validate_lookup_response(self, data, participant_id):
        """Validate that participant appears in lookup response"""
        if not data:
            print(f"  └─ Validation: No data returned from lookup service")
            return False
        
        print(f"  └─ Validating lookup response for participant: {participant_id}")
        
        # Response can be a dict (single participant) or list (multiple participants)
        if isinstance(data, dict):
            # Check if this is the participant we're looking for
            response_participant_id = data.get('participant_id') or data.get('subscriber_id')
            print(f"  └─ Found single participant in response: {response_participant_id}")
            match = response_participant_id == participant_id
            print(f"  └─ Match result: {match}")
            return match
        
        elif isinstance(data, list):
            # Search for participant in list
            print(f"  └─ Searching through {len(data)} participants in response")
            for idx, item in enumerate(data):
                if isinstance(item, dict):
                    response_participant_id = item.get('participant_id') or item.get('subscriber_id')
                    print(f"  └─ [{idx}] Participant: {response_participant_id}")
                    if response_participant_id == participant_id:
                        print(f"  └─ ✓ MATCH FOUND at index {idx}")
                        return True
            print(f"  └─ ✗ No matching participant found in list")
            return False
        
        print(f"  └─ Unexpected data type: {type(data)}")
        return False
    
    def _build_step_payload(self, step, test_data):
        """Build payload for workflow step with placeholder substitution"""
        # Get the data section from step
        payload = copy.deepcopy(step.get('data', {}))
        
        # Replace placeholders
        payload = self._replace_placeholders(payload, test_data)
        
        return payload
    
    def _replace_placeholders(self, obj, test_data):
        """Recursively replace placeholders in object"""
        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                result[key] = self._replace_placeholders(value, test_data)
            return result
        elif isinstance(obj, list):
            return [self._replace_placeholders(item, test_data) for item in obj]
        elif isinstance(obj, str):
            # Replace {{participant_id}} and {{subscriber_id}}
            if '{{participant_id}}' in obj:
                obj = obj.replace('{{participant_id}}', test_data['participant_id'])
            if '{{subscriber_id}}' in obj:
                obj = obj.replace('{{subscriber_id}}', test_data['participant_id'])
            # Replace {{timestamp}}
            if '{{timestamp}}' in obj:
                obj = obj.replace('{{timestamp}}', datetime.now().strftime('%Y%m%d_%H%M%S'))
            # Replace {{uk_id}}
            if '{{uk_id}}' in obj:
                obj = obj.replace('{{uk_id}}', test_data['uk_id'])
            # Replace signing keys and validity dates - CRITICAL for ED25519 auth to work
            if '{{signing_public_key}}' in obj:
                obj = obj.replace('{{signing_public_key}}', test_data['signing_public_key'])
            if '{{encryption_public_key}}' in obj:
                obj = obj.replace('{{encryption_public_key}}', test_data['encryption_public_key'])
            if '{{valid_from}}' in obj:
                obj = obj.replace('{{valid_from}}', test_data['valid_from'])
            if '{{valid_until}}' in obj:
                obj = obj.replace('{{valid_until}}', test_data['valid_until'])
            return obj
        else:
            return obj
    
    def _validate_response(self, test_case, data, test_data):
        """Validate response against expected values"""
        validations = test_case.get('validate', [])
        
        if not validations:
            return True
        
        for validation in validations:
            field = validation.get('field')
            expected_value = validation.get('value')
            
            # Replace placeholders in expected_value
            if isinstance(expected_value, str):
                expected_value = self._replace_placeholders(expected_value, test_data)
            
            # Navigate to field in response
            actual_value = self._get_nested_field(data, field)
            
            if actual_value != expected_value:
                print(f"[{self.step_name}] Validation failed: {field} = {actual_value}, expected {expected_value}")
                return False
        
        return True
    
    def _get_nested_field(self, obj, field_path):
        """Get nested field value from object using dot notation"""
        if not field_path:
            return obj
        
        parts = field_path.split('.', 1)
        current = parts[0]
        remaining = parts[1] if len(parts) > 1 else None
        
        if isinstance(obj, dict):
            value = obj.get(current)
            if remaining:
                return self._get_nested_field(value, remaining)
            return value
        
        return None
    
    def _send_admin_get_request(self, step_name, endpoint, query_params=None, expected_status=[200], auth_type='admin'):
        """Send admin GET request with query parameters"""
        # Get admin token
        token = self.auth_client.get_token()
        if not token:
            print(f"[{step_name}] Failed to get admin token")
            return False, {}, 0, None
        
        # Build headers
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Make request
        with self.client.get(
            f"{self.host}{endpoint}",
            headers=headers,
            params=query_params,
            name=f"{step_name}_GET",
            catch_response=True
        ) as response:
            
            if response.status_code not in expected_status:
                response.failure(f"Expected {expected_status}, got {response.status_code}")
                return False, {}, response.status_code, response
            
            try:
                data = response.json() if response.content else {}
                response.success()
                return True, data, response.status_code, response
            except Exception as e:
                response.failure(f"Failed to parse response: {str(e)}")
                return False, {}, response.status_code, response
    
    def _send_admin_policy_request(self, step_name, endpoint, payload, expected_status=[201], auth_type='admin'):
        """Send POST request to /admin/policies endpoint"""
        # Get admin token
        token = self.auth_client.get_token()
        if not token:
            print(f"[{step_name}] Failed to get admin token")
            return False, {}, 0, None
        
        # Build headers
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Make request
        with self.client.post(
            f"{self.host}{endpoint}",
            json=payload,
            headers=headers,
            name=f"{step_name}_POST_Policy",
            catch_response=True
        ) as response:
            
            if response.status_code not in expected_status:
                response.failure(f"Expected {expected_status}, got {response.status_code}")
                print(f"[{step_name}] Response: {response.text[:500]}")
                return False, {}, response.status_code, response
            
            try:
                data = response.json() if response.content else {}
                response.success()
                return True, data, response.status_code, response
            except Exception as e:
                response.failure(f"Failed to parse response: {str(e)}")
                return False, {}, response.status_code, response
    
    def _send_admin_subscribe_request(self, step_name, payload, expected_status=[200], auth_type='admin'):
        """Override to use full URL instead of relative path
        
        Send admin subscribe request (POST /admin/subscribe)
        
        Args:
            auth_type: 'admin' (default) or 'none' (no auth header)
        
        Returns:
            tuple: (success, data, status_code, response)
        """
        if auth_type == 'none':
            headers = {'Content-Type': 'application/json'}
        else:
            token = self.auth_client.get_token()
            if not token:
                print(f"[{step_name}] Failed to get admin token")
                return False, {}, 0, None
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
        
        with self.client.post(
            name=step_name,
            url=f"{self.host}/admin/subscribe",  # Use full URL
            json=payload,
            headers=headers,
            catch_response=True
        ) as response:
            status_code = response.status_code
            
            if status_code in expected_status:
                try:
                    data = response.json()
                    response.success()
                    return True, data, status_code, response
                except Exception as e:
                    error_msg = f"Error parsing response: {e}"
                    print(f"[{step_name}] {error_msg}")
                    response.failure(error_msg)
                    return False, None, status_code, response
            else:
                try:
                    error_data = response.json()
                    error_msg = f"Expected {expected_status}, got {status_code}: {error_data}"
                    print(f"[{step_name}] {error_msg}")
                    response.failure(error_msg)
                    return False, error_data, status_code, response
                except:
                    error_msg = f"Expected {expected_status}, got {status_code}: {response.text[:200]}"
                    print(f"[{step_name}] {error_msg}")
                    response.failure(error_msg)
                    return False, None, status_code, response
    
    def _send_admin_patch_request(self, step_name, payload, expected_status=[200]):
        """Override to use full URL instead of relative path
        
        Send admin patch request (PATCH /admin/subscribe)
        
        Returns:
            tuple: (success, data, status_code, response)
        """
        token = self.auth_client.get_token()
        if not token:
            print(f"[{step_name}] Failed to get admin token")
            return False, {}, 0, None
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        with self.client.patch(
            name=step_name,
            url=f"{self.host}/admin/subscribe",  # Use full URL
            json=payload,
            headers=headers,
            catch_response=True
        ) as response:
            status_code = response.status_code
            
            if status_code in expected_status:
                try:
                    data = response.json()
                    response.success()
                    return True, data, status_code, response
                except Exception as e:
                    error_msg = f"Error parsing response: {e}"
                    print(f"[{step_name}] {error_msg}")
                    response.failure(error_msg)
                    return False, None, status_code, response
            else:
                try:
                    error_data = response.json()
                    error_msg = f"Expected {expected_status}, got {status_code}: {error_data}"
                    print(f"[{step_name}] {error_msg}")
                    response.failure(error_msg)
                    return False, error_data, status_code, response
                except:
                    error_msg = f"Expected {expected_status}, got {status_code}: {response.text[:200]}"
                    print(f"[{step_name}] {error_msg}")
                    response.failure(error_msg)
                    return False, None, status_code, response

# Locust tasks list - required by CTF framework
tasks = [ONDCPolicyLookupIntegration]
