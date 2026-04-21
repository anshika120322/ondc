from locust import task
from tests.registry.subscribe.common.admin_subscribe_base import AdminSubscribeBase
import yaml
import uuid
import time
import copy
from datetime import datetime

"""
================================================================================
ONDC Policy Management Test Suite
================================================================================
Test File:   test_policy_functional.py
Base Class:  AdminSubscribeBase (admin_subscribe_base.py)
YAML Config: resources/registry/policy/test_policy_functional.yml

Executes 6 policy management tests:
  - P01: Create NETWORK policy via POST /admin/policies
  - P02: Retrieve NETWORK policy via GET /admin/policies
  - P03: Reject top-level policy_id in subscribe
  - P04: Create new NETWORK routing policy via subscribe
  - P05: Update existing NETWORK_PARTICIPANT whitelist policy
  - P06: Upsert policy object only via subscribe

Run with: python driver.py --test ondc_policy_functional --environment ondcRegistry --users 1 --iterations 1
================================================================================
"""

class ONDCPolicyManagement(AdminSubscribeBase):
    """Policy management test suite for ONDC Registry"""
    
    config_file = 'resources/registry/subscribe/test_subscribe_functional.yml'
    test_cases_file = 'resources/registry/policy/test_policy_functional.yml'
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
                
            print(f"\n[YAML] Loaded {len(self.test_cases)} test cases from {self.test_cases_file}")
            print(f"[YAML] Suite: {self.test_suite_info.get('name')}")
            print(f"[YAML] Total Tests: {self.test_suite_info.get('total_tests')}")
            
            # Initialize test results tracking
            self.test_results = []
            
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
        print("\n" + "="*80)
        print("POLICY MANAGEMENT TEST RESULTS SUMMARY")
        print("="*80)
        
        passed = sum(1 for r in self.test_results if r['status'] == 'PASS')
        failed = sum(1 for r in self.test_results if r['status'] == 'FAIL')
        skipped = sum(1 for r in self.test_results if r['status'] == 'SKIP')
        
        total = len(self.test_results)
        print(f"Total: {total} | Passed: {passed} | Failed: {failed} | Skipped: {skipped}")
        print("-"*80)
        
        for result in self.test_results:
            status_icon = {
                'PASS': '[PASS]',
                'FAIL': '[FAIL]',
                'SKIP': '[SKIP]'
            }.get(result['status'], '?')
            
            print(f"{status_icon} {result['test_id']:5} | {result['test_name']:55} | {result['status']:12} | {result['message']}")
        
        print("="*80)
    
    # ==========================================
    # YAML Test Execution
    # ==========================================
    
    @task
    def run_yaml_tests(self):
        """Execute all tests defined in YAML configuration"""
        if not self.test_cases:
            print("[ERROR] No test cases loaded from YAML")
            return
        
        print(f"\n{'='*80}")
        print(f"{self.test_suite_info.get('name', 'Policy Management Test Suite')}")
        print(f"{'='*80}")
        print(f"Total Tests: {len(self.test_cases)}")
        print(f"{'='*80}\n")
        
        for test_case in self.test_cases:
            self._execute_test_case(test_case)
    
    def _execute_test_case(self, test_case):
        """Execute a single test case from YAML configuration"""
        test_id = test_case.get('id', 'UNKNOWN')
        test_name = test_case.get('name', 'Unnamed Test')
        is_workflow = test_case.get('workflow', False)
        
        self.step_name = f"{test_id}_{test_name.replace(' ', '_').replace('(', '').replace(')', '').replace('→', '')}"
        
        print(f"[{self.step_name}] > Test {test_id}: {test_name}")
        
        try:
            # Check if multi-step workflow
            if is_workflow:
                success = self._execute_workflow(test_case, test_id, test_name)
            else:
                success = self._execute_single_step(test_case, test_id, test_name)
            
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
    
    def _execute_single_step(self, test_case, test_id, test_name):
        """Execute a single-step test"""
        method = test_case.get('method', 'POST')
        endpoint = test_case.get('endpoint', '/admin/subscribe')
        expected_status = test_case.get('expected_status', 200)
        auth_type = test_case.get('auth_type', 'admin')
        query_params = test_case.get('query_params', {})
        
        # Normalize expected_status to list (handle both single value and list)
        if not isinstance(expected_status, list):
            expected_status = [expected_status]
        
        # Build payload (for POST/PATCH methods)
        payload = self._build_payload(test_case) if method in ['POST', 'PATCH'] else {}
        
        # Execute API call based on method
        if method == 'GET':
            success, data, status_code, response = self._send_admin_get_request(
                self.step_name,
                endpoint,
                query_params=query_params,
                expected_status=expected_status,
                auth_type=auth_type
            )
        elif method == 'POST':
            # Check if using custom endpoint or default subscribe
            if endpoint != '/admin/subscribe':
                success, data, status_code, response = self._send_admin_policy_request(
                    self.step_name,
                    endpoint,
                    payload,
                    expected_status=expected_status,
                    auth_type=auth_type
                )
            else:
                success, data, status_code, response = self._send_admin_subscribe_request(
                    self.step_name,
                    payload,
                    expected_status=expected_status,
                    auth_type=auth_type
                )
        elif method == 'PATCH':
            success, data, status_code, response = self._send_admin_patch_request(
                self.step_name,
                payload,
                expected_status=expected_status
            )
        else:
            print(f"[{self.step_name}] [FAIL] Unsupported method: {method}")
            return False
        
        # Validate response
        if success:
            return self._validate_response(test_case, data)
        else:
            print(f"[{self.step_name}] Expected {expected_status}, got {status_code}")
            return False
    
    def _execute_workflow(self, test_case, test_id, test_name):
        """Execute a multi-step workflow test"""
        steps = test_case.get('steps', [])
        
        if not steps:
            print(f"[{self.step_name}] No steps defined for workflow")
            return False
        
        # Generate test participant data once for entire workflow
        test_data = self._setup_test_participant()
        
        # Execute each step in sequence
        for step_idx, step in enumerate(steps):
            step_name = step.get('name', f'Step {step_idx + 1}')
            method = step.get('method', 'POST')
            expected_status = step.get('expected_status', 200)
            auth_type = step.get('auth_type', 'admin')
            
            # Normalize expected_status to list
            if not isinstance(expected_status, list):
                expected_status = [expected_status]
            
            print(f"[{self.step_name}] Executing: {step_name}")
            
            # Build payload for this step
            payload = self._build_step_payload(step, test_data)
            
            # Get endpoint from step (default to /admin/subscribe)
            endpoint = step.get('endpoint', '/admin/subscribe')
            
            # Execute API call
            if method == 'POST':
                # Check if using custom policy endpoint or default subscribe endpoint
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
                return False
            
            # Validate response
            if not success:
                print(f"[{self.step_name}] Step '{step_name}' failed (status: {status_code})")
                return False
            
            # Validate step response if specified
            if 'validate' in step:
                if not self._validate_response(step, data):
                    print(f"[{self.step_name}] Step '{step_name}' validation failed")
                    return False
        
        return True
    
    def _build_payload(self, test_case):
        """Build payload for test case with placeholder substitution"""
        # Generate fresh participant data for this test
        test_data = self._setup_test_participant()
        
        # Get the data section from test case
        payload = copy.deepcopy(test_case.get('data', {}))
        
        # Replace placeholders
        payload = self._replace_placeholders(payload, test_data)
        
        return payload
    
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
            # Replace {{subscriber_id}}
            if '{{subscriber_id}}' in obj:
                obj = obj.replace('{{subscriber_id}}', test_data['participant_id'])
            # Replace {{timestamp}}
            if '{{timestamp}}' in obj:
                obj = obj.replace('{{timestamp}}', datetime.now().strftime('%Y%m%d_%H%M%S'))
            return obj
        else:
            return obj
    
    def _validate_response(self, test_case, data):
        """Validate response against expected values"""
        validations = test_case.get('validate', [])
        
        if not validations:
            return True
        
        for validation in validations:
            field = validation.get('field')
            expected_value = validation.get('value')
            
            # Navigate to field in response
            actual_value = self._get_nested_field(data, field)
            
            if actual_value != expected_value:
                print(f"[{self.step_name}] Validation failed: {field} = {actual_value}, expected {expected_value}")
                return False
        
        return True
    
    def _get_nested_field(self, obj, field_path):
        """Get nested field value from object using dot notation or array notation"""
        if not field_path:
            return obj
        
        # Handle array notation like [0].field or field[0]
        if field_path.startswith('['):
            # Array index at root
            bracket_end = field_path.index(']')
            index = int(field_path[1:bracket_end])
            remaining = field_path[bracket_end + 1:]
            if remaining.startswith('.'):
                remaining = remaining[1:]
            if isinstance(obj, list) and len(obj) > index:
                return self._get_nested_field(obj[index], remaining)
            return None
        
        # Handle dot notation
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
        """
        Send admin GET request to any endpoint with query parameters
        
        Args:
            step_name: Name of the test step
            endpoint: API endpoint (e.g., "/admin/policies")
            query_params: Dictionary of query parameters
            expected_status: List of acceptable status codes
            auth_type: Authentication type (default: 'admin')
        
        Returns:
            (success: bool, data: dict, status_code: int, response: Response)
        """
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
        
        # Build URL with query parameters
        url = f"{self.host}{endpoint}"
        
        # Make request
        with self.client.get(
            url,
            headers=headers,
            params=query_params,
            name=f"{step_name}_GET_{endpoint}",
            catch_response=True
        ) as response:
            try:
                data = response.json() if response.content else {}
            except:
                data = {}
            
            status_code = response.status_code
            
            # Check status code
            if status_code in expected_status:
                response.success()
                print(f"[{step_name}] ✓ GET {endpoint} → {status_code}")
                return True, data, status_code, response
            else:
                response.failure(f"Expected {expected_status}, got {status_code}")
                print(f"[{step_name}] ✗ GET {endpoint} → {status_code} (expected {expected_status})")
                print(f"[{step_name}] Response: {data}")
                return False, data, status_code, response
    
    def _send_admin_policy_request(self, step_name, endpoint, payload, expected_status=[201], auth_type='admin'):
        """
        Send admin POST request to any endpoint (e.g., /admin/policies)
        
        Args:
            step_name: Name of the test step
            endpoint: API endpoint (e.g., "/admin/policies")
            payload: Request payload
            expected_status: List of acceptable status codes
            auth_type: Authentication type (default: 'admin')
        
        Returns:
            (success: bool, data: dict, status_code: int, response: Response)
        """
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
        
        # Build URL
        url = f"{self.host}{endpoint}"
        
        # Make request
        with self.client.post(
            url,
            headers=headers,
            json=payload,
            name=f"{step_name}_POST_{endpoint}",
            catch_response=True
        ) as response:
            try:
                data = response.json() if response.content else {}
            except:
                data = {}
            
            status_code = response.status_code
            
            # Check status code
            if status_code in expected_status:
                response.success()
                print(f"[{step_name}] ✓ POST {endpoint} → {status_code}")
                if data:
                    print(f"[{step_name}] Response: {data}")
                return True, data, status_code, response
            else:
                response.failure(f"Expected {expected_status}, got {status_code}")
                print(f"[{step_name}] ✗ POST {endpoint} → {status_code} (expected {expected_status})")
                print(f"[{step_name}] Response: {data}")
                return False, data, status_code, response
    
    def _send_admin_patch_request(self, step_name, payload, expected_status=[200, 204], auth_type='admin'):
        """
        Send admin PATCH request to /admin/policies endpoint for policy updates
        
        Args:
            step_name: Name of the test step
            payload: Request payload (must include policy_id and fields to update)
            expected_status: List of acceptable status codes (default: 200, 204)
            auth_type: Authentication type (default: 'admin')
        
        Returns:
            (success: bool, data: dict, status_code: int, response: Response)
        """
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
        
        # Build URL
        url = f"{self.host}/admin/policies"
        
        # Make PATCH request
        with self.client.patch(
            url,
            headers=headers,
            json=payload,
            name=f"{step_name}_PATCH_/admin/policies",
            catch_response=True
        ) as response:
            try:
                # PATCH might return empty body with 204 No Content
                data = response.json() if response.content else {}
            except:
                data = {}
            
            status_code = response.status_code
            
            # Check status code
            if status_code in expected_status:
                response.success()
                print(f"[{step_name}] ✓ PATCH /admin/policies → {status_code}")
                if data:
                    print(f"[{step_name}] Response: {data}")
                return True, data, status_code, response
            else:
                response.failure(f"Expected {expected_status}, got {status_code}")
                print(f"[{step_name}] ✗ PATCH /admin/policies → {status_code} (expected {expected_status})")
                print(f"[{step_name}] Response: {data}")
                return False, data, status_code, response
    
    def _record_test_result(self, test_id, test_name, status, message):
        """Record test result for summary"""
        self.test_results.append({
            'test_id': test_id,
            'test_name': test_name,
            'status': status,
            'message': message
        })


# Export tasks for CTF framework
tasks = [ONDCPolicyManagement]
