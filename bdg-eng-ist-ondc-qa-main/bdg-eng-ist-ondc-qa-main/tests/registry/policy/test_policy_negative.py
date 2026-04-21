from locust import task
from tests.registry.subscribe.common.admin_subscribe_base import AdminSubscribeBase
import yaml
import uuid
import time
import copy
from datetime import datetime

"""
================================================================================
ONDC Policy Management Negative Test Suite
================================================================================
Test File:   test_policy_negative.py
Base Class:  AdminSubscribeBase (admin_subscribe_base.py)
YAML Config: resources/registry/policy/test_policy_negative.yml

Tests new policy features:
  - is_expired field validation and enforcement
  - version field as user input
  - Expiry enforcement (updates blocked on expired policies)
  - Restricted updates (only is_active and is_expired allowed)
  - Auto-enforcement: is_active=false when is_expired=true

Run with: python driver.py --test ondc_policy_negative --environment ondcRegistry --users 1 --iterations 1
================================================================================
"""

class ONDCPolicyNegative(AdminSubscribeBase):
    """Policy negative test suite for new expiry and version features"""
    
    config_file = 'resources/registry/subscribe/test_subscribe_functional.yml'
    test_cases_file = 'resources/registry/policy/test_policy_negative.yml'
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
                
            print(f"\n[YAML] Loaded {len(self.test_cases)} negative test cases from {self.test_cases_file}")
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
        print("POLICY NEGATIVE TEST RESULTS SUMMARY")
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
        print(f"{self.test_suite_info.get('name', 'Policy Negative Test Suite')}")
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
            # Replace common placeholders
            replacements = {
                '{{participant_id}}': test_data['participant_id'],
                '{{subscriber_id}}': test_data['participant_id'],
                '{{uk_id}}': test_data['uk_id'],
                '{{timestamp}}': datetime.now().strftime('%Y%m%d_%H%M%S'),
                '{{unique_id}}': str(uuid.uuid4())
            }
            
            result = obj
            for placeholder, replacement in replacements.items():
                result = result.replace(placeholder, replacement)
            
            return result
        else:
            return obj
    
    def _validate_response(self, test_case, data):
        """Validate response data against expected values"""
        validations = test_case.get('validate', [])
        
        if not validations:
            return True  # No validations specified
        
        for validation in validations:
            field = validation.get('field')
            expected_value = validation.get('value')
            
            # Navigate nested fields (e.g., "message.ack.status")
            current = data
            for part in field.split('.'):
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    print(f"[{self.step_name}] Validation failed: Field '{field}' not found")
                    return False
            
            if current != expected_value:
                print(f"[{self.step_name}] Validation failed: {field} = {current}, expected {expected_value}")
                return False
        
        return True
    
    def _record_test_result(self, test_id, test_name, status, message):
        """Record test result for summary"""
        self.test_results.append({
            'test_id': test_id,
            'test_name': test_name,
            'status': status,
            'message': message
        })


# Task list for CTF framework
tasks = [ONDCPolicyNegative]
