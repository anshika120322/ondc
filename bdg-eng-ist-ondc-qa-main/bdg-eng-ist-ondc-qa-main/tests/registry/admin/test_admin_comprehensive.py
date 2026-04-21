from locust import task
from tests.registry.subscribe.common.admin_subscribe_base import AdminSubscribeBase
import yaml
import uuid
import time
import copy

"""
================================================================================
ONDC Admin Comprehensive Test Suite
================================================================================
Test File:   ondc_admin_comprehensive.py
Base Class:  AdminSubscribeBase (admin_subscribe_base.py)
YAML Config: ondc_admin_comprehensive_tests.yml

Executes all 45 admin tests (creates, transitions, updates, workflows, validations)
Run with: --users 1 --iterations 1
================================================================================
"""

class ONDCAdminComprehensive(AdminSubscribeBase):
    """Admin comprehensive test suite with positive and negative scenarios"""
    
    config_file = 'resources/registry/subscribe/test_subscribe_functional.yml'
    test_cases_file = 'resources/registry/admin/test_admin_comprehensive.yml'
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
        print("ADMIN TEST RESULTS SUMMARY")
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
        print(f"{self.test_suite_info.get('name', 'Admin Test Suite')}")
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
        is_skip = test_case.get('skip', False)
        skip_reason = test_case.get('skip_reason', 'No reason provided')
        
        self.step_name = f"{test_id}_{test_name.replace(' ', '_').replace('(', '').replace(')', '').replace('→', '')}"
        
        print(f"[{self.step_name}] > Test {test_id}: {test_name}")
        
        # Check if test should be skipped
        if is_skip:
            print(f"[{self.step_name}] [SKIP] {test_id}: {skip_reason}")
            self._record_test_result(test_id, test_name, "SKIP", skip_reason)
            return
        
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
        expected_status = test_case.get('expected_status', 200)
        auth_type = test_case.get('auth_type', 'admin')
        
        # Build payload
        payload = self._build_payload(test_case)
        
        # Execute API call
        if method == 'POST':
            success, data, status_code, response = self._send_admin_subscribe_request(
                self.step_name,
                payload,
                expected_status=[expected_status],
                auth_type=auth_type
            )
        elif method == 'PATCH':
            success, data, status_code, response = self._send_admin_patch_request(
                self.step_name,
                payload,
                expected_status=[expected_status]
            )
        elif method == 'DELETE':
            # DELETE requires endpoint path (e.g., /admin/configs/{config_id})
            endpoint = test_case.get('endpoint')
            if not endpoint:
                print(f"[{self.step_name}] [FAIL] DELETE method requires 'endpoint' field")
                return False
            success, data, status_code, response = self._send_admin_delete_request(
                self.step_name,
                endpoint,
                expected_status=[expected_status]
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
        """Execute a multi-step workflow test with response parsing between steps"""
        steps = test_case.get('steps', [])
        
        if not steps:
            print(f"[{self.step_name}] No steps defined for workflow")
            return False
        
        # Generate test participant data once for entire workflow
        test_data = self._setup_test_participant()
        
        # Response context to store data from previous steps
        response_context = {
            'responses': [],  # Store all responses
            'last_response': None,  # Most recent response for {{response.field}} syntax
            'credentials': None  # Store credentials for lookup API
        }
        
        # Generate test participant data once for the entire workflow
        test_data = self._setup_test_participant()
        
        # Store credentials in context for lookup step
        response_context['credentials'] = {
            'participant_id': test_data.get('participant_id'),
            'uk_id': test_data.get('uk_id'),
            'private_key_seed': test_data.get('private_key_seed')
        }
        
        # Execute each step in sequence
        for step_idx, step in enumerate(steps):
            step_name = step.get('name', f'Step {step_idx + 1}')
            method = step.get('method', 'POST')
            expected_status = step.get('expected_status', 200)
            auth_type = step.get('auth_type', 'admin')
            
            print(f"[{self.step_name}] Executing: {step_name}")
            
            # Build payload for this step (with response context)
            payload = self._build_step_payload(step, test_data, response_context)
            
            # Execute API call
            if method == 'POST':
                success, data, status_code, response = self._send_admin_subscribe_request(
                    f"{self.step_name}_Step{step_idx+1}",
                    payload,
                    expected_status=[expected_status],
                    auth_type=auth_type
                )
            elif method == 'PATCH':
                success, data, status_code, response = self._send_admin_patch_request(
                    f"{self.step_name}_Step{step_idx+1}",
                    payload,
                    expected_status=[expected_status]
                )
            elif method == 'GET':
                # GET uses lookup API to fetch participant details
                participant_id = step.get('participant_id') or test_data.get('participant_id')
                if not participant_id:
                    print(f"[{self.step_name}] Step '{step_name}': GET requires 'participant_id'")
                    return False
                # Substitute variables in participant_id if needed
                participant_id = self._substitute_variables(participant_id, test_data, response_context)
                success, data, status_code, response = self._send_lookup_request(
                    f"{self.step_name}_Step{step_idx+1}",
                    participant_id,
                    response_context['credentials'],
                    expected_status=[expected_status]
                )
            elif method == 'DELETE':
                # DELETE requires endpoint path (substitute variables)
                endpoint = step.get('endpoint')
                if not endpoint:
                    print(f"[{self.step_name}] Step '{step_name}': DELETE requires 'endpoint' field")
                    return False
                # Substitute variables in endpoint path
                endpoint = self._substitute_variables(endpoint, test_data, response_context)
                success, data, status_code, response = self._send_admin_delete_request(
                    f"{self.step_name}_Step{step_idx+1}",
                    endpoint,
                    expected_status=[expected_status]
                )
            else:
                print(f"[{self.step_name}] Unsupported method: {method}")
                return False
            
            if not success:
                print(f"[{self.step_name}] Step '{step_name}' failed: Expected {expected_status}, got {status_code}")
                return False
            
            # Store response data for use in subsequent steps
            response_context['responses'].append({
                'step_index': step_idx,
                'step_name': step_name,
                'data': data,
                'status_code': status_code
            })
            response_context['last_response'] = data
            
            print(f"[{self.step_name}] Step '{step_name}' completed successfully")
        
        # All steps completed successfully
        return True
    
    def _build_payload(self, test_case):
        """Build request payload from test case configuration"""
        payload = copy.deepcopy(test_case.get('data', {}))
        
        # Generate test participant data
        test_data = self._setup_test_participant()
        
        # Substitute variables in payload
        payload = self._substitute_variables(payload, test_data)
        
        return payload
    
    def _build_step_payload(self, step, test_data, response_context=None):
        """Build request payload for a workflow step using shared test_data and response context"""
        payload = copy.deepcopy(step.get('data', {}))
        
        # Substitute variables in payload using shared test_data and response context
        payload = self._substitute_variables(payload, test_data, response_context)
        
        return payload
    
    def _substitute_variables(self, obj, test_data, response_context=None):
        """Recursively substitute {{variables}} in payload with support for response data"""
        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                result[key] = self._substitute_variables(value, test_data, response_context)
            return result
        elif isinstance(obj, list):
            return [self._substitute_variables(item, test_data, response_context) for item in obj]
        elif isinstance(obj, str):
            # Handle response variable substitution (e.g., {{response.configs[0].config_id}})
            if response_context and '{{response.' in obj:
                obj = self._substitute_response_variables(obj, response_context)
            
            # Handle test data variable substitution
            if '{{subscriber_id}}' in obj:
                obj = obj.replace('{{subscriber_id}}', test_data['subscriber_id'])
            if '{{participant_id}}' in obj:
                obj = obj.replace('{{participant_id}}', test_data['participant_id'])
            if '{{uk_id}}' in obj:
                obj = obj.replace('{{uk_id}}', test_data['uk_id'])
            if '{{request_id}}' in obj:
                obj = obj.replace('{{request_id}}', test_data['request_id'])
            if '{{signing_public_key}}' in obj:
                obj = obj.replace('{{signing_public_key}}', test_data['signing_public_key'])
            if '{{encryption_public_key}}' in obj:
                obj = obj.replace('{{encryption_public_key}}', test_data['encryption_public_key'])
            if '{{valid_from}}' in obj:
                obj = obj.replace('{{valid_from}}', test_data['valid_from'])
            if '{{valid_until}}' in obj:
                obj = obj.replace('{{valid_until}}', test_data['valid_until'])
            if '{{uuid}}' in obj:
                obj = obj.replace('{{uuid}}', str(uuid.uuid4())[:6])
            return obj
        else:
            return obj
    
    def _substitute_response_variables(self, text, response_context):
        """Substitute response variables like {{response.configs[0].config_id}}"""
        import re
        
        # Find all {{response.XXX}} patterns
        pattern = r'\{\{response\.([^}]+)\}\}'
        matches = re.findall(pattern, text)
        
        for match in matches:
            path = match  # e.g., "configs[0].config_id" or "participant.participant_id"
            
            try:
                # Get value from last response using path navigation
                value = self._navigate_response_path(response_context['last_response'], path)
                
                if value is not None:
                    # Replace the variable with the extracted value
                    text = text.replace(f'{{{{response.{match}}}}}', str(value))
                    print(f"[RESPONSE_VAR] Substituted {{{{response.{match}}}}} = {value}")
                else:
                    print(f"[RESPONSE_VAR] Warning: Could not find value for {{{{response.{match}}}}}")
            except Exception as e:
                print(f"[RESPONSE_VAR] Error extracting {{{{response.{match}}}}}: {e}")
        
        return text
    
    def _navigate_response_path(self, data, path):
        """Navigate nested response data using dot notation and array indexing
        
        Examples:
            "participant.participant_id" -> data['participant']['participant_id']
            "configs[0].config_id" -> data['configs'][0]['config_id']
            "data.message.ack.status" -> data['data']['message']['ack']['status']
        """
        import re
        
        # Split path by dots, handling array indices
        parts = re.split(r'\.|(?=\[)', path)
        
        current = data
        for part in parts:
            if not part:
                continue
            
            # Handle array index: [0], [1], etc.
            if part.startswith('['):
                match = re.match(r'\[(\d+)\]', part)
                if match:
                    index = int(match.group(1))
                    if isinstance(current, list) and 0 <= index < len(current):
                        current = current[index]
                    else:
                        return None
            # Handle dictionary key
            else:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return None
        
        return current
    
    def _validate_response(self, test_case, data):
        """Validate response against test case expectations"""
        validations = test_case.get('validate', [])
        
        if not validations:
            return True  # No validations defined, consider success
        
        for validation in validations:
            field = validation.get('field')
            expected_value = validation.get('value')
            
            # Navigate nested fields (e.g., "message.ack.status")
            current = data
            for part in field.split('.'):
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    print(f"[VALIDATION] Field '{field}' not found in response")
                    return False
            
            # Check value
            if current != expected_value:
                print(f"[VALIDATION] Field '{field}': expected '{expected_value}', got '{current}'")
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


# Export tasks for CTF framework
tasks = [ONDCAdminComprehensive]
