from locust import task
from tests.registry.subscribe.common.admin_subscribe_base import AdminSubscribeBase
import yaml
import uuid
import time
import logging
import json
import traceback
from datetime import datetime
from typing import Dict, List, Any

"""
================================================================================
ONDC Policy Gateway Integration Test Suite
================================================================================ Test File:   test_policy_gateway_integration.py
Base Class:  AdminSubscribeBase (admin_subscribe_base.py)
YAML Config: resources/registry/policy/test_policy_gateway_integration.yml

Complete gateway policy testing based on call with Satyendra Kumar (March 28, 2026):
  GW-01 to GW-25: Gateway BG type, Three-layer evaluation, API routing, 
                  Runtime refresh, Payload capture, ROUTE actions, Performance,
                  Complete coverage of all 9 policy combinations

Critical Flow:
  Layer 1: Network Policy (Gateway) → Allow/Block by domain + API
  Layer 2: Buyer Participant Policy → Allow/Not_Allow specific seller
  Layer 3: Seller Participant Policy → Allow/Not_Allow specific buyer
  
Result: ALL THREE layers must allow for request to succeed

Run with: python driver.py --test ondc_policy_gateway_integration --env ondcRegistry --users 1 --iterations 1
================================================================================
"""

class ONDCPolicyGatewayIntegration(AdminSubscribeBase):
    """Gateway-integrated policy test suite for ONDC"""
    
    config_file = 'resources/registry/subscribe/test_subscribe_functional.yml'
    test_cases_file = 'resources/registry/policy/test_policy_gateway_integration.yml'
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
                self.gateway_config = test_config.get('gateway_config', {})
                self.lookup_config = test_config.get('lookup_config', {})
                
                print(f"✅ Loaded {len(self.test_cases)} gateway integration test cases")
                print(f"📋 Test Suite: {self.test_suite_info.get('name', 'Gateway Integration')}")
                print(f"🌐 Gateway URL: {self.gateway_config.get('gateway_url', 'N/A')}")
                
        except FileNotFoundError:
            print(f"❌ Test config file not found: {self.test_cases_file}")
            self.test_cases = []
        except yaml.YAMLError as e:
            print(f"❌ Error parsing YAML config: {e}")
            self.test_cases = []
        
        # Initialize test results storage
        if not hasattr(self.__class__, 'gateway_test_results'):
            self.__class__.gateway_test_results = []
        
        # Initialize saved responses and timestamps
        self.saved_responses = {}
        self.timestamps = {}
        
        # Payload storage for each test
        self.payloads = {}
    
    @task
    def run_gateway_integration_tests(self):
        """Execute all gateway integration test cases"""
        
        if not self.test_cases:
            print("❌ No test cases loaded. Check YAML configuration.")
            return
        
        print(f"\n{'='*80}")
        print(f"🚀 Starting Gateway Integration Test Suite")
        print(f"📊 Total Test Cases: {len(self.test_cases)}")
        print(f"{'='*80}\n")
        
        for test_case in self.test_cases:
            test_id = test_case.get('id', 'UNKNOWN')
            test_name = test_case.get('name', 'Unnamed Test')
            test_description = test_case.get('description', '')
            capture_payload = test_case.get('capture_payload', self.config_info.get('capture_payloads', False))
            measure_time = test_case.get('measure_time', False)
            gateway_api = test_case.get('gateway_api', False)
            
            # Check if test is marked as pending - skip if so
            is_pending = test_case.get('pending', False)
            pending_reason = test_case.get('pending_reason', 'No reason provided')
            
            if is_pending:
                print(f"\n{'─'*80}")
                print(f"⏭️  SKIPPING PENDING TEST: {test_id}")
                print(f"📝 Name: {test_name}")
                print(f"⚠️  Reason: {pending_reason}")
                print(f"{'─'*80}")
                # Record this test as skipped, not failed
                test_result = {
                    'test_id': test_id,
                    'test_name': test_name,
                    'description': test_description,
                    'overall_status': 'SKIPPED',
                    'pending_reason': pending_reason,
                    'start_time': datetime.now().isoformat(),
                    'end_time': datetime.now().isoformat(),
                    'steps': []  # No steps for skipped tests
                }
                self.__class__.gateway_test_results.append(test_result)
                continue
            
            print(f"\n{'─'*80}")
            print(f"🧪 Test Case: {test_id}")
            print(f"📝 Name: {test_name}")
            print(f"📄 Description: {test_description}")
            if capture_payload:
                print(f"📦 Payload Capture: ENABLED")
            if measure_time:
                print(f"⏱️  Time Measurement: ENABLED")
            if gateway_api:
                print(f"🌐 Gateway API Call: TRUE")
            print(f"{'─'*80}")
            
            test_result = {
                'test_id': test_id,
                'test_name': test_name,
                'description': test_description,
                'steps': [],
                'overall_status': 'PASS',
                'start_time': datetime.now().isoformat(),
                'end_time': None,
                'payloads': [] if capture_payload else None,
                'timings': {} if measure_time else None
            }
            
            # Execute test steps
            steps = test_case.get('steps', [])
            for step_idx, step in enumerate(steps, 1):
                step_name = step.get('name', f'Step {step_idx}')
                print(f"\n  ▶️  {step_name}")
                
                step_result = self.execute_gateway_step(
                    step, 
                    test_id, 
                    capture_payload=capture_payload,
                    measure_time=measure_time,
                    gateway_api=gateway_api
                )
                
                step_result['step_number'] = step_idx
                step_result['step_name'] = step_name
                test_result['steps'].append(step_result)
                
                if step_result['status'] == 'FAIL':
                    test_result['overall_status'] = 'FAIL'
                    print(f"  ❌ Step Failed: {step_result.get('message', 'Unknown error')}")
                elif step_result['status'] == 'ACKNOWLEDGED':
                    if test_result['overall_status'] == 'PASS':
                        test_result['overall_status'] = 'ACKNOWLEDGED'
                    print(f"  ⚠️  Step Acknowledged: {step_result.get('message', '')}")
                else:
                    print(f"  ✅ Step Passed")
                
                # Handle wait directive
                wait_time = step.get('wait', 0)
                if wait_time > 0:
                    print(f"  ⏳ Waiting {wait_time}ms...")
                    time.sleep(wait_time / 1000.0)
            
            test_result['end_time'] = datetime.now().isoformat()
            self.__class__.gateway_test_results.append(test_result)
            
            # Log test result
            status_map = {
                'PASS': '✅',
                'ACKNOWLEDGED': '⚠️',
                'SKIPPED': '⏭️',
                'FAIL': '❌'
            }
            status_emoji = status_map.get(test_result['overall_status'], '❓')
            print(f"\n{status_emoji} Test {test_id}: {test_result['overall_status']}")
            
            # Log timing info if measured
            if measure_time and test_result['timings']:
                print(f"⏱️  Timings: {json.dumps(test_result['timings'], indent=2)}")
    
    def execute_gateway_step(self, step: Dict, test_id: str, capture_payload: bool = False, 
                            measure_time: bool = False, gateway_api: bool = False) -> Dict:
        """Execute a single step in a gateway integration test"""
        method = step.get('method', 'GET').upper()
        endpoint = step.get('endpoint', '')
        expected_status = step.get('expected_status', 200)
        data = step.get('data', {})
        params = step.get('params', {})
        validations = step.get('validate', [])
        save_response = step.get('save_response', {})
        record_timestamp = step.get('record_timestamp', None)
        # Don't default gateway_call - we need to know if it was explicitly set
        gateway_call = step.get('gateway_call', None)
        calculate_time_diff = step.get('calculate_time_diff', None)
        
        # Get test case config to check for test-level auth_type and V3 credentials
        test_case = None
        for tc in self.test_cases:
            if tc.get('id') == test_id:
                test_case = tc
                break
        
        # Get auth_type: step-level takes precedence, then test-level, then default to 'admin'
        auth_type = step.get('auth_type')
        if not auth_type and test_case:
            auth_type = test_case.get('auth_type', 'admin')
        elif not auth_type:
            auth_type = 'admin'
        
        # For V3 signature auth, check for test-level credentials
        if auth_type == 'v3_signature' and test_case:
            # Store V3 credentials temporarily for this test
            if 'v3_participant_id' in test_case:
                self._v3_participant_id = test_case['v3_participant_id']
            if 'v3_uk_id' in test_case:
                self._v3_uk_id = test_case['v3_uk_id']
            if 'v3_private_key_seed' in test_case:
                self._v3_private_key_seed = test_case['v3_private_key_seed']
        
        # AGGRESSIVE DEBUG: Print step configuration
        print(f"      🔍 ROUTING DEBUG: test_level_gateway_api={gateway_api}, step_level_gateway_call={gateway_call}, endpoint={endpoint}")
        
        # Convert single expected status to list
        if not isinstance(expected_status, list):
            expected_status = [expected_status]
        
        # Substitute variables in endpoint
        endpoint = self.substitute_variables(endpoint, test_id)
        
        # Substitute variables in data (includes special generators)
        data = self.substitute_dict_variables(data, test_id)
        
        # Substitute variables in params
        params = self.substitute_dict_variables(params, test_id)
        
        step_result = {
            'method': method,
            'endpoint': endpoint,
            'status': 'PASS',
            'message': '',
            'response_data': None,
            'status_code': None,
            'request_payload': None,
            'response_payload': None,
            'execution_time_ms': None
        }
        
        # Handle steps with no endpoint (wait/no-op steps)
        if not endpoint or endpoint == '':
            print(f"      ⏭️  SKIPPING: No endpoint specified (wait step)")
            step_result['message'] = 'No endpoint specified - skipping step'
            return step_result
        
        # Capture request payload if enabled
        if capture_payload and data:
            step_result['request_payload'] = json.dumps(data, indent=2)
        
        try:
            # Record start time
            start_time = time.time()
            
            # Record timestamp if requested
            if record_timestamp:
                self.timestamps[record_timestamp] = datetime.now()
            
            # Determine base URL (gateway vs registry)
            # Step-level gateway_call takes precedence over test-level gateway_api
            print(f"\n      ╔════════════════════════════════════════════════════════════╗")
            print(f"      ║ ROUTING DECISION FOR: {method} {endpoint}")
            print(f"      ║ Test-level gateway_api: {gateway_api}")
            print(f"      ║ Step-level gateway_call: {gateway_call}")
            
            if gateway_call is not None:
                # Step explicitly specifies gateway_call - use that
                use_gateway = gateway_call
                print(f"      ║ DECISION: Using step-level gateway_call={gateway_call}")
            else:
                # No step-level override, use test-level gateway_api
                use_gateway = gateway_api
                print(f"      ║ DECISION: Using test-level gateway_api={gateway_api}")
            
            if use_gateway:
                base_url = self.gateway_config.get('gateway_url', self.host)
                print(f"      ║ RESULT: Gateway URL = {base_url}")
                print(f"      ╚════════════════════════════════════════════════════════════╝")
                print(f"      🌐 Gateway Call: {base_url}{endpoint}\n")
            else:
                base_url = self.host
                print(f"      ║ RESULT: Registry URL = {base_url}")
                print(f"      ╚════════════════════════════════════════════════════════════╝")
                print(f"      🏢 Registry Call: {base_url}{endpoint}\n")
            
            # For POST requests, if params exist but data doesn't, use params as body
            # For /lookup endpoint,  add country field if not present
            if method == 'POST' and params and not data:
                if '/lookup' in endpoint and 'country' not in params:
                    # POST /lookup requires country field (default to IND)
                    params['country'] = 'IND'
                    print(f"      🌏 Added country='IND' to /lookup request")
                data = params
                params = None
                if capture_payload:
                    step_result['request_payload'] = json.dumps(data, indent=2)
            
            # Execute HTTP request
            if method == 'POST':
                response = self.execute_request(base_url, endpoint, method='POST', 
                                               json_data=data, auth_type=auth_type)
            elif method == 'GET':
                response = self.execute_request(base_url, endpoint, method='GET', 
                                               params=params, auth_type=auth_type)
            elif method == 'PATCH':
                response = self.execute_request(base_url, endpoint, method='PATCH', 
                                               json_data=data, auth_type=auth_type)
            elif method == 'PUT':
                response = self.execute_request(base_url, endpoint, method='PUT', 
                                               json_data=data, auth_type=auth_type)
            elif method == 'DELETE':
                response = self.execute_request(base_url, endpoint, method='DELETE', 
                                               auth_type=auth_type)
            else:
                step_result['status'] = 'FAIL'
                step_result['message'] = f"Unsupported HTTP method: {method}"
                return step_result
            
            # Calculate execution time
            execution_time = (time.time() - start_time) * 1000  # Convert to ms
            step_result['execution_time_ms'] = round(execution_time, 2)
            
            if measure_time:
                print(f"      ⏱️  Execution Time: {execution_time:.2f}ms")
            
            step_result['status_code'] = response.status_code
            
            # Parse response
            try:
                response_data = response.json() if response.text else {}
                step_result['response_data'] = response_data
                
                # Capture response payload if enabled
                if capture_payload:
                    step_result['response_payload'] = json.dumps(response_data, indent=2)
            except:
                response_data = {}
                step_result['response_data'] = {'raw_text': response.text[:500]}
                if capture_payload:
                    step_result['response_payload'] = response.text[:500]
            
            # Check status code
            if response.status_code not in expected_status:
                step_result['status'] = 'FAIL'
                step_result['message'] = f"Unexpected status code: {response.status_code} (expected {expected_status})"
                
                # Enhanced error logging for policy creation failures
                if '/admin/policies' in endpoint and method == 'POST':
                    print(f"      ❌ POLICY CREATION FAILED!")
                    print(f"      📊 Status Code: {response.status_code}")
                    if response_data:
                        print(f"      📄 Error Response Body:")
                        print(f"      {json.dumps(response_data, indent=8)}")
                    elif response.text:
                        print(f"      📄 Response Text: {response.text[:300]}")
                    if data:
                        print(f"      📤 Request Payload:")
                        print(f"      {json.dumps(data, indent=8)[:500]}")
                elif response.status_code >= 400:
                    # Log errors for other endpoints too
                    print(f"      ❌ ERROR DETAILS:")
                    print(f"      📊 Status: {response.status_code}")
                    if response_data and 'error' in response_data:
                        print(f"      📄 Error: {json.dumps(response_data['error'], indent=8)}")
                    elif response_data and 'message' in response_data:
                        print(f"      📄 Message: {response_data['message']}")
                    else:
                        print(f"      📄 Response: {step_result['response_payload'][:300]}")
                
                if capture_payload:
                    print(f"      📦 Full Response: {step_result['response_payload'][:400]}")
                return step_result
            
            # Save response fields for later use
            for key, json_path in save_response.items():
                value = self.get_nested_value(response_data, json_path)
                from_request = False
                
                # If value not found in response, try to get from request data
                if value is None and data:
                    value = self.get_nested_value(data, json_path)
                    if value is not None:
                        from_request = True
                
                if value is not None:
                    self.saved_responses[key] = value
                    source = " (from request)" if from_request else ""
                    print(f"      💾 Saved {key} = {value}{source}")
                else:
                    print(f"      ⚠️  Could not save {key}: field '{json_path}' not found in response or request")
            
            # Calculate time difference if requested
            if calculate_time_diff and calculate_time_diff in self.timestamps:
                time_diff = datetime.now() - self.timestamps[calculate_time_diff]
                time_diff_seconds = time_diff.total_seconds()
                print(f"      ⏱️  Time since {calculate_time_diff}: {time_diff_seconds:.2f}s")
                step_result['time_diff_seconds'] = time_diff_seconds
            
            # Validate response
            for validation in validations:
                field = validation.get('field', '')
                condition = validation.get('condition', '')
                expected_value = validation.get('value', None)
                
                actual_value = self.get_nested_value(response_data, field)
                
                validation_result = self.validate_field(actual_value, condition, expected_value, field)
                
                if not validation_result['passed']:
                    step_result['status'] = 'FAIL'
                    step_result['message'] = validation_result['message']
                    return step_result
            
            step_result['message'] = f"Status {response.status_code} OK"
            
        except Exception as e:
            # Handle Locust's RescheduleTask exception differently  
            if type(e).__name__ == 'RescheduleTask':
                # This is Locust rescheduling due to errors- log but don't fail the test
                print(f"\n      ⚠️  Locust RescheduleTask triggered (too many errors in this iteration)")
                print(f"      This usually means the API returned errors (400/500)")
                print(f"      Test will be retried in next iteration")
                # Re-raise to let Locust handle it
                raise
            
            step_result['status'] = 'FAIL'
            # Enhanced exception logging with full details
            exception_type = type(e).__name__
            exception_msg = str(e) if str(e) else "No error message"
            
            # Get full traceback as string
            import sys
            exc_type, exc_value, exc_traceback = sys.exc_info()
            tb_lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
            full_traceback = ''.join(tb_lines)
            
            step_result['message'] = f"Exception: {exception_type}: {exception_msg}"
            
            print(f"\n      ❌❌❌ EXCEPTION IN STEP EXECUTION ❌❌❌")
            print(f"      Exception Type: {exception_type}")
            print(f"      Exception Message: {exception_msg}")
            print(f"      Test ID: {test_id}")
            print(f"      Endpoint: {endpoint}")
            print(f"      Method: {method}")
            print(f"\n      📋 Available Saved Variables:")
            for key, val in self.saved_responses.items():
                print(f"        - {key}: {str(val)[:100]}")
            print(f"\n      📜 Full Traceback:")
            for line in tb_lines[-10:]:  # Show last 10 lines of traceback
                print(f"      {line.rstrip()}")
            print(f"      ❌❌❌ END EXCEPTION ❌❌❌\n")
        
        return step_result
    
    def execute_request(self, base_url: str, endpoint: str, method: str = 'GET', 
                       json_data: Dict = None, params: Dict = None, auth_type: str = 'admin'):
        """Execute HTTP request to either registry or gateway"""
        url = f"{base_url}{endpoint}"
        
        headers = self.get_auth_headers(auth_type, endpoint=endpoint, method=method, data=json_data)
        
        # For V3 signature auth, use the pre-serialized body
        if auth_type == 'v3_signature' and 'serialized_body' in headers:
            serialized_body = headers.pop('serialized_body')
            headers['Content-Type'] = 'application/json'
            
            if method == 'POST':
                response = self.client.post(url, headers=headers, data=serialized_body, name=f"{method} {endpoint}")
            elif method == 'PATCH':
                response = self.client.patch(url, headers=headers, data=serialized_body, name=f"{method} {endpoint}")
            else:
                response = self.client.request(method, url, headers=headers, data=serialized_body, name=f"{method} {endpoint}")
        else:
            headers['Content-Type'] = 'application/json'
            
            if method == 'GET':
                response = self.client.get(url, headers=headers, params=params, name=f"{method} {endpoint}")
            elif method == 'POST':
                response = self.client.post(url, headers=headers, json=json_data, name=f"{method} {endpoint}")
            elif method == 'PATCH':
                response = self.client.patch(url, headers=headers, json=json_data, name=f"{method} {endpoint}")
            elif method == 'PUT':
                response = self.client.put(url, headers=headers, json=json_data, name=f"{method} {endpoint}")
            elif method == 'DELETE':
                response = self.client.delete(url, headers=headers, name=f"{method} {endpoint}")
            else:
                raise ValueError(f"Unsupported method: {method}")
        
        return response
    
    def substitute_variables(self, text: str, test_id: str) -> str:
        """Substitute placeholders like {{timestamp}}, {{uuid}}, {{saved_var}}"""
        if not isinstance(text, str):
            return text
        
        # Substitute timestamp
        if '{{timestamp}}' in text:
            timestamp = int(time.time() * 1000)
            text = text.replace('{{timestamp}}', str(timestamp))
        
        # Substitute ISO timestamp
        if '{{timestamp_iso}}' in text:
            timestamp_iso = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
            text = text.replace('{{timestamp_iso}}', timestamp_iso)
        
        # Substitute UUID
        if '{{uuid}}' in text:
            text = text.replace('{{uuid}}', str(uuid.uuid4()))
        
        # Substitute test_id
        if '{{test_id}}' in text:
            text = text.replace('{{test_id}}', test_id)
        
        # Substitute saved responses
        for key, value in self.saved_responses.items():
            placeholder = f"{{{{{key}}}}}"
            if placeholder in text:
                text = text.replace(placeholder, str(value))
        
        return text
    
    def substitute_dict_variables(self, obj: Any, test_id: str) -> Any:
        """Recursively substitute variables in dictionaries and lists"""
        if isinstance(obj, dict):
            return {k: self.substitute_dict_variables(v, test_id) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.substitute_dict_variables(item, test_id) for item in obj]
        elif isinstance(obj, str):
            # Handle special generators
            if obj == "{{generate_100_rules}}":
                return self.generate_policy_rules(100)
            elif obj == "{{generate_500_rules}}":
                return self.generate_policy_rules(500)
            elif obj == "{{generate_1200_rules}}":
                return self.generate_policy_rules(1200)
            else:
                return self.substitute_variables(obj, test_id)
        else:
            return obj
    
    def generate_policy_rules(self, count: int) -> List[Dict]:
        """Generate N policy rules for performance testing"""
        domains = ["ONDC:RET10", "ONDC:RET11", "ONDC:RET12", "ONDC:FIS12", "ONDC:LOG10"]
        actions = ["search", "on_search", "select", "on_select", "init", "on_init", 
                  "confirm", "on_confirm", "status", "on_status"]
        action_types = ["BROADCAST", "BLOCK", "ROUTE"]
        
        rules = []
        for i in range(count):
            domain = domains[i % len(domains)]
            action = actions[i % len(actions)]
            action_type = action_types[i % len(action_types)]
            
            rule = {
                "id": f"PERF-RULE-{i+1:04d}",
                "description": f"Performance test rule {i+1}",
                "priority": 100,
                "status": "ENABLED",
                "match_condition": {
                    "domain": domain,
                    "action": action
                },
                "action_to_take": {
                    "action_type": action_type
                }
            }
            rules.append(rule)
        
        return rules
    
    def get_nested_value(self, data: Any, path: str) -> Any:
        """Get value from nested dict/list using dot notation"""
        if not path:
            return data
        
        try:
            parts = path.split('.')
            current = data
            
            for part in parts:
                # Handle array indexing
                if '[' in part and ']' in part:
                    key = part[:part.index('[')]
                    index = int(part[part.index('[')+1:part.index(']')])
                    
                    # If key is empty, current is already an array
                    if key == '':
                        current = current[index]
                    else:
                        current = current[key][index]
                # Handle .length property
                elif part == 'length' and isinstance(current, list):
                    return len(current)
                else:
                    current = current[part]
            
            return current
        except (KeyError, IndexError, TypeError):
            return None
    
    def validate_field(self, actual_value: Any, condition: str, expected_value: Any, field_name: str) -> Dict:
        """Validate a field against a condition"""
        result = {'passed': True, 'message': ''}
        
        if condition == 'exists':
            if actual_value is None:
                result['passed'] = False
                result['message'] = f"Field '{field_name}' does not exist"
        
        elif condition == 'equals':
            if actual_value != expected_value:
                result['passed'] = False
                result['message'] = f"Field '{field_name}' is '{actual_value}', expected '{expected_value}'"
        
        elif condition == 'contains':
            if expected_value not in str(actual_value):
                result['passed'] = False
                result['message'] = f"Field '{field_name}' does not contain '{expected_value}'"
        
        elif condition == 'is_array':
            if not isinstance(actual_value, list):
                result['passed'] = False
                result['message'] = f"Field '{field_name}' is not an array"
        
        elif condition == 'greater_than':
            if actual_value <= expected_value:
                result['passed'] = False
                result['message'] = f"Field '{field_name}' ({actual_value}) is not greater than {expected_value}"
        
        return result
    
    def get_auth_headers(self, auth_type: str = 'admin', endpoint: str = '', method: str = 'GET', data: Dict = None) -> Dict:
        """Get authentication headers"""
        if auth_type == 'admin':
            token = self.get_admin_token()
            print(f"      🔑 Using admin token: {token[:50]}..." if token and len(token) > 50 else f"      ⚠️  Admin token: {token}")
            return {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
        elif auth_type == 'v3_signature':
            # Use ED25519 signature authentication for V3 endpoints
            try:
                from tests.utils.ondc_auth_helper import ONDCAuthHelper
                
                # Use test-level V3 credentials if available, otherwise fall back to config
                participant_id = getattr(self, '_v3_participant_id', None) or self.config.get('participant_id', 'buyer.ondc.zionmart.in')
                uk_id = getattr(self, '_v3_uk_id', None) or self.config.get('uk_id', '6c939b20-35ac-4102-9c53-ec8b1b60139d')
                private_key_hex = getattr(self, '_v3_private_key_seed', None) or self.config.get('private_key_seed', '06fb9cb9daa3234a165a0307629e45fc2c1a8b30b0bbb273142deab42a17803f')
                
                # Convert hex to bytes
                private_key_bytes = bytes.fromhex(private_key_hex)
                
                # Initialize auth helper
                auth_helper = ONDCAuthHelper(
                    participant_id=participant_id,
                    uk_id=uk_id,
                    private_key_seed=private_key_bytes
                )
                
                # Generate signature headers
                headers = auth_helper.generate_headers(
                    payload=data if data else {},
                    ttl=300,
                    include_digest=True
                )
                
                print(f"      🔐 Using ED25519 signature auth: {participant_id}")
                return headers
                
            except Exception as e:
                print(f"      ❌ Failed to generate ED25519 signature: {e}")
                import traceback
                traceback.print_exc()
                return {'Content-Type': 'application/json'}
        elif auth_type == 'subscribe':
            # For subscribe endpoints, might need different auth
            token = self.get_admin_token()
            return {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
        return {'Content-Type': 'application/json'}
    
    def get_admin_token(self) -> str:
        """Get admin JWT token"""
        # Try auth_client first (from base class)
        if hasattr(self, 'auth_client') and self.auth_client:
            try:
                token = self.auth_client.get_token()
                if token:
                    print(f"      ✅ Got token from auth_client")
                    return token
            except Exception as e:
                print(f"      ⚠️  auth_client.get_token() failed: {e}")
        
        # Try config (from base class)
        if hasattr(self, 'config') and self.config:
            token = self.config.get('admin_token')
            if token:
                print(f"      ✅ Got token from self.config")
                return token
        
        # Try tenant_config (legacy)
        if hasattr(self, 'tenant_config') and self.tenant_config:
            token = self.tenant_config.get('admin_token')
            if token:
                print(f"      ✅ Got token from tenant_config")
                return token
        
        print(f"      ❌ No admin token found!")
        return "admin-token-placeholder"
    
    @classmethod
    def generate_html_report(cls) -> str:
        """Generate comprehensive HTML report with payload and timing details"""
        if not hasattr(cls, 'gateway_test_results') or not cls.gateway_test_results:
            return "<html><body><h1>No test results available</h1></body></html>"
        
        total_tests = len(cls.gateway_test_results)
        passed = sum(1 for r in cls.gateway_test_results if r['overall_status'] == 'PASS')
        acknowledged = sum(1 for r in cls.gateway_test_results if r['overall_status'] == 'ACKNOWLEDGED')
        skipped = sum(1 for r in cls.gateway_test_results if r['overall_status'] == 'SKIPPED')
        failed = sum(1 for r in cls.gateway_test_results if r['overall_status'] == 'FAIL')
        active_tests = total_tests - skipped  # Tests that actually ran
        pass_rate = (passed / active_tests * 100) if active_tests > 0 else 0
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Gateway Integration Test Report</title>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px; }}
                .header h1 {{ margin: 0; font-size: 32px; }}
                .header p {{ margin: 5px 0; opacity: 0.9; }}
                .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
                .stat-card {{ flex: 1; padding: 25px; border-radius: 8px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                .stat-card.total {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }}
                .stat-card.passed {{ background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); color: white; }}
                .stat-card.acknowledged {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; }}
                .stat-card.failed {{ background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); color: white; }}
                .stat-card.skipped {{ background: linear-gradient(135deg, #a8a8a8 0%, #d3d3d3 100%); color: white; }}
                .stat-number {{ font-size: 48px; font-weight: bold; }}
                .stat-label {{ font-size: 14px; text-transform: uppercase; letter-spacing: 1px; }}
                .test-card {{ background-color: white; margin: 20px 0; padding: 25px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                .test-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 2px solid #f0f0f0; padding-bottom: 15px; }}
                .test-id {{ font-size: 20px; font-weight: bold; color: #2c3e50; }}
                .status-badge {{ padding: 8px 20px; border-radius: 20px; font-weight: bold; font-size: 14px; }}
                .status-badge.PASS {{ background-color: #27ae60; color: white; }}
                .status-badge.ACKNOWLEDGED {{ background-color: #f39c12; color: white; }}
                .status-badge.SKIPPED {{ background-color: #95a5a6; color: white; }}
                .status-badge.FAIL {{ background-color: #e74c3c; color: white; }}
                .test-name {{ font-size: 18px; color: #34495e; margin: 10px 0; font-weight: 500; }}
                .test-description {{ color: #7f8c8d; font-size: 15px; margin: 10px 0; }}
                .steps {{ margin-top: 20px; }}
                .step {{ padding: 15px; margin: 10px 0; border-left: 4px solid #bdc3c7; background-color: #f8f9fa; border-radius: 4px; }}
                .step.PASS {{ border-left-color: #27ae60; background-color: #d5f4e6; }}
                .step.FAIL {{ border-left-color: #e74c3c; background-color: #fadbd8; }}
                .step.ACKNOWLEDGED {{ border-left-color: #f39c12; background-color: #fef5e7; }}
                .step-header {{ font-weight: bold; color: #2c3e50; margin-bottom: 8px; }}
                .step-message {{ font-size: 14px; color: #555; margin-top: 8px; }}
                .step-timing {{ font-size: 13px; color: #7f8c8d; font-style: italic; margin-top: 5px; }}
                .payload {{ background-color: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 4px; margin-top: 10px; font-family: 'Courier New', monospace; font-size: 12px; overflow-x: auto; max-height: 300px; overflow-y: auto; }}
                .payload-label {{ font-weight: bold; color: #3498db; margin-bottom: 5px; }}
                .collapsible {{ cursor: pointer; user-select: none; }}
                .collapsible:hover {{ opacity: 0.8; }}
                .collapsible-content {{ display: none; }}
                .collapsible-content.active {{ display: block; }}
            </style>
            <script>
                function toggleCollapsible(id) {{
                    var content = document.getElementById(id);
                    content.classList.toggle('active');
                }}
            </script>
        </head>
        <body>
            <div class="header">
                <h1>🌐 Gateway Integration Test Report</h1>
                <p>Complete Policy Testing: BG Type, Three-Layer Evaluation, API Routing, Runtime Refresh</p>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Pass Rate: {pass_rate:.1f}%</strong> ({passed}/{active_tests} active tests passed)</p>
            </div>
            
            <div class="summary">
                <div class="stat-card total">
                    <div class="stat-number">{total_tests}</div>
                    <div class="stat-label">Total Tests</div>
                </div>
                <div class="stat-card passed">
                    <div class="stat-number">{passed}</div>
                    <div class="stat-label">Passed</div>
                </div>
                <div class="stat-card acknowledged">
                    <div class="stat-number">{acknowledged}</div>
                    <div class="stat-label">Acknowledged</div>
                </div>
                <div class="stat-card skipped">
                    <div class="stat-number">{skipped}</div>
                    <div class="stat-label">Skipped (Pending)</div>
                </div>
                <div class="stat-card failed">
                    <div class="stat-number">{failed}</div>
                    <div class="stat-label">Failed</div>
                </div>
            </div>
            
            <h2>Test Results</h2>
        """
        
        for result in cls.gateway_test_results:
            test_id = result['test_id']
            test_name = result['test_name']
            description = result['description']
            status = result['overall_status']
            steps = result['steps']
            payloads = result.get('payloads', [])
            
            html += f"""
            <div class="test-card">
                <div class="test-header">
                    <span class="test-id">{test_id}</span>
                    <span class="status-badge {status}">{status}</span>
                </div>
                <div class="test-name">{test_name}</div>
                <div class="test-description">{description}</div>
            """
            
            # Handle SKIPPED tests differently - show pending reason
            if status == 'SKIPPED':
                pending_reason = result.get('pending_reason', 'Test marked as pending')
                html += f"""
                <div class="steps">
                    <strong>⏸️ Pending Reason:</strong>
                    <div class="step" style="border-left-color: #95a5a6; background-color: #f0f0f0;">
                        <div class="step-message">{pending_reason}</div>
                    </div>
                </div>
                """
            else:
                # Normal test execution - show steps
                html += """
                <div class="steps">
                    <strong>Steps:</strong>
                """
                
                for idx, step in enumerate(steps):
                    step_num = step['step_number']
                    step_name = step['step_name']
                    step_status = step['status']
                    step_message = step.get('message', '')
                    exec_time = step.get('execution_time_ms', None)
                    request_payload = step.get('request_payload', None)
                    response_payload = step.get('response_payload', None)
                    
                    html += f"""
                        <div class="step {step_status}">
                            <div class="step-header">Step {step_num}: {step_name}</div>
                            <div class="step-message">{step_message}</div>
                    """
                    
                    if exec_time:
                        html += f'<div class="step-timing">⏱️ Execution Time: {exec_time}ms</div>'
                    
                    if request_payload:
                        payload_id = f"req_{test_id}_{idx}"
                        html += f"""
                            <div class="payload-label collapsible" onclick="toggleCollapsible('{payload_id}')">
                                📤 Request Payload (click to toggle)
                            </div>
                            <div id="{payload_id}" class="collapsible-content">
                                <pre class="payload">{request_payload}</pre>
                            </div>
                        """
                    
                    if response_payload:
                        payload_id = f"resp_{test_id}_{idx}"
                        html += f"""
                            <div class="payload-label collapsible" onclick="toggleCollapsible('{payload_id}')">
                                📥 Response Payload (click to toggle)
                            </div>
                            <div id="{payload_id}" class="collapsible-content">
                                <pre class="payload">{response_payload}</pre>
                            </div>
                        """
                    
                    html += '</div>'
                
                html += """
                </div>
                """
            
            html += """
            </div>
            """
        
        html += """
        </body>
        </html>
        """
        
        return html


# Register this test class with Locust
tasks = [ONDCPolicyGatewayIntegration]
