from locust import task
from tests.registry.subscribe.common.admin_subscribe_base import AdminSubscribeBase
import yaml
import uuid
import time
import logging
from datetime import datetime

"""
================================================================================
ONDC Policy Search Combinations Test Suite
================================================================================
Test File:   test_policy_search_combinations.py
Base Class:  AdminSubscribeBase (admin_subscribe_base.py)
YAML Config: resources/registry/policy/test_policy_search_combinations.yml

Tests for Network + Participant policy combinations with /search endpoint:
  PS-01 to PS-15: Network BROADCAST, Participant ALLOW/NOT_ALLOW, Priority, etc.

Based on: Network-Policy 1.json & Participant-Policy.json

Run with: python driver.py --test ondc_policy_search_combinations --env ondcRegistry --users 1 --iterations 1
================================================================================
"""

class ONDCPolicySearchCombinations(AdminSubscribeBase):
    """Policy + Search combinations test suite for ONDC Registry"""
    
    config_file = 'resources/registry/subscribe/test_subscribe_functional.yml'
    test_cases_file = 'resources/registry/policy/test_policy_search_combinations.yml'
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
                
                print(f"✅ Loaded {len(self.test_cases)} policy search combination test cases from {self.test_cases_file}")
                print(f"📋 Test Suite: {self.test_suite_info.get('name', 'Policy Search Combinations')}")
                
        except FileNotFoundError:
            print(f"❌ Test config file not found: {self.test_cases_file}")
            self.test_cases = []
        except yaml.YAMLError as e:
            print(f"❌ Error parsing YAML config: {e}")
            self.test_cases = []
        
        # Initialize test results storage
        if not hasattr(self.__class__, 'policy_search_results'):
            self.__class__.policy_search_results = []
        
        # Initialize saved responses for variable substitution
        self.saved_responses = {}
    
    @task
    def run_policy_search_combination_tests(self):
        """Execute all policy search combination test cases"""
        
        if not self.test_cases:
            print("❌ No test cases loaded. Check YAML configuration.")
            return
        
        print(f"\n{'='*80}")
        print(f"🚀 Starting Policy Search Combinations Test Suite")
        print(f"📊 Total Test Cases: {len(self.test_cases)}")
        print(f"{'='*80}\n")
        
        for test_case in self.test_cases:
            test_id = test_case.get('id', 'UNKNOWN')
            test_name = test_case.get('name', 'Unnamed Test')
            test_description = test_case.get('description', '')
            
            print(f"\n{'─'*80}")
            print(f"🧪 Test Case: {test_id}")
            print(f"📝 Name: {test_name}")
            print(f"📄 Description: {test_description}")
            print(f"{'─'*80}")
            
            test_result = {
                'test_id': test_id,
                'test_name': test_name,
                'description': test_description,
                'steps': [],
                'overall_status': 'PASS',
                'start_time': datetime.now().isoformat(),
                'end_time': None
            }
            
            # Execute test steps
            steps = test_case.get('steps', [])
            for step_idx, step in enumerate(steps, 1):
                step_name = step.get('name', f'Step {step_idx}')
                print(f"\n  ▶️  {step_name}")
                
                step_result = self.execute_policy_search_step(step, test_id)
                step_result['step_number'] = step_idx
                step_result['step_name'] = step_name
                test_result['steps'].append(step_result)
                
                if step_result['status'] == 'FAIL':
                    test_result['overall_status'] = 'FAIL'
                    print(f"  ❌ Step Failed: {step_result.get('message', 'Unknown error')}")
                    # Continue to next steps even if one fails (for comprehensive testing)
                elif step_result['status'] == 'ACKNOWLEDGED':
                    if test_result['overall_status'] == 'PASS':
                        test_result['overall_status'] = 'ACKNOWLEDGED'
                    print(f"  ⚠️  Step Acknowledged: {step_result.get('message', '')}")
                else:
                    print(f"  ✅ Step Passed")
                
                # Small delay between steps
                time.sleep(0.5)
            
            test_result['end_time'] = datetime.now().isoformat()
            self.__class__.policy_search_results.append(test_result)
            
            # Log test result
            status_emoji = "✅" if test_result['overall_status'] == 'PASS' else "⚠️" if test_result['overall_status'] == 'ACKNOWLEDGED' else "❌"
            print(f"\n{status_emoji} Test {test_id}: {test_result['overall_status']}")
    
    def execute_policy_search_step(self, step, test_id):
        """Execute a single step in a policy search test"""
        method = step.get('method', 'GET').upper()
        endpoint = step.get('endpoint', '')
        auth_type = step.get('auth_type', 'admin')
        expected_status = step.get('expected_status', 200)
        data = step.get('data', {})
        params = step.get('params', {})
        validations = step.get('validate', [])
        save_response = step.get('save_response', {})
        
        # Convert single expected status to list
        if not isinstance(expected_status, list):
            expected_status = [expected_status]
        
        # Substitute variables in endpoint
        endpoint = self.substitute_variables(endpoint, test_id)
        
        # Substitute variables in data
        data = self.substitute_dict_variables(data, test_id)
        
        # Substitute variables in params
        params = self.substitute_dict_variables(params, test_id)
        
        step_result = {
            'method': method,
            'endpoint': endpoint,
            'status': 'PASS',
            'message': '',
            'response_data': None,
            'status_code': None
        }
        
        try:
            # Execute HTTP request
            if method == 'POST':
                response = self.execute_admin_request(endpoint, method='POST', json_data=data, auth_type=auth_type)
            elif method == 'GET':
                response = self.execute_admin_request(endpoint, method='GET', params=params, auth_type=auth_type)
            elif method == 'PATCH':
                response = self.execute_admin_request(endpoint, method='PATCH', json_data=data, auth_type=auth_type)
            elif method == 'PUT':
                response = self.execute_admin_request(endpoint, method='PUT', json_data=data, auth_type=auth_type)
            elif method == 'DELETE':
                response = self.execute_admin_request(endpoint, method='DELETE', auth_type=auth_type)
            else:
                step_result['status'] = 'FAIL'
                step_result['message'] = f"Unsupported HTTP method: {method}"
                return step_result
            
            step_result['status_code'] = response.status_code
            
            # Parse response
            try:
                response_data = response.json() if response.text else {}
                step_result['response_data'] = response_data
            except:
                response_data = {}
                step_result['response_data'] = {'raw_text': response.text[:500]}
            
            # Check status code
            if response.status_code not in expected_status:
                step_result['status'] = 'FAIL'
                step_result['message'] = f"Unexpected status code: {response.status_code} (expected {expected_status})"
                return step_result
            
            # Save response fields for later use
            for key, json_path in save_response.items():
                value = self.get_nested_value(response_data, json_path)
                if value is not None:
                    self.saved_responses[key] = value
                    print(f"      💾 Saved {key} = {value}")
            
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
            step_result['status'] = 'FAIL'
            step_result['message'] = f"Exception: {str(e)}"
            print(f"Exception in step execution: {e}")
        
        return step_result
    
    def substitute_variables(self, text, test_id):
        """Substitute placeholders like {{timestamp}} and {{saved_var}} in text"""
        if not isinstance(text, str):
            return text
        
        # Substitute timestamp
        if '{{timestamp}}' in text:
            timestamp = int(time.time() * 1000)
            text = text.replace('{{timestamp}}', str(timestamp))
        
        # Substitute test_id
        if '{{test_id}}' in text:
            text = text.replace('{{test_id}}', test_id)
        
        # Substitute saved responses
        for key, value in self.saved_responses.items():
            placeholder = f"{{{{{key}}}}}"
            if placeholder in text:
                text = text.replace(placeholder, str(value))
        
        return text
    
    def substitute_dict_variables(self, obj, test_id):
        """Recursively substitute variables in dictionaries and lists"""
        if isinstance(obj, dict):
            return {k: self.substitute_dict_variables(v, test_id) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.substitute_dict_variables(item, test_id) for item in obj]
        elif isinstance(obj, str):
            return self.substitute_variables(obj, test_id)
        else:
            return obj
    
    def get_nested_value(self, data, path):
        """Get value from nested dict/list using dot notation (e.g., 'policies[0].policy_id')"""
        if not path:
            return data
        
        try:
            parts = path.split('.')
            current = data
            
            for part in parts:
                # Handle array indexing like 'rules[0]'
                if '[' in part and ']' in part:
                    key = part[:part.index('[')]
                    index = int(part[part.index('[')+1:part.index(']')])
                    current = current[key][index]
                else:
                    current = current[part]
            
            return current
        except (KeyError, IndexError, TypeError):
            return None
    
    def validate_field(self, actual_value, condition, expected_value, field_name):
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
    
    def execute_admin_request(self, endpoint, method='GET', json_data=None, params=None, auth_type='admin'):
        """Execute an admin API request with proper authentication"""
        base_url = self.host
        url = f"{base_url}{endpoint}"
        
        headers = self.get_auth_headers(auth_type)
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
    
    def get_auth_headers(self, auth_type='admin'):
        """Get authentication headers"""
        if auth_type == 'admin':
            return {
                'Authorization': f'Bearer {self.get_admin_token()}',
                'Content-Type': 'application/json'
            }
        return {'Content-Type': 'application/json'}
    
    def get_admin_token(self):
        """Get admin JWT token from auth client"""
        return self.auth_client.get_token()
    
    @classmethod
    def generate_html_report(cls):
        """Generate HTML report for policy search combination test results"""
        if not hasattr(cls, 'policy_search_results') or not cls.policy_search_results:
            return "<html><body><h1>No test results available</h1></body></html>"
        
        total_tests = len(cls.policy_search_results)
        passed = sum(1 for r in cls.policy_search_results if r['overall_status'] == 'PASS')
        acknowledged = sum(1 for r in cls.policy_search_results if r['overall_status'] == 'ACKNOWLEDGED')
        failed = sum(1 for r in cls.policy_search_results if r['overall_status'] == 'FAIL')
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Policy Search Combinations Test Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
                .stat-card {{ flex: 1; padding: 20px; border-radius: 5px; text-align: center; }}
                .stat-card.total {{ background-color: #3498db; color: white; }}
                .stat-card.passed {{ background-color: #27ae60; color: white; }}
                .stat-card.acknowledged {{ background-color: #f39c12; color: white; }}
                .stat-card.failed {{ background-color: #e74c3c; color: white; }}
                .stat-number {{ font-size: 48px; font-weight: bold; }}
                .stat-label {{ font-size: 14px; text-transform: uppercase; }}
                .test-card {{ background-color: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .test-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
                .test-id {{ font-size: 18px; font-weight: bold; color: #2c3e50; }}
                .status-badge {{ padding: 5px 15px; border-radius: 3px; font-weight: bold; }}
                .status-badge.PASS {{ background-color: #27ae60; color: white; }}
                .status-badge.ACKNOWLEDGED {{ background-color: #f39c12; color: white; }}
                .status-badge.FAIL {{ background-color: #e74c3c; color: white; }}
                .test-name {{ font-size: 16px; color: #34495e; margin: 10px 0; }}
                .test-description {{ color: #7f8c8d; font-size: 14px; margin: 10px 0; }}
                .steps {{ margin-top: 15px; }}
                .step {{ padding: 10px; margin: 5px 0; border-left: 3px solid #bdc3c7; background-color: #ecf0f1; }}
                .step.PASS {{ border-left-color: #27ae60; }}
                .step.FAIL {{ border-left-color: #e74c3c; background-color: #fadbd8; }}
                .step.ACKNOWLEDGED {{ border-left-color: #f39c12; background-color: #fef5e7; }}
                .step-number {{ font-weight: bold; color: #2c3e50; }}
                .step-message {{ font-size: 13px; color: #555; margin-top: 5px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔍 Policy Search Combinations Test Report</h1>
                <p>Network + Participant Policy Testing with /search endpoint</p>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
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
                <div class="stat-card failed">
                    <div class="stat-number">{failed}</div>
                    <div class="stat-label">Failed</div>
                </div>
            </div>
            
            <h2>Test Results</h2>
        """
        
        for result in cls.policy_search_results:
            test_id = result['test_id']
            test_name = result['test_name']
            description = result['description']
            status = result['overall_status']
            steps = result['steps']
            
            html += f"""
            <div class="test-card">
                <div class="test-header">
                    <span class="test-id">{test_id}</span>
                    <span class="status-badge {status}">{status}</span>
                </div>
                <div class="test-name">{test_name}</div>
                <div class="test-description">{description}</div>
                <div class="steps">
                    <strong>Steps:</strong>
            """
            
            for step in steps:
                step_num = step['step_number']
                step_name = step['step_name']
                step_status = step['status']
                step_message = step.get('message', '')
                
                html += f"""
                    <div class="step {step_status}">
                        <span class="step-number">Step {step_num}:</span> {step_name}
                        <div class="step-message">{step_message}</div>
                    </div>
                """
            
            html += """
                </div>
            </div>
            """
        
        html += """
        </body>
        </html>
        """
        
        return html

# Register the test class with Common Test Foundation
tasks = [ONDCPolicySearchCombinations]
