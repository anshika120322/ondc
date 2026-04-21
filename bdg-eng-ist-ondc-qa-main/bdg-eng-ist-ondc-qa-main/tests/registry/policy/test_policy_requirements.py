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
ONDC Policy Requirements Test Suite
================================================================================
Test File:   test_policy_requirements.py
Base Class:  AdminSubscribeBase (admin_subscribe_base.py)
YAML Config: resources/registry/policy/test_policy_requirements.yml

Tests for specific policy requirements:
  REQ-01: SYSTEM policy enforces mandatory fields during subscribe
  REQ-02: FILTER policy restricts lookup results
  REQ-03: Admin can update policy rules (rule_definition)
  REQ-04: Admin can deactivate policy and verify enforcement
  REQ-05: Policy JSON normalization handles deeply nested structures

Run with: python driver.py --test ondc_policy_requirements --env ondcRegistry --users 1 --iterations 1
================================================================================
"""

class ONDCPolicyRequirements(AdminSubscribeBase):
    """Policy requirements test suite for ONDC Registry"""
    
    config_file = 'resources/registry/subscribe/test_subscribe_functional.yml'
    test_cases_file = 'resources/registry/policy/test_policy_requirements.yml'
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
            
            # Track created resources for cleanup
            self.created_participants = []
            self.created_policies = []
            
        except Exception as e:
            print(f"[ERROR] Failed to load test cases from YAML: {e}")
            import traceback
            traceback.print_exc()
            self.test_cases = []
    
    def on_stop(self):
        """Display test summary and generate custom HTML report"""
        super().on_stop()
        
        if not self.test_results:
            return
        
        # Display summary table
        print("\n" + "="*100)
        print("POLICY REQUIREMENTS TEST RESULTS SUMMARY")
        print("="*100)
        
        passed = sum(1 for r in self.test_results if r['status'] == 'PASS')
        failed = sum(1 for r in self.test_results if r['status'] == 'FAIL')
        skipped = sum(1 for r in self.test_results if r['status'] == 'SKIP')
        acknowledged = sum(1 for r in self.test_results if r['status'] == 'ACKNOWLEDGED')
        
        total = len(self.test_results)
        pass_rate = (passed / total * 100) if total > 0 else 0
        
        print(f"Total: {total} | Passed: {passed} | Failed: {failed} | Acknowledged: {acknowledged} | Skipped: {skipped}")
        print(f"Pass Rate: {pass_rate:.1f}%")
        print("-"*100)
        
        for result in self.test_results:
            status_icon = {
                'PASS': '✅ [PASS]',
                'FAIL': '❌ [FAIL]',
                'SKIP': '⏭️  [SKIP]',
                'ACKNOWLEDGED': '⚠️  [ACK]'
            }.get(result['status'], '?')
            
            print(f"{status_icon} {result['test_id']:8} | {result['test_name']:65} | {result['message']}")
        
        print("="*100)
        
        # Generate custom HTML report
        self._generate_custom_html_report()
    
    def _generate_custom_html_report(self):
        """Generate a custom HTML report with all test case results"""
        import os
        
        try:
            # Ensure results directory exists
            os.makedirs('results', exist_ok=True)
            
            # Count results by status
            passed = sum(1 for r in self.test_results if r['status'] == 'PASS')
            failed = sum(1 for r in self.test_results if r['status'] == 'FAIL')
            skipped = sum(1 for r in self.test_results if r['status'] == 'SKIP')
            acknowledged = sum(1 for r in self.test_results if r['status'] == 'ACKNOWLEDGED')
            total = len(self.test_results)
            pass_rate = (passed / total * 100) if total > 0 else 0
            
            # Build HTML
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Policy Requirements Test Results</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f8f9fa; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
        .stat-value {{ font-size: 28px; font-weight: bold; margin-bottom: 5px; }}
        .stat-label {{ color: #6c757d; font-size: 14px; }}
        .test-table {{ background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden; }}
        .test-row {{ transition: background-color 0.2s; }}
        .test-row:hover {{ background-color: #f8f9fa; }}
        .badge {{ font-size: 12px; padding: 6px 12px; }}
        .filter-buttons {{ margin-bottom: 20px; }}
        .status-PASS {{ border-left: 4px solid #28a745; }}
        .status-FAIL {{ border-left: 4px solid #dc3545; }}
        .status-ACKNOWLEDGED {{ border-left: 4px solid #ffc107; }}
        .status-SKIP {{ border-left: 4px solid #6c757d; }}
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="header">
            <h1>🔍 Policy Requirements Test Results</h1>
            <p class="mb-0">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value text-primary">{total}</div>
                <div class="stat-label">Total Tests</div>
            </div>
            <div class="stat-card">
                <div class="stat-value text-success">{passed}</div>
                <div class="stat-label">Passed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value text-danger">{failed}</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value text-warning">{acknowledged}</div>
                <div class="stat-label">Acknowledged</div>
            </div>
            <div class="stat-card">
                <div class="stat-value text-secondary">{skipped}</div>
                <div class="stat-label">Skipped</div>
            </div>
            <div class="stat-card">
                <div class="stat-value text-info">{pass_rate:.1f}%</div>
                <div class="stat-label">Pass Rate</div>
            </div>
        </div>
        
        <div class="filter-buttons">
            <button class="btn btn-sm btn-outline-primary active" onclick="filterTests('all')">All</button>
            <button class="btn btn-sm btn-outline-success" onclick="filterTests('PASS')">Passed</button>
            <button class="btn btn-sm btn-outline-danger" onclick="filterTests('FAIL')">Failed</button>
            <button class="btn btn-sm btn-outline-warning" onclick="filterTests('ACKNOWLEDGED')">Acknowledged</button>
            <button class="btn btn-sm btn-outline-secondary" onclick="filterTests('SKIP')">Skipped</button>
        </div>
        
        <div class="test-table">
            <table class="table table-hover mb-0">
                <thead class="table-light">
                    <tr>
                        <th style="width: 5%">#</th>
                        <th style="width: 10%">Test ID</th>
                        <th style="width: 35%">Test Name</th>
                        <th style="width: 10%">Status</th>
                        <th style="width: 40%">Message</th>
                    </tr>
                </thead>
                <tbody>
"""
            
            # Add test rows
            for idx, result in enumerate(self.test_results, 1):
                status = result['status']
                badge_class = {
                    'PASS': 'bg-success',
                    'FAIL': 'bg-danger',
                    'ACKNOWLEDGED': 'bg-warning',
                    'SKIP': 'bg-secondary'
                }.get(status, 'bg-secondary')
                
                html_content += f"""
                    <tr class="test-row status-{status}" data-status="{status}">
                        <td>{idx}</td>
                        <td><code>{result['test_id']}</code></td>
                        <td>{result['test_name']}</td>
                        <td><span class="badge {badge_class}">{status}</span></td>
                        <td><small>{result['message']}</small></td>
                    </tr>
"""
            
            html_content += """
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        function filterTests(status) {
            const rows = document.querySelectorAll('.test-row');
            const buttons = document.querySelectorAll('.filter-buttons button');
            
            // Update active button
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            // Filter rows
            rows.forEach(row => {
                if (status === 'all' || row.dataset.status === status) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }
    </script>
</body>
</html>
"""
            
            # Write to file
            report_path = 'results/policy_requirements_test_results.html'
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"\n[INFO] Custom HTML report generated: {report_path}")
            print(f"[INFO] Report contains all {total} test case results")
            
        except Exception as e:
            print(f"[ERROR] Failed to generate HTML report: {e}")
            import traceback
            traceback.print_exc()
    
    def _record_test_result(self, test_id, test_name, status, message=""):
        """Record test result for summary display"""
        self.test_results.append({
            'test_id': test_id,
            'test_name': test_name,
            'status': status,
            'message': message
        })
    
    # ==========================================
    # YAML Test Execution
    # ==========================================
    
    @task
    def run_yaml_tests(self):
        """Execute all tests defined in YAML configuration"""
        if not self.test_cases:
            print("[ERROR] No test cases loaded from YAML")
            return
        
        print(f"\n{'='*100}")
        print(f"{self.test_suite_info.get('name', 'Policy Requirements Test Suite')}")
        print(f"{'='*100}")
        print(f"Total Tests: {len(self.test_cases)}")
        print(f"{'='*100}\n")
        
        for test_case in self.test_cases:
            self._execute_test_case(test_case)
    
    def _execute_test_case(self, test_case):
        """Execute a single test case from YAML configuration"""
        test_id = test_case.get('id', 'UNKNOWN')
        test_name = test_case.get('name', 'Unnamed Test')
        description = test_case.get('description', '')
        
        self.step_name = f"{test_id}_{test_name.replace(' ', '_')[:50]}"
        
        print(f"\n[{test_id}] >>> {test_name}")
        print(f"[{test_id}] Description: {description}")
        
        try:
            # All tests in this suite are multi-step workflows
            steps = test_case.get('steps', [])
            
            if not steps:
                print(f"[{test_id}] [SKIP] No steps defined")
                self._record_test_result(test_id, test_name, "SKIP", "No steps defined")
                return
            
            # Generate test participant data once for entire workflow
            test_data = self._setup_test_participant()
            
            # Execute workflow
            success = self._execute_workflow_steps(steps, test_data, test_id, test_name)
            
            if success:
                print(f"[{test_id}] ✅ [PASS] Test passed")
                self._record_test_result(test_id, test_name, "PASS", "All steps completed successfully")
            else:
                print(f"[{test_id}] ❌ [FAIL] Test failed")
                self._record_test_result(test_id, test_name, "FAIL", "One or more steps failed")
        
        except Exception as e:
            print(f"[{test_id}] ❌ [FAIL] Exception: {str(e)}")
            import traceback
            traceback.print_exc()
            self._record_test_result(test_id, test_name, "FAIL", f"Exception: {str(e)}")
        
        time.sleep(1)
    
    def _execute_workflow_steps(self, steps, test_data, test_id, test_name):
        """Execute all steps in a workflow"""
        saved_values = {}
        
        for step_idx, step in enumerate(steps):
            step_name = step.get('name', f'Step {step_idx + 1}')
            step_type = step.get('type', 'api')
            
            print(f"[{test_id}] Step {step_idx + 1}/{len(steps)}: {step_name}")
            
            # Execute based on step type
            if step_type == 'lookup':
                success = self._execute_lookup_step(step, test_data, test_id)
            else:
                success, data = self._execute_api_step(step, test_data, step_idx, test_id, saved_values)
                
                # Save response values if specified
                if success and 'save_response' in step:
                    self._save_response_values(step['save_response'], data, saved_values)
            
            # Check step result
            if not success:
                print(f"[{test_id}] ❌ Step '{step_name}' failed")
                return False
        
        return True
    
    def _execute_api_step(self, step, test_data, step_idx, test_id, saved_values):
        """Execute a standard API step"""
        method = step.get('method', 'POST')
        endpoint = step.get('endpoint', '/admin/subscribe')
        expected_status = step.get('expected_status', 200)
        auth_type = step.get('auth_type', 'admin')
        
        # Normalize expected_status to list
        if not isinstance(expected_status, list):
            expected_status = [expected_status]
        
        # Build payload for this step
        payload = self._build_step_payload(step, test_data, saved_values)
        
        # Replace placeholders in endpoint (e.g., /admin/policies/{{policy_id}})
        endpoint = self._replace_placeholders_str(endpoint, saved_values)
        
        # Execute API call
        if method == 'GET':
            query_params = step.get('query_params', {})
            query_params = self._replace_placeholders(query_params, saved_values)
            
            success, data, status_code, response = self._send_admin_get_request(
                f"{test_id}_Step{step_idx+1}",
                endpoint,
                query_params=query_params,
                expected_status=expected_status,
                auth_type=auth_type
            )
        elif method == 'POST':
            if endpoint.startswith('/admin/policies'):
                success, data, status_code, response = self._send_admin_policy_request(
                    f"{test_id}_Step{step_idx+1}",
                    endpoint,
                    payload,
                    expected_status=expected_status,
                    auth_type=auth_type
                )
            else:
                success, data, status_code, response = self._send_admin_subscribe_request(
                    f"{test_id}_Step{step_idx+1}",
                    payload,
                    expected_status=expected_status,
                    auth_type=auth_type
                )
        elif method == 'PATCH':
            success, data, status_code, response = self._send_admin_patch_request(
                f"{test_id}_Step{step_idx+1}",
                endpoint,
                payload,
                expected_status=expected_status
            )
        else:
            print(f"[{test_id}] [FAIL] Unsupported method: {method}")
            return False, {}
        
        # Validate response if step has validation rules
        if success and 'validate' in step:
            if not self._validate_response(step, data, test_data):
                print(f"[{test_id}] Step validation failed")
                return False, data
        
        # Add delay after subscribe to allow sync
        if success and method == 'POST' and endpoint == '/admin/subscribe':
            time.sleep(5)
        
        return success, data
    
    def _execute_lookup_step(self, step, test_data, test_id):
        """Execute a lookup query step"""
        lookup_type = step.get('lookup_type', 'participant_id')
        query = step.get('query', {})
        verify_filter = step.get('verify_filter', {})
        
        # Build lookup payload
        if lookup_type == 'participant_id':
            payload = {
                "participant_id": test_data['participant_id'],
                "country": "IND",
                "type": "BPP"
            }
        elif lookup_type == 'domain':
            payload = {
                "domain": query.get('domain', 'ONDC:RET12'),
                "type": query.get('type', 'BPP'),
                "city": query.get('city', 'std:080'),
                "country": "IND"
            }
        else:
            print(f"[{test_id}] Unknown lookup_type: {lookup_type}")
            return False
        
        # Send lookup request - use the V3 lookup method with proper signature
        try:
            import requests
            import json
            
            lookup_url = f"{self.lookup_host}/lookup"
            headers = {'Content-Type': 'application/json'}
            
            print(f"[{test_id}] Sending lookup request: {payload}")
            response = requests.post(lookup_url, json=payload, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                print(f"[{test_id}] ✅ Lookup successful, returned {len(data) if isinstance(data, list) else 'unknown'} results")
                
                # Verify filtering if specified
                if verify_filter:
                    return self._verify_lookup_filtering(test_id, data, verify_filter, test_data)
                
                return True
            else:
                print(f"[{test_id}] ❌ Lookup failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"[{test_id}] ❌ Lookup exception: {str(e)}")
            return False
    
    def _verify_lookup_filtering(self, test_id, data, verify_filter, test_data):
        """Verify that lookup results are filtered correctly"""
        should_include = verify_filter.get('should_include', [])
        should_exclude = verify_filter.get('should_exclude', [])
        
        # Extract participant IDs from results
        results = data if isinstance(data, list) else []
        result_ids = [r.get('participant_id', '') for r in results]
        
        # Replace placeholders in expected IDs
        should_include = [self._replace_placeholders_str(pid, test_data) for pid in should_include]
        should_exclude = [self._replace_placeholders_str(pid, test_data) for pid in should_exclude]
        
        # Check inclusions
        for expected_id in should_include:
            if expected_id not in result_ids:
                print(f"[{test_id}] ❌ Expected participant '{expected_id}' NOT found in results")
                return False
            print(f"[{test_id}] ✅ Expected participant '{expected_id}' found in results")
        
        # Check exclusions
        for excluded_id in should_exclude:
            if excluded_id in result_ids:
                print(f"[{test_id}] ❌ Unwanted participant '{excluded_id}' found in results (should be filtered)")
                return False
            print(f"[{test_id}] ✅ Participant '{excluded_id}' correctly filtered out")
        
        return True
    
    def _save_response_values(self, save_config, data, saved_values):
        """Save values from response for use in subsequent steps"""
        for key, json_path in save_config.items():
            value = self._extract_json_path(data, json_path)
            if value is not None:
                saved_values[key] = value
                print(f"  → Saved {key} = {value}")
    
    def _extract_json_path(self, data, json_path):
        """Extract value from nested JSON using dot notation"""
        keys = json_path.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        
        return value
    
    def _replace_placeholders_str(self, text, values):
        """Replace {{placeholder}} in string with saved values"""
        if not isinstance(text, str):
            return text
        
        import re
        pattern = r'\{\{([^}]+)\}\}'
        
        def replacer(match):
            key = match.group(1)
            return str(values.get(key, match.group(0)))
        
        return re.sub(pattern, replacer, text)
    
    def _build_step_payload(self, step, test_data, saved_values=None):
        """Build payload for a step, replacing placeholders"""
        if saved_values is None:
            saved_values = {}
        
        data = step.get('data', {})
        payload = copy.deepcopy(data)
        
        # Merge test_data and saved_values for replacements
        all_values = {**test_data, **saved_values}
        
        # Replace placeholders recursively
        payload = self._replace_placeholders(payload, all_values)
        
        return payload
    
    def _send_admin_policy_request(self, step_name, endpoint, payload, expected_status=[201], auth_type='admin'):
        """Send admin POST request to any endpoint (e.g., /admin/policies)"""
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
    
    def _send_admin_get_request(self, step_name, endpoint, query_params=None, expected_status=[200], auth_type='admin'):
        """Send admin GET request to any endpoint with query parameters"""
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
    
    def _send_admin_patch_request(self, step_name, endpoint, payload, expected_status=[200, 204], auth_type='admin'):
        """Send admin PATCH request to /admin/policies endpoint for policy updates"""
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
        
        # Build URL - use provided endpoint
        url = f"{self.host}{endpoint}"
        
        # Make PATCH request
        with self.client.patch(
            url,
            headers=headers,
            json=payload,
            name=f"{step_name}_PATCH_{endpoint}",
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
                print(f"[{step_name}] ✓ PATCH {endpoint} → {status_code}")
                if data:
                    print(f"[{step_name}] Response: {data}")
                return True, data, status_code, response
            else:
                response.failure(f"Expected {expected_status}, got {status_code}")
                print(f"[{step_name}] ✗ PATCH {endpoint} → {status_code} (expected {expected_status})")
                print(f"[{step_name}] Response: {data}")
                return False, data, status_code, response
    
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
                '{{participant_id}}': test_data.get('participant_id', ''),
                '{{subscriber_id}}': test_data.get('participant_id', ''),
                '{{timestamp}}': datetime.now().strftime('%Y%m%d_%H%M%S'),
                '{{uk_id}}': test_data.get('uk_id', ''),
                '{{signing_public_key}}': test_data.get('signing_public_key', ''),
                '{{encryption_public_key}}': test_data.get('encryption_public_key', ''),
                '{{valid_from}}': test_data.get('valid_from', ''),
                '{{valid_until}}': test_data.get('valid_until', ''),
            }
            
            # Also handle saved values (for {{policy_id}}, etc.)
            for key, value in test_data.items():
                placeholder = f'{{{{{key}}}}}'
                if placeholder in obj and value:
                    obj = obj.replace(placeholder, str(value))
            
            # Apply standard replacements
            for placeholder, value in replacements.items():
                if placeholder in obj:
                    obj = obj.replace(placeholder, str(value))
            
            return obj
        else:
            return obj
    
    def _validate_response(self, test_case, data, test_data=None):
        """Validate response against expected values"""
        validations = test_case.get('validate', [])
        
        if not validations:
            return True
        
        for validation in validations:
            field = validation.get('field')
            expected_value = validation.get('value')
            condition = validation.get('condition', 'equals')
            
            # Navigate to field in response
            actual_value = self._get_nested_field(data, field)
            
            # Check condition
            if condition == 'equals':
                if actual_value != expected_value:
                    print(f"[{self.step_name}] Validation failed: {field} = {actual_value}, expected {expected_value}")
                    return False
            elif condition == 'exists':
                if actual_value is None:
                    print(f"[{self.step_name}] Validation failed: {field} does not exist")
                    return False
            elif condition == 'contains':
                if expected_value not in str(actual_value):
                    print(f"[{self.step_name}] Validation failed: {field} ({actual_value}) does not contain '{expected_value}'")
                    return False
            elif condition == 'array_length_gte':
                if not isinstance(actual_value, list) or len(actual_value) < expected_value:
                    print(f"[{self.step_name}] Validation failed: {field} length {len(actual_value) if isinstance(actual_value, list) else 0} < {expected_value}")
                    return False
            elif condition == 'array_length':
                if not isinstance(actual_value, list) or len(actual_value) != expected_value:
                    print(f"[{self.step_name}] Validation failed: {field} length {len(actual_value) if isinstance(actual_value, list) else 0} != {expected_value}")
                    return False
        
        return True
    
    def _get_nested_field(self, obj, field_path):
        """Get nested field value from object using dot notation or array notation"""
        if not field_path:
            return obj
        
        # Handle array notation like [0].field or field[0]
        if '[' in field_path:
            # Split by bracket to handle array indexing
            parts = field_path.replace(']', '').split('[')
            current = parts[0] if parts[0] else None
            
            if current:
                # Navigate to the array first
                obj = obj.get(current) if isinstance(obj, dict) else obj
            
            # Handle array index
            if len(parts) > 1:
                try:
                    index = int(parts[1])
                    if isinstance(obj, list) and len(obj) > index:
                        obj = obj[index]
                        # Handle remaining path after array index
                        if len(parts) > 2:
                            remaining = '.'.join(parts[2:])
                            return self._get_nested_field(obj, remaining)
                        return obj
                except (ValueError, IndexError):
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


# Export tasks for CTF framework
tasks = [ONDCPolicyRequirements]
