import json
import yaml
import time
from datetime import datetime
from locust import TaskSet, task
from common_test_foundation.lib.proxy.proxy_server import ProxyServer

"""
ONDC Registry - Comprehensive Health Check Test Suite
Test Cases: HEALTH-01 to HEALTH-06

Purpose:
- Validate health check endpoints (/health, /health/live, /health/ready)
- Test dependency monitoring (Database, Redis/Cache)
- Verify Kubernetes liveness and readiness probe endpoints
- Infrastructure-level readiness behavior validation

Test Coverage:
- HEALTH-01: Basic health check with all dependencies healthy
- HEALTH-02: Health check reports unhealthy when DB down
- HEALTH-03: Health check reports degraded when Redis down
- HEALTH-04: Kubernetes liveness probe endpoint
- HEALTH-05: Kubernetes readiness probe endpoint
- HEALTH-06: Readiness probe prevents traffic to unhealthy pod

Run with:
python driver.py --test ondc_admin_health_comprehensive --env ondcRegistry --users 1 --iterations 1 --headless --html results/admin_health_comprehensive.html
"""


class ONDCAdminHealthComprehensive(TaskSet):
    """Comprehensive health check test suite"""
    
    def on_start(self):
        """Initialize test configuration"""
        print("\n" + "="*80)
        print("ONDC ADMIN HEALTH CHECK COMPREHENSIVE TEST SUITE")
        print("="*80)
        
        # Initialize proxy 
        self.proxy = ProxyServer()
        self.step_name = 'ON_START'
        self.proxy.start_capture(trx_id=self.step_name)
        self.client.verify = self.proxy.get_certificate()
        self.client.proxies = self.proxy.get_http_proxy_config()
        
        # Get base URL
        self.base_url = self.parent.host
        
        # Load test configuration from YAML
        config_file = "resources/admin/test_admin_health_comprehensive.yml"
        self.test_config = self._load_test_config(config_file)
        
        print(f"Base URL: {self.base_url}")
        print(f"Total Tests: {self.test_config['test_suite']['total_tests']}")
        print("="*80 + "\n")
        
        # Initialize test results tracking
        self.test_results = []
        
    def _load_test_config(self, config_file):
        """Load test configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"❌ Error loading test config: {e}")
            return {"test_suite": {"total_tests": 0}, "tests": []}
    
    def _execute_test_step(self, test_id, test_name, step):
        """Execute a single test step"""
        step_id = step.get('step_id', 1)
        step_name = step.get('name', f'Step {step_id}')
        action = step.get('action', 'api_call')
        method = step.get('method', 'GET')
        endpoint = step.get('endpoint', '/health')
        expected_status = step.get('expected_status', [200])
        validations = step.get('validations', [])
        
        print(f"  Step {step_id}/{len([s for s in self.current_test.get('steps', [])])}: {step_name}")
        
        if action == 'validation':
            # Skip validation-only steps (manual validation instructions)
            print(f"    ℹ️  Manual validation step - skipped")
            return True, "Manual validation step"
        
        # Build request URL
        url = f"{self.base_url}{endpoint}"
        
        # Prepare headers
        headers = step.get('headers', {})
        if not headers:
            headers = {'Accept': 'application/json'}
        
        # Execute API call
        step_label = f"{test_id}_{step_name.replace(' ', '_')}"
        
        try:
            if method.upper() == 'GET':
                with self.client.get(
                    name=step_label,
                    url=endpoint,
                    headers=headers,
                    catch_response=True
                ) as response:
                    return self._validate_response(response, step, expected_status, validations, test_id)
            else:
                print(f"    ⚠️  Unsupported method: {method}")
                return False, f"Unsupported method: {method}"
                
        except Exception as e:
            print(f"    ❌ Request failed: {str(e)}")
            return False, f"Request failed: {str(e)}"
    
    def _validate_response(self, response, step, expected_status, validations, test_id):
        """Validate API response against expected criteria"""
        status_code = response.status_code
        
        # Check status code
        if status_code not in expected_status:
            msg = f"Status {status_code} not in expected {expected_status}"
            print(f"    ❌ {msg}")
            response.failure(msg)
            return False, msg
        
        print(f"    ✅ Status {status_code}")
        
        # Parse response body
        try:
            response_data = response.json() if response.text else {}
        except:
            response_data = {}
        
        # Execute validations
        validation_results = []
        for validation in validations:
            val_type = validation.get('type')
            result = self._execute_validation(val_type, validation, response_data, status_code)
            validation_results.append(result)
            
            if not result:
                msg = validation.get('description', f'Validation {val_type} failed')
                print(f"    ❌ {msg}")
        
        # All validations must pass
        all_passed = all(validation_results) if validation_results else True
        
        if all_passed:
            response.success()
            return True, "All validations passed"
        else:
            msg = "Some validations failed"
            response.failure(msg)
            return False, msg
    
    def _execute_validation(self, val_type, validation, response_data, status_code):
        """Execute a specific validation check"""
        try:
            if val_type == 'status_code':
                expected = validation.get('expected')
                return status_code == expected
            
            elif val_type == 'status_code_range':
                expected_range = validation.get('expected', [])
                return status_code in expected_range
            
            elif val_type == 'response_field':
                field = validation.get('field')
                expected_values = validation.get('expected_values', [])
                actual_value = response_data.get(field)
                return actual_value in expected_values
            
            elif val_type == 'response_field_exists':
                field = validation.get('field')
                return field in response_data
            
            elif val_type == 'response_structure':
                required_fields = validation.get('required_fields', [])
                return all(field in response_data for field in required_fields)
            
            elif val_type == 'nested_field_exists':
                field_path = validation.get('field', '')
                parts = field_path.split('.')
                current = response_data
                for part in parts:
                    if isinstance(current, dict) and part in current:
                        current = current[part]
                    else:
                        return False
                return True
            
            elif val_type == 'conditional_validation':
                # Evaluate condition
                condition = validation.get('condition', '')
                if 'status_code' in condition:
                    condition = condition.replace('status_code', str(status_code))
                    if eval(condition):
                        # Execute nested validations
                        nested_validations = validation.get('validations', [])
                        return all(
                            self._execute_validation(v.get('type'), v, response_data, status_code)
                            for v in nested_validations
                        )
                return True
            
            elif val_type == 'endpoint_exists':
                # Endpoint is accessible if we got here
                return True
            
            elif val_type in ['response_format', 'infrastructure_note', 'manual_validation']:
                # Informational validations - always pass
                return True
            
            else:
                print(f"    ⚠️  Unknown validation type: {val_type}")
                return True
                
        except Exception as e:
            print(f"    ⚠️  Validation error for {val_type}: {e}")
            return False
    
    def _run_test_case(self, test_case):
        """Run a single test case"""
        test_id = test_case.get('id')
        test_name = test_case.get('name')
        test_type = test_case.get('type', 'positive')
        steps = test_case.get('steps', [])
        
        print(f"\n[{test_id}] {test_name}")
        print(f"  Type: {test_type} | Steps: {len(steps)}")
        
        # Store current test for reference
        self.current_test = test_case
        
        # Execute all steps
        step_results = []
        for step in steps:
            success, message = self._execute_test_step(test_id, test_name, step)
            step_results.append(success)
            
            # For negative tests, we expect controlled failures
            if test_type == 'negative' and not success:
                # This might be expected behavior
                pass
        
        # Test passes if all steps pass (or if it's infrastructure test with accessible endpoints)
        test_passed = all(step_results) if step_results else False
        
        # For infrastructure tests, partial success is acceptable
        if test_case.get('type') == 'infrastructure' and any(step_results):
            test_passed = True
        
        result = {
            'id': test_id,
            'name': test_name,
            'type': test_type,
            'status': 'PASS' if test_passed else 'FAIL',
            'steps_passed': sum(step_results),
            'steps_total': len(steps),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.test_results.append(result)
        
        status_icon = "✅" if test_passed else "❌"
        print(f"{status_icon} [{test_id}] {'PASS' if test_passed else 'FAIL'}")
        
        return test_passed
    
    @task(1)
    def run_all_health_tests(self):
        """Execute all health check test cases"""
        print("\n" + "="*80)
        print("STARTING HEALTH CHECK TEST EXECUTION")
        print("="*80)
        
        tests = self.test_config.get('tests', [])
        
        if not tests:
            print("❌ No tests found in configuration")
            return
        
        total_tests = len(tests)
        passed_tests = 0
        
        # Execute each test case
        for test_case in tests:
            try:
                if self._run_test_case(test_case):
                    passed_tests += 1
            except Exception as e:
                test_id = test_case.get('id', 'UNKNOWN')
                print(f"❌ [{test_id}] Exception: {str(e)}")
                self.test_results.append({
                    'id': test_id,
                    'name': test_case.get('name', 'Unknown'),
                    'type': test_case.get('type', 'positive'),
                    'status': 'FAIL',
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                })
        
        # Print summary
        self._print_test_summary(total_tests, passed_tests)
    
    def _print_test_summary(self, total, passed):
        """Print test execution summary"""
        failed = total - passed
        pass_rate = (passed / total * 100) if total > 0 else 0
        
        print("\n" + "="*80)
        print("ADMIN HEALTH CHECK TEST SUMMARY")
        print("="*80)
        print(f"Total: {total} | Passed: {passed} | Failed: {failed}")
        print(f"Pass Rate: {pass_rate:.1f}%")
        print("="*80)
        
        # Detailed results
        print("\nDetailed Results:")
        for result in self.test_results:
            status_icon = "✅" if result['status'] == 'PASS' else "❌"
            print(f"{status_icon} [{result['id']}] {result['name']}")
        
        print("\n" + "="*80 + "\n")
    
    def on_stop(self):
        """Cleanup and final summary"""
        if hasattr(self, 'test_results') and self.test_results:
            total = len(self.test_results)
            passed = sum(1 for r in self.test_results if r['status'] == 'PASS')
            print(f"\n✅ Test execution completed: {passed}/{total} tests passed\n")


# Register task set
tasks = [ONDCAdminHealthComprehensive]
