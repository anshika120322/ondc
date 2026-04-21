"""
Base Test Runner

Abstract base class for all test runners with common functionality.
"""

import yaml
import json
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from ..utils.http_client import HTTPClient
from ..utils.data_generator import DataGenerator
from ..utils.state_manager import StateManager
from ..utils.html_reporter import HTMLReporter


class TestResult:
    """Container for test execution result."""
    
    def __init__(self, test_id: str, name: str):
        self.test_id = test_id
        self.name = name
        self.passed = False
        self.status_code = None
        self.expected_status = None
        self.response_body = None
        self.error_message = None
        self.execution_time_ms = 0
        self.timestamp = datetime.now().isoformat()
        self.validations = []
        
        # Complete request/response details
        self.request_details = []
        self.response_details = []
        
        # ONDC key pair used in this test (populated for V3 auth tests)
        self.ondc_key_info = None
        
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "test_id": self.test_id,
            "name": self.name,
            "passed": self.passed,
            "status_code": self.status_code,
            "expected_status": self.expected_status,
            "error_message": self.error_message,
            "execution_time_ms": self.execution_time_ms,
            "timestamp": self.timestamp,
            "validations": self.validations,
            "response_body": self.response_body if not self.passed else None,
            "request_details": self.request_details,
            "response_details": self.response_details,
            "ondc_key_info": self.ondc_key_info
        }


class BaseTestRunner(ABC):
    """
    Abstract base class for test runners.
    
    Provides common functionality for:
    - Loading test configurations
    - HTTP client management
    - Test execution flow
    - Result tracking
    - Data generation
    """
    
    def __init__(self, config_file: str, base_url: str, test_ids: Optional[List[str]] = None, optional_mode: str = 'skip',
                 auth_url: Optional[str] = None, admin_username: str = "admin", admin_password: str = "admin123",
                 username_field: str = "username", password_field: str = "password",
                 token_field: str = "access_token", session_id: Optional[str] = None,
                 ssl_verify: bool = True):
        """
        Initialize test runner.
        
        Args:
            config_file: Path to YAML test configuration file
            base_url: Base URL of the API (required, no default)
            test_ids: Optional list of test IDs to run (supports ranges like 'V01-V05')
            optional_mode: How to handle optional tests - 'skip', 'include', or 'only'
            auth_url: Optional external auth service login URL
            admin_username: Admin username/email value
            admin_password: Admin password value
            username_field: Payload key for username credential (e.g. "email")
            password_field: Payload key for password credential
            token_field: Key name for the token in the login response (e.g. "accessToken")
        """
        self.config_file = config_file
        self.base_url = base_url
        self.client = HTTPClient(base_url, admin_username, admin_password,
                                 auth_url=auth_url,
                                 username_field=username_field,
                                 password_field=password_field,
                                 token_field=token_field,
                                 ssl_verify=ssl_verify)
        self.test_ids = test_ids
        self.optional_mode = optional_mode
        
        # Generate unique session ID for this test run (or use supplied shared one)
        import random
        import string
        self.session_id = session_id if session_id else ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        self.data_gen = DataGenerator()
        self.state_mgr = StateManager()
        self.config = None
        self.tests = []
        self.results = []
        
    def load_config(self) -> bool:
        """
        Load test configuration from YAML file.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
            
            all_tests = self.config.get('tests', [])
            print(f"[OK] Loaded {len(all_tests)} tests from {self.config_file}")
            
            # Apply filters
            self.tests = self._filter_tests(all_tests)
            
            if len(self.tests) < len(all_tests):
                print(f"[INFO] Filtered to {len(self.tests)} tests based on criteria")
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Error loading config: {e}")
            return False
    
    def _filter_tests(self, all_tests: List[Dict]) -> List[Dict]:
        """
        Filter tests based on test IDs and optional mode.
        
        Args:
            all_tests: All tests from configuration
            
        Returns:
            Filtered list of tests
        """
        filtered = all_tests
        
        # Filter by test IDs if specified
        if self.test_ids:
            expanded_ids = self._expand_test_ids(self.test_ids)
            filtered = [t for t in filtered if t.get('id') in expanded_ids]
            if not filtered:
                print(f"[WARNING] No tests matched IDs: {self.test_ids}")
        
        # Filter by optional status
        if self.optional_mode == 'skip':
            # Skip optional tests (default behavior)
            filtered = [t for t in filtered if not t.get('optional', False)]
        elif self.optional_mode == 'only':
            # Run only optional tests
            filtered = [t for t in filtered if t.get('optional', False)]
        # 'include' mode: no filtering, run all
        
        return filtered
    
    def _expand_test_ids(self, test_ids: List[str]) -> set:
        """
        Expand test ID patterns including ranges.
        
        Examples:
            ['V01', 'V02'] -> {'V01', 'V02'}
            ['V01-V05'] -> {'V01', 'V02', 'V03', 'V04', 'V05'}
            ['A01-A03', 'V10'] -> {'A01', 'A02', 'A03', 'V10'}
        
        Args:
            test_ids: List of test ID patterns
            
        Returns:
            Set of expanded test IDs
        """
        expanded = set()
        
        for pattern in test_ids:
            if '-' in pattern and pattern.count('-') == 1:
                # Range pattern (e.g., 'V01-V05')
                try:
                    start, end = pattern.split('-')
                    # Extract prefix and numbers
                    prefix_start = ''.join(c for c in start if not c.isdigit())
                    prefix_end = ''.join(c for c in end if not c.isdigit())
                    
                    if prefix_start != prefix_end:
                        print(f"[WARNING] Invalid range '{pattern}': prefixes don't match")
                        expanded.add(pattern)
                        continue
                    
                    num_start = int(''.join(c for c in start if c.isdigit()))
                    num_end = int(''.join(c for c in end if c.isdigit()))
                    num_width = len(''.join(c for c in start if c.isdigit()))
                    
                    # Generate range
                    for i in range(num_start, num_end + 1):
                        expanded.add(f"{prefix_start}{i:0{num_width}d}")
                        
                except (ValueError, IndexError) as e:
                    print(f"[WARNING] Invalid range pattern '{pattern}': {e}")
                    expanded.add(pattern)
            else:
                # Single test ID
                expanded.add(pattern)
        
        return expanded
    
    def execute_test(self, test: Dict) -> TestResult:
        """
        Execute a single test.
        
        Args:
            test: Test configuration dictionary
            
        Returns:
            TestResult object
        """
        result = TestResult(test['id'], test['name'])
        start_time = time.time()
        
        try:
            # Check for batch execution
            batch_size = test.get('batch_size', 1)
            
            if batch_size > 1:
                # Execute batch test
                success = self._execute_batch_test(test, result, batch_size)
            elif test.get('workflow', False) or 'steps' in test:
                # Execute workflow test (explicit workflow flag OR has steps array)
                success = self._execute_workflow(test, result)
            else:
                # Execute single request test
                success = self._execute_single_request(test, result)
            
            result.passed = success
            
        except Exception as e:
            result.passed = False
            # Handle encoding issues in error messages
            error_str = str(e).replace('→', '->').encode('ascii', 'replace').decode('ascii')
            result.error_message = error_str
            
        finally:
            result.execution_time_ms = int((time.time() - start_time) * 1000)
            
            # Validate performance threshold if specified
            if 'performance_threshold_ms' in test:
                threshold = test['performance_threshold_ms']
                if result.execution_time_ms > threshold:
                    result.passed = False
                    result.error_message = f"Performance threshold exceeded: {result.execution_time_ms}ms > {threshold}ms"
        
        return result
    
    def _execute_single_request(self, test: Dict, result: TestResult) -> bool:
        """
        Execute a single HTTP request test.
        
        Args:
            test: Test configuration
            result: TestResult to populate
            
        Returns:
            True if test passed, False otherwise
        """
        # Prepare request data
        method = test['method']
        endpoint = test['endpoint']
        auth_type = test.get('auth_type', 'none')
        data = test.get('data', {})
        expected_status = test.get('expected_status', 200)
        
        # Generate unique subscriber_id based on test_id and session
        test_id = test.get('id', 'test').lower()
        subscriber_id = self.data_gen.generate_subscriber_id(prefix=test_id, suffix=self.session_id)
        
        # Resolve variables in data (e.g., {{subscriber_id}})
        if data:
            data = self._resolve_variables(data, {'subscriber_id': subscriber_id})
        
        # Build custom headers (e.g., X-Request-ID for DNS signature tests)
        custom_headers = {}
        if test.get('request_id'):
            custom_headers['X-Request-ID'] = test['request_id']
        if test.get('headers'):
            custom_headers.update(test['headers'])
        
        # Execute request
        response = self.client.request(
            method=method,
            endpoint=endpoint,
            auth_type=auth_type,
            subscriber_id=subscriber_id if auth_type == 'v3' else None,
            data=data if data else None,
            headers=custom_headers if custom_headers else None,
            timeout=test.get('timeout', 30)
        )
        
        # Capture request details
        result.request_details.append({
            "method": method,
            "endpoint": endpoint,
            "url": response.request.url if hasattr(response, 'request') else None,
            "query_params": None,
            "auth_type": auth_type,
            "subscriber_id": subscriber_id if auth_type == 'v3' else None,
            "headers": dict(response.request.headers) if hasattr(response, 'request') else {},
            "body": data
        })
        
        # Record result
        result.status_code = response.status_code
        result.expected_status = expected_status
        
        try:
            result.response_body = response.json()
        except:
            result.response_body = response.text
        
        # Capture response details
        result.response_details.append({
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": result.response_body
        })
        
        # Validate status code
        if response.status_code != expected_status:
            error_details = ""
            if hasattr(result.response_body, 'get'):
                if 'error' in result.response_body:
                    error_info = result.response_body['error']
                    error_details = f" - {error_info.get('code', '')}: {error_info.get('message', '')}"
                    if 'path' in error_info:
                        error_details += f" (path: {error_info['path']})"
            result.error_message = f"Expected {expected_status}, got {response.status_code}{error_details}"
            return False
        
        # Perform field validations
        if 'validate' in test:
            for validation in test['validate']:
                if not self._validate_field(result.response_body, validation, result):
                    failed_v = next((v for v in reversed(result.validations) if not v.get('passed')), None)
                    if failed_v:
                        err = failed_v.get('error', f"Validation failed: field '{failed_v.get('field', validation['field'])}' expected {failed_v.get('expected', '?')} but got {failed_v.get('actual', '?')}")
                        result.error_message = err
                    else:
                        result.error_message = f"Validation failed for field '{validation['field']}'"
                    return False
        
        # Save state if needed
        if subscriber_id and response.status_code == expected_status:
            status = data.get('action', 'WHITELISTED')
            self.state_mgr.register_participant(subscriber_id, status)
        
        return True
    
    def _execute_workflow(self, test: Dict, result: TestResult) -> bool:
        """
        Execute multi-step workflow test.
        
        Args:
            test: Test configuration with steps
            result: TestResult to populate
            
        Returns:
            True if all steps passed, False otherwise
        """
        steps = test.get('steps', [])
        
        # Check if concurrent execution is requested
        if test.get('concurrent_steps', False):
            return self._execute_concurrent_workflow(test, result, steps)
        
        # Sequential execution (default)
        return self._execute_sequential_workflow(test, result, steps)
    
    def _execute_sequential_workflow(self, test: Dict, result: TestResult, steps: List[Dict]) -> bool:
        """
        Execute workflow steps sequentially (original behavior).
        
        Args:
            test: Test configuration
            result: TestResult to populate
            steps: List of workflow steps
            
        Returns:
            True if all steps passed, False otherwise
        """
        # Initialize context with unique subscriber_id for this workflow
        test_id = test.get('id', 'test').lower()
        subscriber_id = self.data_gen.generate_subscriber_id(prefix=test_id, suffix=self.session_id)
        context = {'subscriber_id': subscriber_id, 'timestamp': str(int(time.time() * 1000))}
        
        for i, step in enumerate(steps):
            step_name = step.get('name', f'Step {i+1}')
            print(f"  -> {step_name}")
            
            # Resolve variables in step data and endpoint
            step_data = self._resolve_variables(step.get('data', {}), context)
            endpoint = self._resolve_variables(step.get('endpoint', ''), context) if isinstance(step.get('endpoint'), str) else step.get('endpoint', '')
            
            # Resolve variables in query_params
            step_query_params = self._resolve_variables(step.get('query_params', {}), context) or None
            
            # Execute step
            response = self.client.request(
                method=step['method'],
                endpoint=endpoint,
                auth_type=step.get('auth_type', 'none'),
                subscriber_id=context.get('subscriber_id') if step.get('auth_type') == 'v3' else None,
                data=step_data if step_data else None,
                params=step_query_params,
                timeout=step.get('timeout', 30)
            )
            
            # Capture request details for this step
            result.request_details.append({
                "step_name": step_name,
                "method": step['method'],
                "endpoint": step['endpoint'],
                "url": response.request.url if hasattr(response, 'request') else None,
                "query_params": step_query_params,
                "auth_type": step.get('auth_type', 'none'),
                "subscriber_id": context.get('subscriber_id') if step.get('auth_type') == 'v3' else None,
                "headers": dict(response.request.headers) if hasattr(response, 'request') else {},
                "body": step_data
            })
            
            # Parse response body
            try:
                response_body = response.json()
            except:
                response_body = response.text
            
            # Capture response details for this step
            result.response_details.append({
                "step_name": step_name,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response_body
            })
            
            # Check status
            expected = step.get('expected_status', 200)
            if response.status_code != expected:
                result.error_message = f"{step_name}: Expected {expected}, got {response.status_code}"
                result.status_code = response.status_code
                result.expected_status = expected
                result.response_body = response_body
                return False
            
            # Save subscriber_id from first step
            if step.get('save_subscriber_id', False):
                try:
                    response_data = response.json()
                    context['subscriber_id'] = response_data.get('subscriber_id')
                except:
                    pass
            
            # Validate step
            if 'validate' in step:
                try:
                    response_data = response.json()
                except:
                    response_data = {}
                    
                for validation in step['validate']:
                    if not self._validate_field(response_data, validation, result):
                        failed_v = next((v for v in reversed(result.validations) if not v.get('passed')), None)
                        if failed_v:
                            err = failed_v.get('error', f"Validation failed: field '{failed_v.get('field', validation['field'])}' expected {failed_v.get('expected', '?')} but got {failed_v.get('actual', '?')}")
                            result.error_message = f"{step_name}: {err}"
                        else:
                            result.error_message = f"{step_name}: Validation failed for field '{validation['field']}'"
                        return False
            
            # Store response fields into context for later steps
            if 'store' in step:
                try:
                    store_data = response.json()
                except Exception:
                    store_data = {}
                for store_item in step.get('store', []):
                    field_path = store_item.get('field', '')
                    as_key = store_item.get('as', '')
                    if field_path and as_key:
                        val = store_data
                        for part in field_path.split('.'):
                            if isinstance(val, dict):
                                val = val.get(part)
                            else:
                                val = None
                                break
                        if val is not None:
                            context[as_key] = val
        
        result.status_code = 200
        result.expected_status = 200
        return True
    
    def _execute_concurrent_workflow(self, test: Dict, result: TestResult, steps: List[Dict]) -> bool:
        """
        Execute workflow with concurrent steps.
        
        Steps marked with 'concurrent: true' will be executed in parallel.
        
        Args:
            test: Test configuration
            result: TestResult to populate
            steps: List of workflow steps
            
        Returns:
            True if all steps passed, False otherwise
        """
        # Initialize context
        test_id = test.get('id', 'test').lower()
        subscriber_id = self.data_gen.generate_subscriber_id(prefix=test_id, suffix=self.session_id)
        context = {'subscriber_id': subscriber_id}
        
        # Group steps into sequential and concurrent batches
        i = 0
        while i < len(steps):
            step = steps[i]
            
            # Check if this step is concurrent
            if step.get('concurrent', False):
                # Collect all consecutive concurrent steps
                concurrent_batch = []
                while i < len(steps) and steps[i].get('concurrent', False):
                    concurrent_batch.append(steps[i])
                    i += 1
                
                # Execute concurrent batch
                if not self._execute_concurrent_steps(concurrent_batch, context, result):
                    return False
            else:
                # Execute single step sequentially
                step_name = step.get('name', f'Step {i+1}')
                print(f"  -> {step_name}")
                
                if not self._execute_step(step, context, result, step_name):
                    return False
                i += 1
        
        result.status_code = 200
        result.expected_status = 200
        return True
    
    def _execute_concurrent_steps(self, steps: List[Dict], context: Dict, result: TestResult) -> bool:
        """
        Execute multiple steps concurrently using threads.
        
        Args:
            steps: List of steps to execute concurrently
            context: Shared context dictionary
            result: TestResult to populate
            
        Returns:
            True if all concurrent steps passed, False otherwise
        """
        print(f"  -> Executing {len(steps)} concurrent steps...")
        
        step_results = []
        lock = Lock()
        
        def execute_concurrent_step(step_data):
            step, index = step_data
            step_name = step.get('name', f'Concurrent Step {index+1}')
            
            # Create temporary result container
            temp_result = TestResult(f"concurrent_{index}", step_name)
            
            # Execute the step
            success = self._execute_step(step, context, temp_result, step_name)
            
            # Thread-safe result appending
            with lock:
                step_results.append((step_name, success, temp_result))
            
            return success
        
        # Execute steps in parallel
        with ThreadPoolExecutor(max_workers=len(steps)) as executor:
            futures = {executor.submit(execute_concurrent_step, (step, i)): i for i, step in enumerate(steps)}
            
            all_passed = True
            for future in as_completed(futures):
                try:
                    if not future.result():
                        all_passed = False
                except Exception as e:
                    print(f"    [ERROR] Concurrent step failed: {e}")
                    all_passed = False
        
        # Report results
        for step_name, success, temp_result in step_results:
            status = "[OK]" if success else "[FAIL]"
            print(f"    {status} {step_name}")
            
            # Merge request/response details into main result
            result.request_details.extend(temp_result.request_details)
            result.response_details.extend(temp_result.response_details)
            
            if not success and temp_result.error_message:
                result.error_message = f"{step_name}: {temp_result.error_message}"
        
        return all_passed
    
    def _execute_step(self, step: Dict, context: Dict, result: TestResult, step_name: str) -> bool:
        """
        Execute a single workflow step.
        
        Args:
            step: Step configuration
            context: Context dictionary with variables
            result: TestResult to populate
            step_name: Name of the step for logging
            
        Returns:
            True if step passed, False otherwise
        """
        # Resolve variables in step data and endpoint
        step_data = self._resolve_variables(step.get('data', {}), context)
        endpoint = self._resolve_variables(step.get('endpoint', ''), context) if isinstance(step.get('endpoint'), str) else step.get('endpoint', '')
        step_query_params = self._resolve_variables(step.get('query_params', {}), context) or None
        
        # Build custom headers (e.g., X-Request-ID for DNS signature tests)
        custom_headers = {}
        if step.get('request_id'):
            custom_headers['X-Request-ID'] = step['request_id']
        if step.get('headers'):
            custom_headers.update(step['headers'])
        
        # Execute step
        response = self.client.request(
            method=step['method'],
            endpoint=endpoint,
            auth_type=step.get('auth_type', 'none'),
            subscriber_id=context.get('subscriber_id') if step.get('auth_type') == 'v3' else None,
            data=step_data if step_data else None,
            params=step_query_params,
            headers=custom_headers if custom_headers else None,
            timeout=step.get('timeout', 30)
        )
        
        # Capture request details for this step
        result.request_details.append({
            "step_name": step_name,
            "method": step['method'],
            "endpoint": step['endpoint'],
            "url": response.request.url if hasattr(response, 'request') else None,
            "query_params": step_query_params,
            "auth_type": step.get('auth_type', 'none'),
            "subscriber_id": context.get('subscriber_id') if step.get('auth_type') == 'v3' else None,
            "headers": dict(response.request.headers) if hasattr(response, 'request') else {},
            "body": step_data
        })
        
        # Parse response body
        try:
            response_body = response.json()
        except:
            response_body = response.text
        
        # Capture response details for this step
        result.response_details.append({
            "step_name": step_name,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response_body
        })
        
        # Check status (support multiple expected statuses for concurrent scenarios)
        expected = step.get('expected_status', 200)
        expected_statuses = expected if isinstance(expected, list) else [expected]
        
        if response.status_code not in expected_statuses:
            result.error_message = f"{step_name}: Expected {expected}, got {response.status_code}"
            result.status_code = response.status_code
            result.expected_status = expected
            result.response_body = response_body
            return False
        
        # Save subscriber_id from first step
        if step.get('save_subscriber_id', False):
            try:
                response_data = response.json()
                context['subscriber_id'] = response_data.get('subscriber_id')
            except:
                pass
        
        # Validate step
        if 'validate' in step:
            try:
                response_data = response.json()
            except:
                response_data = {}
            
            for validation in step['validate']:
                if not self._validate_field(response_data, validation, result):
                    return False
        
        # Store response fields into context for later steps
        if 'store' in step:
            try:
                store_data = response.json()
            except Exception:
                store_data = {}
            for store_item in step.get('store', []):
                field_path = store_item.get('field', '')
                as_key = store_item.get('as', '')
                if field_path and as_key:
                    val = store_data
                    for part in field_path.split('.'):
                        if isinstance(val, dict):
                            val = val.get(part)
                        else:
                            val = None
                            break
                    if val is not None:
                        context[as_key] = val
        
        return True
    
    def _execute_batch_test(self, test: Dict, result: TestResult, batch_size: int) -> bool:
        """
        Execute a test multiple times with batch index variable.
        
        Args:
            test: Test configuration
            result: TestResult to populate
            batch_size: Number of batch iterations
            
        Returns:
            True if all batch iterations passed, False otherwise
        """
        print(f"  -> Executing batch of {batch_size} iterations...")
        
        passed_count = 0
        failed_count = 0
        total_time_ms = 0
        
        for batch_index in range(batch_size):
            batch_context = {
                'batch_index': batch_index,
                'timestamp': int(time.time() * 1000)
            }
            
            # Execute single iteration
            if test.get('workflow', False):
                # Batch workflow - add batch context to subscriber_id
                test_id = test.get('id', 'test').lower()
                subscriber_id = self.data_gen.generate_subscriber_id(
                    prefix=f"{test_id}_batch{batch_index}", 
                    suffix=self.session_id
                )
                batch_context['subscriber_id'] = subscriber_id
                
                # Execute workflow with batch context
                temp_result = TestResult(f"{test['id']}_batch{batch_index}", f"Batch {batch_index}")
                iteration_start = time.time()
                
                success = self._execute_sequential_workflow(test, temp_result, test.get('steps', []))
                
                iteration_time = int((time.time() - iteration_start) * 1000)
                total_time_ms += iteration_time
                
                if success:
                    passed_count += 1
                else:
                    failed_count += 1
                    if failed_count == 1:  # Capture first failure details
                        result.error_message = f"Batch iteration {batch_index} failed: {temp_result.error_message}"
                        result.response_body = temp_result.response_body
            else:
                # Batch single request
                iteration_start = time.time()
                
                # Resolve batch variables in data
                data = self._resolve_variables(test.get('data', {}), batch_context)
                
                # Generate unique subscriber_id for this iteration
                test_id = test.get('id', 'test').lower()
                subscriber_id = self.data_gen.generate_subscriber_id(
                    prefix=f"{test_id}_batch{batch_index}",
                    suffix=self.session_id
                )
                data = self._resolve_variables(data, {'subscriber_id': subscriber_id})
                
                # Execute request
                response = self.client.request(
                    method=test['method'],
                    endpoint=test['endpoint'],
                    auth_type=test.get('auth_type', 'none'),
                    subscriber_id=subscriber_id if test.get('auth_type') == 'v3' else None,
                    data=data,
                    timeout=test.get('timeout', 30)
                )
                
                iteration_time = int((time.time() - iteration_start) * 1000)
                total_time_ms += iteration_time
                
                expected = test.get('expected_status', 200)
                if response.status_code == expected:
                    passed_count += 1
                else:
                    failed_count += 1
                    if failed_count == 1:  # Capture first failure
                        try:
                            result.response_body = response.json()
                        except:
                            result.response_body = response.text
                        result.error_message = f"Batch iteration {batch_index} failed: Expected {expected}, got {response.status_code}"
        
        # Update result
        result.execution_time_ms = total_time_ms
        avg_time = total_time_ms // batch_size if batch_size > 0 else 0
        
        print(f"    Batch complete: {passed_count} passed, {failed_count} failed (avg {avg_time}ms per iteration)")
        
        # Consider test passed if all iterations passed
        return failed_count == 0
    
    def _resolve_variables(self, data: Any, context: Dict) -> Any:
        """
        Resolve variable placeholders in data.
        
        Args:
            data: Data with potential {{variable}} placeholders
            context: Context dictionary with variable values
            
        Returns:
            Data with variables resolved
        """
        if isinstance(data, dict):
            return {k: self._resolve_variables(v, context) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._resolve_variables(item, context) for item in data]
        elif isinstance(data, str):
            # Replace {{variable}} patterns
            for key, value in context.items():
                placeholder = f"{{{{{key}}}}}"
                if placeholder in data:
                    data = data.replace(placeholder, str(value))
            return data
        return data
    
    def _navigate_field(self, data, parts):
        """
        Navigate nested data using dot/bracket path parts.
        Supports [*] wildcard which collects values across all list items.
        Returns the value, or raises KeyError/IndexError/TypeError/AttributeError if not found.
        """
        if not parts:
            return data
        part = parts[0]
        rest = parts[1:]
        if part == '*':
            if not isinstance(data, list):
                raise TypeError(f"Expected list for wildcard, got {type(data).__name__}")
            results = []
            for item in data:
                sub = self._navigate_field(item, rest)
                if isinstance(sub, list):
                    results.extend(sub)
                else:
                    results.append(sub)
            return results
        elif part.isdigit():
            return self._navigate_field(data[int(part)], rest)
        elif isinstance(data, dict):
            return self._navigate_field(data.get(part), rest)
        elif hasattr(data, 'get'):
            return self._navigate_field(data.get(part), rest)
        else:
            raise AttributeError(f"Cannot navigate '{part}' on {type(data).__name__}")

    def _validate_field(self, response_data: Dict, validation: Dict, result: TestResult) -> bool:
        """
        Validate a field in the response.
        
        Args:
            response_data: Response body dictionary
            validation: Validation specification
            result: TestResult to record validation
            
        Returns:
            True if validation passed, False otherwise
        """
        field = validation['field']
        
        # Navigate nested fields supporting [*] wildcards (e.g., "items[*].status")
        parts = [p for p in field.replace('[', '.').replace(']', '').split('.') if p]
        try:
            value = self._navigate_field(response_data, parts)
        except (KeyError, IndexError, TypeError, AttributeError):
            result.validations.append({
                "field": field,
                "passed": False,
                "error": f"Field {field} not found in response"
            })
            return False
        
        # Check existence
        if validation.get('exists', False):
            passed = value is not None
            result.validations.append({
                "field": field,
                "passed": passed,
                "expected": "exists",
                "actual": "exists" if passed else "missing"
            })
            return passed
        
        # Check value
        if 'value' in validation:
            expected = validation['value']
            operator = validation.get('operator', '==')
            if value is None and operator not in ('!=', '=='):
                result.validations.append({
                    "field": field,
                    "passed": False,
                    "expected": f"{operator} {expected}",
                    "actual": None,
                    "error": f"Field '{field}' is None, cannot apply operator '{operator}'"
                })
                return False
            if operator == '>=':
                passed = value >= expected
            elif operator == '>':
                passed = value > expected
            elif operator == '<=':
                passed = value <= expected
            elif operator == '<':
                passed = value < expected
            elif operator == '!=':
                passed = value != expected
            else:
                passed = value == expected
            result.validations.append({
                "field": field,
                "passed": passed,
                "expected": f"{operator} {expected}" if operator != '==' else expected,
                "actual": value
            })
            return passed
        
        # Check array length
        if 'array_length' in validation:
            expected_len = validation['array_length']
            actual_len = len(value) if isinstance(value, list) else 0
            passed = actual_len == expected_len
            result.validations.append({
                "field": field,
                "passed": passed,
                "expected_length": expected_len,
                "actual_length": actual_len
            })
            return passed

        # Check all_equals (for wildcard-collected lists, e.g., items[*].status all_equals "SUBSCRIBED")
        if 'all_equals' in validation:
            expected = validation['all_equals']
            values = value if isinstance(value, list) else [value]
            passed = bool(values) and all(v == expected for v in values)
            result.validations.append({
                "field": field,
                "passed": passed,
                "expected": f"all equal {expected}",
                "actual": values
            })
            return passed

        # Check contains (value or list contains the expected item)
        if 'contains' in validation:
            expected = validation['contains']
            if isinstance(value, list):
                passed = expected in value
            elif isinstance(value, str):
                passed = expected in value
            else:
                passed = value == expected
            result.validations.append({
                "field": field,
                "passed": passed,
                "expected": f"contains {expected}",
                "actual": value
            })
            return passed

        return True
    
    def run_all_tests(self) -> Dict:
        """
        Run all tests in the configuration.
        
        Returns:
            Summary dictionary
        """
        print(f"\n{'='*70}")
        print(f"Running {self.config['test_suite']['name']}")
        print(f"Total tests: {len(self.tests)}")
        print(f"{'='*70}\n")
        
        self.results = []
        passed = 0
        failed = 0
        
        for test in self.tests:
            # Replace Unicode arrows for Windows console compatibility
            test_name = test['name'].replace('→', '->').encode('ascii', 'replace').decode('ascii')
            try:
                print(f"[{test['id']}] {test_name}")
            except UnicodeEncodeError:
                print(f"[{test['id']}] {test_name.encode('ascii', 'replace').decode('ascii')}")
            
            result = self.execute_test(test)
            self.results.append(result)
            
            if result.passed:
                print(f"  [OK] PASSED ({result.execution_time_ms}ms)\n")
                passed += 1
            else:
                print(f"  [FAIL] FAILED: {result.error_message}")
                if result.status_code:
                    print(f"    Status: {result.status_code} (expected {result.expected_status})")
                print()
                failed += 1
        
        # Summary
        total = passed + failed
        pass_rate = (passed / total * 100) if total > 0 else 0
        
        summary = {
            "total": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": round(pass_rate, 2),
            "results": [r.to_dict() for r in self.results]
        }
        
        print(f"\n{'='*70}")
        print(f"SUMMARY: {passed}/{total} passed ({pass_rate:.1f}%)")
        print(f"{'='*70}\n")
        
        return summary
    
    def save_results(self, output_file: str):
        """Save test results to JSON and HTML files."""
        summary = {
            "test_suite": self.config.get('test_suite', {}).get('name', 'Unknown'),
            "timestamp": datetime.now().isoformat(),
            "results": [r.to_dict() for r in self.results],
            "summary": {
                "total": len(self.results),
                "passed": sum(1 for r in self.results if r.passed),
                "failed": sum(1 for r in self.results if not r.passed)
            }
        }
        
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save JSON report
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)
        
        print(f"[OK] JSON report saved to {output_file}")
        
        # Save HTML report
        html_file = output_path.with_suffix('.html')
        test_suite_name = self.config.get('test_suite', {}).get('name', 'Test Suite')
        HTMLReporter.generate_report(
            results=summary['results'],
            output_file=str(html_file),
            test_suite_name=test_suite_name
        )
        print(f"[OK] HTML report saved to {html_file}")
    
    @abstractmethod
    def setup(self) -> bool:
        """
        Perform runner-specific setup.
        
        Returns:
            True if setup successful
        """
        pass
    
    @abstractmethod
    def teardown(self):
        """Perform runner-specific cleanup."""
        pass
