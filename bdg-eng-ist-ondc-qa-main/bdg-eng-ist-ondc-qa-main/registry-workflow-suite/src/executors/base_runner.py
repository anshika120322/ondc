"""
Base Test Runner

Abstract base class for all test runners with common functionality.
"""

import os
import re
import uuid
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
        self.warnings = []           # steps with allow_failure=true that failed
        
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
            "warnings": self.warnings,
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
                 gateway_url: Optional[str] = None, tags: Optional[List[str]] = None,
                 seed: Optional[int] = None, fail_fast: bool = False,
                 dry_run: bool = False,
                 participant_url: str = '', dns_skip: bool = False):
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
            gateway_url: Optional gateway base URL for /v2.0/lookup calls; falls back to base_url
            tags: Optional list of tags to filter tests (e.g. ['smoke', 'crud'])
            seed: Optional random seed for reproducible subscriber IDs
            fail_fast: Stop on first test failure
            dry_run: Print tests that would run without executing them
        """
        self.config_file = config_file
        self.base_url = base_url
        self.gateway_url = gateway_url or base_url
        self.auth_url = auth_url
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.tags = tags
        self.fail_fast = fail_fast
        self.dry_run = dry_run
        self.participant_url = participant_url
        self.dns_skip = dns_skip
        if seed is not None:
            import random as _rnd
            _rnd.seed(seed)
        self.client = HTTPClient(base_url, admin_username, admin_password,
                                 auth_url=auth_url,
                                 username_field=username_field,
                                 password_field=password_field,
                                 token_field=token_field)
        self.test_ids = test_ids
        self.optional_mode = optional_mode
        
        # Generate unique session ID for this test run (or use supplied shared one)
        import random
        import string
        self.session_id = session_id if session_id else ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        self.data_gen = DataGenerator(seed=seed)
        self.state_mgr = StateManager()
        self.config = None
        self.tests = []
        self.results = []
        self._v3_registered: Dict[str, bool] = {}  # subscriber_id -> registered
        self._v3_lookup_registered = False  # Flag for pre-registered lookup participant
        
    def load_config(self) -> bool:
        """
        Load test configuration from YAML file.
        Supports ``include:`` at the top level to merge tests from other YAML
        files (Group H3).

        Returns:
            True if successful, False otherwise
        """
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)

            # Group H3: include: merging
            includes = self.config.pop('include', None) or []
            if isinstance(includes, str):
                includes = [includes]
            base_dir = Path(self.config_file).parent
            for inc_path in includes:
                resolved = base_dir / inc_path
                try:
                    with open(resolved, 'r', encoding='utf-8') as f:
                        inc_data = yaml.safe_load(f)
                    if isinstance(inc_data, dict):
                        self.config.setdefault('tests', [])
                        self.config['tests'].extend(inc_data.get('tests', []))
                    elif isinstance(inc_data, list):
                        self.config.setdefault('tests', [])
                        self.config['tests'].extend(inc_data)
                    print(f"[OK] Included tests from {resolved}")
                except Exception as exc:
                    print(f"[WARNING] Could not include {resolved}: {exc}")

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
        """Filter tests based on test IDs, optional mode, and tags."""
        filtered = all_tests
        
        # Filter by test IDs if specified
        if self.test_ids:
            expanded_ids = self._expand_test_ids(self.test_ids)
            filtered = [t for t in filtered if t.get('id') in expanded_ids]
            if not filtered:
                print(f"[WARNING] No tests matched IDs: {self.test_ids}")
        
        # Filter by optional status
        if self.optional_mode == 'skip':
            filtered = [t for t in filtered if not t.get('optional', False)]
        elif self.optional_mode == 'only':
            filtered = [t for t in filtered if t.get('optional', False)]
        
        # Filter by tags (Group D/E)
        if self.tags:
            tag_set = set(self.tags)
            filtered = [t for t in filtered if tag_set.intersection(set(t.get('tags', [])))]
            if not filtered:
                print(f"[WARNING] No tests matched tags: {self.tags}")
        
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
    
    def execute_test(self, test: Dict, passed_ids: Optional[set] = None) -> TestResult:
        """
        Execute a single test.
        
        Args:
            test: Test configuration dictionary
            passed_ids: Set of test IDs that have passed (for depends_on)
            
        Returns:
            TestResult object
        """
        result = TestResult(test['id'], test['name'])
        start_time = time.time()
        
        # Dry-run: just print what would run
        if self.dry_run:
            method = test.get('method', 'WORKFLOW')
            endpoint = test.get('endpoint', '[multi-step]')
            print(f"  [DRY-RUN] {method} {endpoint}")
            result.passed = True
            result.error_message = None
            result.execution_time_ms = 0
            return result
        
        # depends_on check (Group D)
        if test.get('depends_on') and passed_ids is not None:
            dep = test['depends_on']
            deps = dep if isinstance(dep, list) else [dep]
            missing = [d for d in deps if d not in passed_ids]
            if missing:
                result.passed = False
                result.error_message = f"Skipped: depends_on {missing} not passed"
                result.execution_time_ms = 0
                return result
        
        try:
            # Check for batch execution
            batch_size = test.get('batch_size', 1)
            
            if batch_size > 1:
                success = self._execute_batch_test(test, result, batch_size)
            elif test.get('workflow', False) or 'steps' in test:
                success = self._execute_workflow(test, result)
            else:
                success = self._execute_single_request(test, result)
            
            result.passed = success
            
        except Exception as e:
            result.passed = False
            error_str = str(e).replace('→', '->').encode('ascii', 'replace').decode('ascii')
            result.error_message = error_str
            
        finally:
            result.execution_time_ms = int((time.time() - start_time) * 1000)
            
            # performance_threshold_ms check
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
            data = self._resolve_variables(data, {
                'subscriber_id': subscriber_id,
                'participant_url': self.participant_url,
            })
        
        # Build custom headers – resolve {{variables}} so tests can use dynamic values
        custom_headers = {}
        if test.get('request_id'):
            custom_headers['X-Request-ID'] = test['request_id']
        if test.get('headers'):
            resolved_hdrs = self._resolve_variables(test['headers'], {'subscriber_id': subscriber_id})
            custom_headers.update(resolved_hdrs)

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
                # Resolve {{variable}} references in the validation spec
                validation = self._resolve_variables(validation, {'subscriber_id': subscriber_id} if subscriber_id else {})
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
        """Execute workflow steps sequentially with full feature support."""
        test_id = test.get('id', 'test').lower()
        subscriber_id = self.data_gen.generate_subscriber_id(prefix=test_id, suffix=self.session_id)
        
        # Build initial context — includes test-level variables (Group D)
        # Note: admin_password is intentionally excluded from context to prevent logging sensitive data
        context = {
            'subscriber_id': subscriber_id,
            'timestamp': str(int(time.time() * 1000)),
            'gateway_url': self.gateway_url,
            'admin_username': self.admin_username,
            'participant_url': self.participant_url,
        }
        if self.auth_url:
            context['auth_url'] = self.auth_url
        # Inject test-level static variables (Group D5)
        for k, v in test.get('variables', {}).items():
            context[k] = v
        # uk_id for V3 tests
        uk_id = self.data_gen.generate_unique_key_id()
        context.update({
            'request_id': str(uuid.uuid4()),
            'uk_id': uk_id,
        })
        
        v3_registered = False
        inject_v3_key = test.get('inject_v3_key', False)  # Group A3
        use_v3_lookup_key = test.get('use_v3_lookup_key', False)  # Use pre-configured v3 key

        # Look-ahead: only auto-register V3 if this test actually uses v3 auth
        # somewhere in its steps (or explicitly opts in via inject_v3_key).
        # This prevents pure-admin tests whose steps happen to carry a `key:` field
        # (e.g. A34) from triggering unnecessary key-pair generation.
        all_steps = (
            test.get('setup_steps', [])
            + test.get('steps', [])
            + test.get('teardown_steps', [])
        )
        _test_needs_v3 = inject_v3_key or any(
            s.get('auth_type') in ('v3', 'v3_lookup') for s in all_steps
        )

        def _run_steps(step_list: List[Dict], phase: str = 'main') -> bool:
            nonlocal v3_registered
            for i, step in enumerate(step_list):
                step_name = step.get('name', f'{phase} Step {i+1}')
                desc = step.get('description', '')

                # sleep step (Group B3)
                if 'sleep_seconds' in step:
                    secs = step['sleep_seconds']
                    print(f"  -> {step_name}: sleeping {secs}s")
                    time.sleep(secs)
                    continue

                # skip_if / run_if (Group B1)
                if step.get('skip_if'):
                    cond_val = self._resolve_variables(step['skip_if'], context)
                    if self._eval_condition(cond_val, context):
                        print(f"  -> {step_name}: [SKIPPED] skip_if matched")
                        continue
                if step.get('run_if'):
                    cond_val = self._resolve_variables(step['run_if'], context)
                    if not self._eval_condition(cond_val, context):
                        print(f"  -> {step_name}: [SKIPPED] run_if not matched")
                        continue

                print(f"  -> {step_name}" + (f" — {desc}" if desc else ""))

                auth_type = step.get('auth_type', 'none')

                # Resolve step data first so we can inspect 'key' field presence
                step_data = self._resolve_variables(step.get('data', {}), context)

                # Auto-inject dns_skip from suite config for admin /subscribe steps
                if (self.dns_skip
                        and auth_type == 'admin'
                        and step.get('method', '').upper() in ('POST', 'PATCH')
                        and '/admin/subscribe' in str(step.get('endpoint', ''))
                        and 'dns_skip' not in step_data):
                    step_data['dns_skip'] = True

                # Auto-inject dns_skip for NP self-service /v3.0/subscribe steps
                if (self.dns_skip
                        and auth_type == 'v3'
                        and step.get('method', '').upper() in ('POST', 'PATCH')
                        and '/v3.0/subscribe' in str(step.get('endpoint', ''))
                        and 'dns_skip' not in step_data):
                    step_data['dns_skip'] = True

                # Group A: auto-register V3 key pair.
                # Only runs when the test actually contains a v3 step (or inject_v3_key).
                # Register before:
                #   1. Admin subscribe steps that carry a 'key' field (so the server
                #      stores the *real* generated public key, not a placeholder).
                #   2. Any step with auth_type == 'v3'.
                #   3. Any step with auth_type == 'v3_lookup' (uses pre-registered credentials).
                
                # Handle v3_lookup (pre-registered participant for lookup calls)
                if auth_type == 'v3_lookup' and not self._v3_lookup_registered:
                    # Load pre-registered credentials from config
                    cfg = self.config.get('config', {})
                    lookup_participant_id = cfg.get('v3_participant_id')
                    lookup_uk_id = cfg.get('v3_uk_id')
                    lookup_private_key_seed_hex = cfg.get('v3_private_key_seed')
                    
                    if not all([lookup_participant_id, lookup_uk_id, lookup_private_key_seed_hex]):
                        raise ValueError(
                            "v3_lookup auth requires v3_participant_id, v3_uk_id, "
                            "and v3_private_key_seed in config section"
                        )
                    
                    # Convert hex seed to bytes (32 bytes)
                    try:
                        private_key_seed_bytes = bytes.fromhex(lookup_private_key_seed_hex)
                        if len(private_key_seed_bytes) != 32:
                            raise ValueError(f"Private key seed must be 32 bytes, got {len(private_key_seed_bytes)}")
                    except ValueError as e:
                        raise ValueError(f"Invalid private key seed hex: {e}")
                    
                    # Register with existing key seed
                    self.client.register_v3_participant(
                        lookup_participant_id, 
                        lookup_uk_id,
                        private_key_seed=private_key_seed_bytes
                    )
                    self._v3_lookup_registered = True
                    print(f"    [OK] Registered V3 lookup auth for {lookup_participant_id} (pre-registered)")
                
                # Handle v3 (dynamically generated participant for subscribe calls)
                if _test_needs_v3 and not v3_registered:
                    is_admin_subscribe_with_key = (
                        auth_type == 'admin'
                        and step.get('method', '').upper() in ('POST', 'PATCH')
                        and '/admin/subscribe' in str(step.get('endpoint', ''))
                        and 'key' in step_data
                    )
                    if is_admin_subscribe_with_key or auth_type == 'v3':
                        # Extract uk_id from the step's key data if present (for consistency)
                        # This ensures V3 signature uses the same uk_id that Admin POST will register
                        actual_uk_id = uk_id  # Default to generated UUID
                        if is_admin_subscribe_with_key and 'key' in step_data:
                            # Handle both array and dict formats for key field
                            key_data = step_data['key']
                            if isinstance(key_data, list) and len(key_data) > 0:
                                key_data = key_data[0]  # Use first key in array
                            if isinstance(key_data, dict) and 'uk_id' in key_data:
                                actual_uk_id = key_data['uk_id']
                                # Update context so subsequent steps use the correct uk_id
                                context['uk_id'] = actual_uk_id
                                print(f"    [OK] Using uk_id from step data: {actual_uk_id}")
                        
                        # Use pre-configured v3_lookup key if requested, otherwise generate new random key
                        if use_v3_lookup_key:
                            # Use the same pre-configured key from config
                            cfg = self.config.get('config', {})
                            lookup_private_key_seed_hex = cfg.get('v3_private_key_seed')
                            if not lookup_private_key_seed_hex:
                                raise ValueError("use_v3_lookup_key requires v3_private_key_seed in config")
                            private_key_seed_bytes = bytes.fromhex(lookup_private_key_seed_hex)
                            self.client.register_v3_participant(subscriber_id, actual_uk_id, private_key_seed=private_key_seed_bytes)
                            print(f"    [OK] Registered V3 auth for {subscriber_id} (using pre-configured key)")
                        else:
                            # Generate new random key (default behavior)
                            self.client.register_v3_participant(subscriber_id, actual_uk_id)
                            print(f"    [OK] Registered V3 auth for {subscriber_id}")
                        
                        full_key = self.client.get_v3_full_key_info(subscriber_id)
                        if full_key:
                            result.ondc_key_info = full_key
                        pub_key = self.client.get_v3_public_key(subscriber_id)
                        if pub_key:
                            context.update({
                                'signing_public_key': pub_key.get('signing_public_key', ''),
                                'encryption_public_key': pub_key.get('encryption_public_key', ''),
                                'valid_from': pub_key.get('valid_from', ''),
                                'valid_until': pub_key.get('valid_until', ''),
                            })
                        v3_registered = True

                        # Re-resolve step_data so {{signing_public_key}} etc. are expanded
                        step_data = self._resolve_variables(step.get('data', {}), context)

                # Inject generated public key into admin step 'key' field when:
                #   - test has inject_v3_key: true  (explicit opt-in, Group A3), OR
                #   - the admin subscribe step had a key field (implicit — replaces placeholder)
                # Only applies when V3 is actually needed by this test.
                # Skip injection if the key already has a real value (not a placeholder like "1234...")
                if _test_needs_v3 and v3_registered and auth_type == 'admin' and 'key' in step_data:
                    # Handle both array and dict formats for key field
                    key_data = step_data['key']
                    if isinstance(key_data, list) and len(key_data) > 0:
                        key_data = key_data[0]  # Work with first key in array
                        is_array_format = True
                    else:
                        is_array_format = False
                    
                    existing_pub_key = key_data.get('signing_public_key', '') if isinstance(key_data, dict) else ''
                    is_placeholder = existing_pub_key.startswith('MCowBQYDK2VwAyEA1234')
                    
                    if (inject_v3_key or (
                        step.get('method', '').upper() in ('POST', 'PATCH')
                        and '/admin/subscribe' in str(step.get('endpoint', ''))
                    )) and is_placeholder:
                        # Only inject if it's a placeholder
                        # Determine which participant's key to inject
                        # If step data has participant_id different from context, use that
                        target_participant = step_data.get('participant_id', subscriber_id)
                        pub_key = self.client.get_v3_public_key(target_participant)
                        if pub_key:
                            old_key = key_data.get('signing_public_key', 'N/A')[:20] if isinstance(key_data, dict) else 'N/A'
                            if isinstance(key_data, dict):
                                key_data.update(pub_key)
                                if is_array_format:
                                    step_data['key'][0] = key_data
                            new_key = key_data.get('signing_public_key', 'N/A')[:20] if isinstance(key_data, dict) else 'N/A'
                            print(f"    [OK] Injected V3 public key: {old_key}... -> {new_key}...")
                        else:
                            print(f"    [WARN] Failed to get V3 public key for {target_participant}")

                # Generate a plain UUID into context without touching the V3 key
                if step.get('generate_uuid_as'):
                    ctx_key = step['generate_uuid_as']
                    context[ctx_key] = str(uuid.uuid4())
                    print(f"    [UUID] Generated {ctx_key} = {context[ctx_key]}")
                    # Re-resolve step_data with the new UUID in context
                    step_data = self._resolve_variables(step.get('data', {}), context)

                # Generate new key pair mid-test for key rotation testing
                if step.get('generate_new_key', False) and v3_registered:
                    print(f"    [KEY ROTATION] Generating new key pair for {subscriber_id}")
                    # Generate new uk_id for the rotated key
                    new_uk_id = self.data_gen.generate_unique_key_id()
                    context['uk_id_new'] = new_uk_id
                    
                    # Register new key pair (this overwrites the existing key in ONDCAuthManager)
                    self.client.register_v3_participant(subscriber_id, new_uk_id)
                    print(f"    [KEY ROTATION] Registered new V3 key pair with uk_id: {new_uk_id}")
                    
                    # Get the new public keys and store them with _new suffix
                    new_pub_key = self.client.get_v3_public_key(subscriber_id)
                    if new_pub_key:
                        context.update({
                            'signing_public_key_new': new_pub_key.get('signing_public_key', ''),
                            'encryption_public_key_new': new_pub_key.get('encryption_public_key', ''),
                        })
                        print(f"    [KEY ROTATION] New signing key: {new_pub_key.get('signing_public_key', '')[:30]}...")
                        print(f"    [KEY ROTATION] New encryption key: {new_pub_key.get('encryption_public_key', '')[:30]}...")
                        
                        # Update main result with new key info for debugging
                        new_full_key = self.client.get_v3_full_key_info(subscriber_id)
                        if new_full_key:
                            result.ondc_key_info = new_full_key
                    else:
                        print(f"    [WARN] Failed to get new V3 public key for {subscriber_id}")
                    
                    # Re-resolve step_data so {{signing_public_key_new}} etc. are expanded
                    step_data = self._resolve_variables(step.get('data', {}), context)

                endpoint = self._resolve_variables(step.get('endpoint', ''), context) if isinstance(step.get('endpoint'), str) else step.get('endpoint', '')
                step_query_params = self._resolve_variables(step.get('query_params', {}), context) or None
                custom_headers = {}
                if step.get('request_id'):
                    custom_headers['X-Request-ID'] = step['request_id']
                if step.get('headers'):
                    resolved_hdrs = self._resolve_variables(step['headers'], context)
                    custom_headers.update(resolved_hdrs)

                # ===========================================================================
                # WORKAROUND: Challenge encryption endpoint expects raw 32-byte keys
                # UAT /challenge/encrypt/text endpoint expects raw 32-byte X25519 keys,
                # but standard Ed25519/X25519 keys use SubjectPublicKeyInfo format with
                # ASN.1 prefix (44 bytes total). Extract raw 32 bytes for compatibility.
                # ===========================================================================
                if '/challenge/encrypt' in endpoint and step_data:
                    if 'subscriber_encryption_public_key' in step_data:
                        from ..utils.data_generator import DataGenerator
                        try:
                            original_key = step_data['subscriber_encryption_public_key']
                            print(f"    [DEBUG] Original encryption key: {original_key}")
                            import base64
                            try:
                                original_decoded = base64.b64decode(original_key + '===')  # Add padding
                                print(f"    [DEBUG] Original key decoded length: {len(original_decoded)} bytes")
                            except:
                                print(f"    [DEBUG] Failed to decode original key for inspection")
                            
                            raw_key = DataGenerator.extract_raw_32byte_key(original_key)
                            step_data['subscriber_encryption_public_key'] = raw_key
                            print(f"    [WORKAROUND] Extracted raw 32-byte key for challenge endpoint")
                            print(f"    [WORKAROUND] Original: {original_key[:20]}... ({len(original_key)} chars)")
                            raw_decoded = base64.b64decode(raw_key)
                            print(f"    [WORKAROUND] Raw key: {raw_key[:20]}... ({len(raw_decoded)} bytes)")
                        except Exception as e:
                            print(f"    [WARNING] Failed to extract raw key: {e}")
                            print(f"    [WARNING] Continuing with original key...")
                            # Continue with original key if extraction fails

                # retry logic (Group B2)
                retry_cfg = step.get('retry', {})
                max_attempts = 1 + retry_cfg.get('count', 0)
                retry_delay = retry_cfg.get('delay_seconds', 1)
                retry_until_status = retry_cfg.get('until_status')
                
                # Handle step-level V3 parameters (for tests with multiple V3 participants)
                step_v3_subscriber_id = step.get('v3_subscriber_id')
                step_v3_private_key = step.get('v3_private_key')
                step_v3_unique_key_id = step.get('v3_unique_key_id')
                
                # If step specifies custom V3 auth parameters, register them now
                if auth_type == 'v3' and step_v3_subscriber_id:
                    # Resolve subscriber_id in case it has {{variables}}
                    resolved_v3_subscriber_id = self._resolve_variables(step_v3_subscriber_id, context)
                    resolved_v3_unique_key_id = self._resolve_variables(step_v3_unique_key_id, context) if step_v3_unique_key_id else None
                    resolved_v3_private_key = self._resolve_variables(step_v3_private_key, context) if step_v3_private_key else None
                    
                    # Register new V3 participant with custom credentials
                    if resolved_v3_private_key and resolved_v3_unique_key_id:
                        # Try to detect key format and convert appropriately
                        # The key from generate-keypair is base64 encoded
                        # The key from config (v3_private_key_seed) is hex encoded
                        import base64
                        try:
                            # Try base64 first (format from /utility/generate-keypair)
                            if not resolved_v3_private_key.startswith('-----'):  # Not PEM
                                # Assume base64string and decode to get the raw 32-byte seed
                                try:
                                    private_key_bytes = base64.b64decode(resolved_v3_private_key)
                                    # Ed25519 private keys are 64 bytes (32 seed + 32 public)
                                    # Extract just the seed (first 32 bytes)
                                    if len(private_key_bytes) == 64:
                                        private_key_seed = private_key_bytes[:32]
                                    elif len(private_key_bytes) == 32:
                                        private_key_seed = private_key_bytes
                                    else:
                                        raise ValueError(f"Expected 32 or 64 bytes, got {len(private_key_bytes)}")
                                    
                                    self.client.register_v3_participant(
                                        resolved_v3_subscriber_id,
                                        resolved_v3_unique_key_id,
                                        private_key_seed=private_key_seed
                                    )
                                    print(f"    [OK] Registered step-level V3 auth for {resolved_v3_subscriber_id} (uk_id: {resolved_v3_unique_key_id})")
                                except Exception:
                                    # If base64 fails, try hex (for v3_private_key_seed from config)
                                    private_key_seed = bytes.fromhex(resolved_v3_private_key)
                                    if len(private_key_seed) != 32:
                                        raise ValueError(f"Hex key must be 32 bytes, got {len(private_key_seed)}")
                                    self.client.register_v3_participant(
                                        resolved_v3_subscriber_id,
                                        resolved_v3_unique_key_id,
                                        private_key_seed=private_key_seed
                                    )
                                    print(f"    [OK] Registered step-level V3 auth for {resolved_v3_subscriber_id} (uk_id: {resolved_v3_unique_key_id})")
                            else:
                                # PEM format
                                self.client.register_v3_participant(
                                    resolved_v3_subscriber_id,
                                    resolved_v3_unique_key_id,
                                    private_key_pem=resolved_v3_private_key
                                )
                                print(f"    [OK] Registered step-level V3 auth for {resolved_v3_subscriber_id} (PEM format)")
                        except Exception as e:
                            raise ValueError(f"Invalid v3_private_key format: {e}")
                    else:
                        # Generate random key if not provided
                        actual_uk_id = resolved_v3_unique_key_id or self.data_gen.generate_unique_key_id()
                        self.client.register_v3_participant(resolved_v3_subscriber_id, actual_uk_id)
                        print(f"    [OK] Registered step-level V3 auth for {resolved_v3_subscriber_id} (generated key)")
                
                # Determine subscriber_id based on auth_type
                request_subscriber_id = None
                if auth_type == 'v3':
                    # Use step-level subscriber_id if specified, otherwise use context
                    if step_v3_subscriber_id:
                        request_subscriber_id = self._resolve_variables(step_v3_subscriber_id, context)
                    else:
                        request_subscriber_id = context.get('subscriber_id')
                elif auth_type == 'v3_lookup':
                    # For v3_lookup, subscriber_id is in the step data
                    request_subscriber_id = step_data.get('subscriber_id')
                
                # Auto-inject required fields for V3 PATCH requests
                if step['method'] == 'PATCH' and auth_type == 'v3' and step_data:
                    # Add request_id if not present (required by V3 PATCH schema)
                    if 'request_id' not in step_data:
                        step_data['request_id'] = context.get('request_id', str(uuid.uuid4()))
                    
                    # Add uk_id at root level if not present (required for authentication).
                    # For key rotation: root uk_id = current/old key (schema-required for identity);
                    #                   key.uk_id = new key (for rotation).
                    # Both must be present simultaneously per the registry PATCH schema.
                    if 'uk_id' not in step_data:
                        step_data['uk_id'] = context.get('uk_id')
                
                response = None
                for attempt in range(max_attempts):
                    if attempt > 0:
                        time.sleep(retry_delay)
                        print(f"    [RETRY] attempt {attempt + 1}/{max_attempts}")
                    response = self.client.request(
                        method=step['method'],
                        endpoint=endpoint,
                        auth_type=auth_type,
                        subscriber_id=request_subscriber_id,
                        data=step_data if step_data else None,
                        params=step_query_params,
                        headers=custom_headers if custom_headers else None,
                        timeout=step.get('timeout', 30),
                        invalid_signature=step.get('invalid_signature', False),
                    )
                    if retry_until_status is None or response.status_code == retry_until_status:
                        break

                # Capture request details
                result.request_details.append({
                    "step_name": step_name,
                    "method": step['method'],
                    "endpoint": endpoint,
                    "url": response.request.url if hasattr(response, 'request') else None,
                    "query_params": step_query_params,
                    "auth_type": auth_type,
                    "subscriber_id": request_subscriber_id,
                    "headers": dict(response.request.headers) if hasattr(response, 'request') else {},
                    "body": step_data,
                    "description": desc,
                })
                
                try:
                    response_body = response.json()
                except Exception:
                    response_body = response.text
                
                result.response_details.append({
                    "step_name": step_name,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response_body
                })

                # Status check (supports list of expected)
                expected = step.get('expected_status', 200)
                expected_statuses = expected if isinstance(expected, list) else [expected]
                
                if response.status_code not in expected_statuses:
                    msg = f"{step_name}: Expected {expected}, got {response.status_code}"
                    if step.get('allow_failure', False):
                        print(f"    [WARN] {msg} (allow_failure=true, continuing)")
                        result.warnings.append(msg)
                    else:
                        result.error_message = msg
                        result.status_code = response.status_code
                        result.expected_status = expected
                        result.response_body = response_body
                        return False

                # save_subscriber_id
                if step.get('save_subscriber_id', False):
                    if isinstance(response_body, dict):
                        context['subscriber_id'] = response_body.get('subscriber_id', context.get('subscriber_id'))

                # validate
                if 'validate' in step:
                    rd = response_body if response_body is not None else {}
                    for validation in step['validate']:
                        validation = self._resolve_variables(validation, context)
                        if not self._validate_field(rd, validation, result):
                            failed_v = next((v for v in reversed(result.validations) if not v.get('passed')), None)
                            if failed_v:
                                err = failed_v.get('error', f"Validation failed: field '{failed_v.get('field', validation.get('field','?'))}' expected {failed_v.get('expected', '?')} but got {failed_v.get('actual', '?')}")
                                result.error_message = f"{step_name}: {err}"
                            else:
                                result.error_message = f"{step_name}: Validation failed for field '{validation.get('field', '?')}'"
                            return False

                # store from body (Group B7 enhanced)
                if 'store' in step:
                    store_src = response_body if response_body is not None else {}
                    for store_item in step['store']:
                        # store from response header (Group B6)
                        if 'header' in store_item:
                            hdr_name = store_item['header']
                            as_key = store_item.get('as', hdr_name)
                            val = response.headers.get(hdr_name)
                            if val is not None:
                                context[as_key] = val
                        else:
                            field_path = store_item.get('field', '')
                            as_key = store_item.get('as', '')
                            if field_path and as_key:
                                parts = field_path.split('.')
                                val = store_src
                                for part in parts:
                                    if isinstance(val, list) and part.isdigit():
                                        val = val[int(part)]
                                    elif isinstance(val, dict):
                                        val = val.get(part)
                                    else:
                                        val = None
                                        break
                                if val is not None:
                                    context[as_key] = val

            return True

        # setup_steps (Group D4)
        if 'setup_steps' in test:
            if not _run_steps(test['setup_steps'], phase='setup'):
                return False

        # main steps
        main_ok = _run_steps(steps, phase='main')

        # teardown_steps always run (Group D3)
        if 'teardown_steps' in test:
            _run_steps(test['teardown_steps'], phase='teardown')

        if main_ok:
            result.status_code = 200
            result.expected_status = 200
        return main_ok
    
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
        # Note: admin_password is intentionally excluded from context to prevent logging sensitive data
        test_id = test.get('id', 'test').lower()
        subscriber_id = self.data_gen.generate_subscriber_id(prefix=test_id, suffix=self.session_id)
        context = {'subscriber_id': subscriber_id, 'admin_username': self.admin_username}
        if self.auth_url:
            context['auth_url'] = self.auth_url
        
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
        
        # Build custom headers — resolve {{variables}} in values too
        custom_headers = {}
        if step.get('request_id'):
            custom_headers['X-Request-ID'] = step['request_id']
        if step.get('headers'):
            custom_headers.update(self._resolve_variables(step['headers'], context))
        
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
            msg = f"{step_name}: Expected {expected}, got {response.status_code}"
            if step.get('allow_failure', False):
                print(f"    [WARN] {msg} (allow_failure=true, continuing)")
                result.warnings.append(msg)
            else:
                result.error_message = msg
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
            except Exception:
                response_data = {}
            # Pass list/dict/str responses as-is so field paths like "0.status" work
            for validation in step['validate']:
                # Resolve {{variable}} references in the validation spec
                validation = self._resolve_variables(validation, context)
                if not self._validate_field(response_data if response_data is not None else {}, validation, result):
                    return False
        
        # Store response fields into context for later steps (with header support)
        if 'store' in step:
            try:
                store_data = response.json()
            except Exception:
                store_data = {}
            for store_item in step.get('store', []):
                if 'header' in store_item:
                    hdr_name = store_item['header']
                    as_key = store_item.get('as', hdr_name)
                    val = response.headers.get(hdr_name)
                    if val is not None:
                        context[as_key] = val
                else:
                    field_path = store_item.get('field', '')
                    as_key = store_item.get('as', '')
                    if field_path and as_key:
                        val = store_data
                        for part in field_path.split('.'):
                            if isinstance(val, list) and part.isdigit():
                                val = val[int(part)]
                            elif isinstance(val, dict):
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
        Supports:
          {{key}}          — context variable
          {{fake:email}}   — fake data (Group G1)
          {{fake:domain}}  — fake domain
          {{fake:uuid}}    — UUID
          {{env:VAR}}      — OS environment variable (Group G2)
        """
        if isinstance(data, dict):
            return {k: self._resolve_variables(v, context) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._resolve_variables(item, context) for item in data]
        elif isinstance(data, str):
            # fake data generators (Group G1)
            import random as _rnd
            data = re.sub(r'\{\{fake:email\}\}',
                          lambda _: f"user{_rnd.randint(1000,9999)}@example.com", data)
            data = re.sub(r'\{\{fake:domain\}\}',
                          lambda _: f"test-{_rnd.randint(1000,9999)}.example.com", data)
            data = re.sub(r'\{\{fake:uuid\}\}',
                          lambda _: str(uuid.uuid4()), data)
            data = re.sub(r'\{\{fake:phone\}\}',
                          lambda _: f"+91{_rnd.randint(7000000000,9999999999)}", data)
            data = re.sub(r'\{\{fake:name\}\}',
                          lambda _: _rnd.choice(['Alice','Bob','Charlie','Diana','Eve']), data)
            # OS environment variables (Group G2)
            def _env_sub(m):
                return os.environ.get(m.group(1), m.group(0))
            data = re.sub(r'\{\{env:([^}]+)\}\}', _env_sub, data)
            # context variable substitution
            for key, value in context.items():
                placeholder = f"{{{{{key}}}}}"
                if placeholder in data:
                    data = data.replace(placeholder, str(value))
            return data
        return data

    def _eval_condition(self, condition: str, context: Dict) -> bool:
        """
        Evaluate a simple condition string for skip_if/run_if.
        Supports: '{{var}} == value', '{{var}} != value', '{{var}} in [a,b]'
        """
        if not isinstance(condition, str):
            return bool(condition)
        condition = condition.strip()
        # already resolved — try simple equality
        for op in (' != ', ' == ', ' in '):
            if op in condition:
                left, right = condition.split(op, 1)
                left, right = left.strip(), right.strip()
                if op.strip() == '==':
                    return left == right
                elif op.strip() == '!=':
                    return left != right
                elif op.strip() == 'in':
                    items = [x.strip().strip("'\"") for x in right.strip('[]').split(',')]
                    return left in items
        return bool(condition)
    
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

        # Group C1: is_null / is_not_null
        if 'is_null' in validation:
            expect_null = bool(validation['is_null'])
            passed = (value is None) == expect_null
            result.validations.append({
                "field": field, "passed": passed,
                "expected": "null" if expect_null else "not null",
                "actual": "null" if value is None else repr(value)
            })
            return passed

        # Group C5: not_empty
        if validation.get('not_empty', False):
            passed = value not in (None, '', [], {})
            result.validations.append({
                "field": field, "passed": passed,
                "expected": "not empty", "actual": repr(value)
            })
            return passed

        # Group C2: type check
        if 'type' in validation:
            type_map = {
                'string': str, 'str': str,
                'number': (int, float), 'int': int, 'float': float,
                'boolean': bool, 'bool': bool,
                'array': list, 'list': list,
                'object': dict, 'dict': dict,
                'null': type(None),
            }
            expected_type = validation['type']
            expected_py = type_map.get(expected_type)
            passed = isinstance(value, expected_py) if expected_py else False
            result.validations.append({
                "field": field, "passed": passed,
                "expected": f"type {expected_type}",
                "actual": f"type {type(value).__name__}"
            })
            return passed

        # Group C3: length (string or array)
        # Supports:  length: 3          (exactly 3)
        #            length: {min: 1}   (at least 1)
        #            length: {max: 10}  (at most 10)
        #            length: {min: 2, max: 5}
        if 'length' in validation:
            length_cfg = validation['length']
            actual_len = len(value) if hasattr(value, '__len__') else None
            if isinstance(length_cfg, int):
                min_len = max_len = length_cfg
            else:
                min_len = length_cfg.get('min', 0)
                max_len = length_cfg.get('max', 2**31)
            passed = actual_len is not None and min_len <= actual_len <= max_len
            result.validations.append({
                "field": field, "passed": passed,
                "expected": f"length {min_len}..{max_len}",
                "actual": f"length {actual_len}"
            })
            return passed

        # Group C4: schema validation
        if 'schema' in validation:
            schema_file = validation['schema']
            try:
                import jsonschema
                with open(schema_file, 'r', encoding='utf-8') as sf:
                    schema = json.load(sf)
                jsonschema.validate(instance=value, schema=schema)
                passed = True
                err_msg = None
            except Exception as e:
                passed = False
                err_msg = str(e)[:200]
            result.validations.append({
                "field": field, "passed": passed,
                "expected": f"valid against {schema_file}",
                "actual": err_msg if not passed else "valid"
            })
            return passed
        
        # Check value
        if 'value' in validation:
            expected = validation['value']
            operator = validation.get('operator', '==')
            # Only guard against None for strict numeric comparisons
            if value is None and operator in ('>=', '>', '<=', '<'):
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
                label = f">= {expected}"
            elif operator == '>':
                passed = value > expected
                label = f"> {expected}"
            elif operator == '<=':
                passed = value <= expected
                label = f"<= {expected}"
            elif operator == '<':
                passed = value < expected
                label = f"< {expected}"
            elif operator == '!=':
                passed = value != expected
                label = f"!= {expected}"
            elif operator == 'contains':
                # field resolves to a list (via [*].field); checks expected value is in it
                passed = isinstance(value, list) and expected in value
                label = f"list contains {expected!r}"
            elif operator == 'not_contains':
                # field resolves to a list; checks expected value is NOT in it
                passed = not (isinstance(value, list) and expected in value)
                label = f"list not contains {expected!r}"
            elif operator == 'contains_object':
                # field=[*]; expected is a dict; at least one list item must match all k-v pairs
                if not isinstance(value, list) or not isinstance(expected, dict):
                    passed = False
                else:
                    passed = any(
                        isinstance(item, dict) and all(item.get(k) == v for k, v in expected.items())
                        for item in value
                    )
                label = f"list contains object matching {expected}"
            elif operator == 'all':
                # field resolves to a list (via [*].field); every item must equal expected
                passed = isinstance(value, list) and len(value) > 0 and all(v == expected for v in value)
                label = f"all items == {expected!r}"
            elif operator == 'any_equals':
                # at least one item in collected list equals expected
                passed = isinstance(value, list) and expected in value
                label = f"any item == {expected!r}"
            elif operator == 'count':
                # length of list equals expected integer
                actual_len = len(value) if isinstance(value, list) else 0
                passed = actual_len == expected
                result.validations.append({
                    "field": field,
                    "passed": passed,
                    "expected": f"count == {expected}",
                    "actual": f"count == {actual_len}"
                })
                return passed
            elif operator == 'in':
                # field value is one of the values in expected list
                passed = isinstance(expected, list) and value in expected
                label = f"value in {expected}"
            elif operator == 'not_in':
                # field value is NOT in expected list
                passed = isinstance(expected, list) and value not in expected
                label = f"value not in {expected}"
            elif operator == 'starts_with':
                passed = isinstance(value, str) and isinstance(expected, str) and value.startswith(expected)
                label = f"starts_with {expected!r}"
            elif operator == 'ends_with':
                passed = isinstance(value, str) and isinstance(expected, str) and value.endswith(expected)
                label = f"ends_with {expected!r}"
            elif operator == 'regex_match':
                import re
                try:
                    passed = bool(re.search(str(expected), str(value) if value is not None else ''))
                except re.error:
                    passed = False
                label = f"matches /{expected}/"
            else:
                passed = value == expected
                label = str(expected)
            result.validations.append({
                "field": field,
                "passed": passed,
                "expected": label,
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

        # Check equals (exact value match)
        if 'equals' in validation:
            expected = validation['equals']
            # Convert value to string/int for comparison if needed
            if isinstance(expected, str):
                value_to_compare = str(value) if value is not None else None
            elif isinstance(expected, int):
                try:
                    value_to_compare = int(value) if value is not None else None
                except (ValueError, TypeError):
                    value_to_compare = value
            else:
                value_to_compare = value
            
            passed = value_to_compare == expected
            result.validations.append({
                "field": field,
                "passed": passed,
                "expected": f"equals {expected}",
                "actual": value
            })
            return passed

        # Check in_range (value is within a numeric range)
        if 'in_range' in validation:
            range_cfg = validation['in_range']
            min_val = range_cfg.get('min')
            max_val = range_cfg.get('max')
            
            # Try to convert value to numeric
            try:
                if isinstance(value, str):
                    # Try to extract numeric part from string like "ERR_15001" -> 15001
                    import re
                    match = re.search(r'\d+', value)
                    numeric_value = int(match.group()) if match else None
                elif isinstance(value, (int, float)):
                    numeric_value = value
                else:
                    numeric_value = None
            except (ValueError, TypeError, AttributeError):
                numeric_value = None
            
            if numeric_value is None:
                passed = False
                result.validations.append({
                    "field": field,
                    "passed": passed,
                    "expected": f"in range [{min_val}, {max_val}]",
                    "actual": value,
                    "error": f"Cannot convert {value!r} to numeric for range check"
                })
                return False
            
            passed = (min_val is None or numeric_value >= min_val) and \
                     (max_val is None or numeric_value <= max_val)
            result.validations.append({
                "field": field,
                "passed": passed,
                "expected": f"in range [{min_val}, {max_val}]",
                "actual": f"{numeric_value} (from {value!r})"
            })
            return passed

        return True
    
    def run_all_tests(self) -> Dict:
        """Run all tests in the configuration."""
        print(f"\n{'='*70}")
        print(f"Running {self.config['test_suite']['name']}")
        print(f"Total tests: {len(self.tests)}")
        if self.dry_run:
            print(f"[DRY-RUN] No requests will be sent")
        print(f"{'='*70}\n")
        
        self.results = []
        passed = 0
        failed = 0
        passed_ids: set = set()
        
        for test in self.tests:
            test_name = test['name'].replace('→', '->').encode('ascii', 'replace').decode('ascii')
            tags_str = f" [{', '.join(test.get('tags', []))}]" if test.get('tags') else ''
            try:
                print(f"[{test['id']}] {test_name}{tags_str}")
            except UnicodeEncodeError:
                print(f"[{test['id']}] {test_name.encode('ascii','replace').decode('ascii')}{tags_str}")
            
            result = self.execute_test(test, passed_ids=passed_ids)
            self.results.append(result)
            
            if result.passed:
                print(f"  [OK] PASSED ({result.execution_time_ms}ms)\n")
                passed += 1
                passed_ids.add(test['id'])
            else:
                msg = result.error_message or ''
                print(f"  [FAIL] FAILED: {msg}")
                if result.status_code and not msg.startswith('Skipped:'):
                    print(f"    Status: {result.status_code} (expected {result.expected_status})")
                if result.warnings:
                    for w in result.warnings:
                        print(f"  [WARN] {w}")
                print()
                failed += 1
                if self.fail_fast:
                    print("[FAIL-FAST] Stopping on first failure.")
                    break
        
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
    
    def save_results(self, output_file: str, output_format: str = 'html'):
        """Save test results to JSON, HTML, and optionally JUnit XML files."""
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
        
        # JSON report
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)
        print(f"[OK] JSON report saved to {output_file}")
        
        # HTML report
        html_file = output_path.with_suffix('.html')
        test_suite_name = self.config.get('test_suite', {}).get('name', 'Test Suite')
        HTMLReporter.generate_report(
            results=summary['results'],
            output_file=str(html_file),
            test_suite_name=test_suite_name
        )
        print(f"[OK] HTML report saved to {html_file}")
        
        # JUnit XML (Group E3)
        if output_format == 'junit':
            self._save_junit_xml(output_path.with_suffix('.xml'), summary, test_suite_name)

        # Webhook notification (Group F4)
        webhook_url = os.environ.get('TEST_WEBHOOK_URL') or self.config.get('test_suite', {}).get('webhook_url')
        if webhook_url:
            self._send_webhook(webhook_url, summary)

    def _save_junit_xml(self, xml_path: Path, summary: Dict, suite_name: str):
        """Generate JUnit XML report for CI/CD integration."""
        results = summary['results']
        total = summary['summary']['total']
        failed = summary['summary']['failed']
        elapsed = sum(r.get('execution_time_ms', 0) for r in results) / 1000.0
        
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<testsuite name="{suite_name}" tests="{total}" failures="{failed}" time="{elapsed:.3f}">',
        ]
        for r in results:
            t = r.get('execution_time_ms', 0) / 1000.0
            name = r.get('name', r.get('test_id', '?')).replace('"', "'")
            classname = suite_name.replace(' ', '_')
            if r.get('passed'):
                lines.append(f'  <testcase name="{name}" classname="{classname}" time="{t:.3f}"/>')
            else:
                msg = (r.get('error_message') or 'FAILED').replace('"', "'").replace('<', '&lt;').replace('>', '&gt;')
                lines.append(f'  <testcase name="{name}" classname="{classname}" time="{t:.3f}">')
                lines.append(f'    <failure message="{msg}"/>')
                lines.append('  </testcase>')
        lines.append('</testsuite>')
        
        with open(xml_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        print(f"[OK] JUnit XML report saved to {xml_path}")

    def _send_webhook(self, url: str, summary: Dict):
        """POST run summary to a webhook URL (Group F4)."""
        import urllib.request as _req
        payload = {
            "suite": summary.get("test_suite", "Unknown"),
            "timestamp": summary.get("timestamp"),
            "total": summary["summary"]["total"],
            "passed": summary["summary"]["passed"],
            "failed": summary["summary"]["failed"],
            "pass_rate": round(
                summary["summary"]["passed"] / summary["summary"]["total"] * 100, 1
            ) if summary["summary"]["total"] else 0,
        }
        body = json.dumps(payload).encode()
        try:
            request = _req.Request(
                url, data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with _req.urlopen(request, timeout=10) as resp:
                print(f"[WEBHOOK] Notified {url} — HTTP {resp.status}")
        except Exception as exc:
            print(f"[WEBHOOK] Failed to notify {url}: {exc}")
    
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
