"""
================================================================================
ADVANCED SUBSCRIBE BASE CLASS
================================================================================
File: advanced_subscribe_base.py
Class: AdvancedSubscribeBase

Base class specifically for Advanced test scenarios.

USED BY:
  - ondc_reg_advanced.py (15 advanced tests)
    YML: ondc_reg_advanced_tests.yml

PROVIDES:
  - Multi-domain operations support
  - Concurrency and performance testing
  - Edge case handling
  - YAML-driven test execution
  - Extended request methods (GET, POST, PATCH)
================================================================================
"""
import json
import uuid
import base64
import yaml
import os
import time
import threading
import requests
from datetime import datetime, timedelta
from locust import SequentialTaskSet
from common_test_foundation.lib.proxy.proxy_server import ProxyServer
from common_test_foundation.helpers.taskset_handler import RESCHEDULE_TASK, taskset_handler
from tests.utils.registry_auth_client import RegistryAuthClient
from tests.utils.ondc_auth_helper import ONDCAuthHelper

# For proper Ed25519 key generation
from nacl.signing import SigningKey
from nacl.encoding import Base64Encoder


@taskset_handler(RESCHEDULE_TASK)
class AdvancedSubscribeBase(SequentialTaskSet):
    """Base class for advanced ONDC Registry tests with both Admin and V3 API support"""
    
    # Configuration
    config_file = 'resources/registry/ondc_reg_advanced_tests.yml'
    tenant_name = 'ondcRegistry'
    
    def on_start(self):
        """Initialize test data and configuration with both admin and V3 capabilities"""
        self.step_name = 'ON_START'
        self.proxy = ProxyServer()
        self.proxy.start_capture(trx_id=self.step_name)
        self.client.verify = self.proxy.get_certificate()
        self.client.proxies = self.proxy.get_http_proxy_config()
        
        # Load configuration
        config_file = getattr(self, 'config_file', 'resources/registry/ondc_reg_advanced_tests.yml')
        tenant_name = getattr(self, 'tenant_name', 'ondcRegistry')
        
        config = self._load_config(config_file, tenant_name)
        
        # Load config
        self.host = config.get('host', 'http://localhost:8080')
        
        # Initialize Registry Auth Client for admin API calls
        admin_username = config.get('admin_username', '<admin-user>')
        admin_password = config.get('admin_password', 'admin')
        admin_token = config.get('admin_token', None)  # Static token (optional)
        admin_auth_url = config.get('admin_auth_url', None)  # External auth service (optional)
        
        # Pass proxy configuration to auth client
        self.auth_client = RegistryAuthClient(
            self.host, 
            admin_username, 
            admin_password,
            proxies=self.proxy.get_http_proxy_config(),
            verify=self.proxy.get_certificate(),
            static_token=admin_token,
            auth_url=admin_auth_url
        )
        
        if admin_token:
            print(f"[ON_START] Using static admin token (no login required)")
        elif admin_auth_url:
            print(f"[ON_START] Using external auth service: {admin_auth_url}")
        else:
            print(f"[ON_START] Admin auth client initialized (will auto-refresh tokens)")
        
        # Test data
        self.domains = config.get('domains', ['ONDC:RET10', 'ONDC:RET11', 'ONDC:RET12', 'ONDC:AGR10', 'ONDC:TRV10'])
        self.cities = config.get('cities', ['std:080', 'std:011', 'std:022', 'std:033', 'std:044'])
        self.np_types = config.get('np_types', ['seller', 'buyer', 'logistics'])
        
        # Initialize test context for state management between tasks
        self.test_context = {}
        
        # Performance tracking
        self.performance_metrics = {}
        
        # Initialize evidence log file for dev team
        self.evidence_file = '/tmp/ondc_api_evidence.log'
        try:
            with open(self.evidence_file, 'w') as f:
                f.write("="*80 + "\n")
                f.write("ONDC REGISTRY API REQUEST/RESPONSE EVIDENCE LOG\n")
                f.write(f"Test Run: {datetime.utcnow().isoformat()}Z\n")
                f.write(f"Target Host: {self.host}\n")
                f.write("="*80 + "\n\n")
            print(f"[ON_START] Evidence file created: {self.evidence_file}")
        except Exception as e:
            print(f"[ON_START] Warning: Could not create evidence file: {e}")
            self.evidence_file = None
    
    def _log_evidence(self, title, content):
        """Log evidence to file for dev team"""
        if hasattr(self, 'evidence_file') and self.evidence_file:
            try:
                with open(self.evidence_file, 'a') as f:
                    f.write(f"{title}\n")
                    f.write(f"{content}\n\n")
            except Exception as e:
                print(f"[WARNING] Could not write evidence: {e}")
    
    def _setup_test_participant(self):
        """
        Generate fresh Ed25519 keypair and participant ID for a single test.
        Each test should call this to get isolated credentials.
        
        Returns:
            dict: Contains participant_id, uk_id, private_key_seed, 
                  signing_public_key, encryption_public_key, valid_from, valid_until
        """
        # Generate fresh Ed25519 keypair
        signing_key = SigningKey.generate()
        signing_key_bytes = bytes(signing_key)  # 32-byte seed
        
        # Generate unique IDs
        session_suffix = str(uuid.uuid4())[:6]
        participant_id = f"ctf-adv-{session_suffix}.participant.ondc"
        uk_id = str(uuid.uuid4())
        
        # Public keys
        signing_public_key = signing_key.verify_key.encode(encoder=Base64Encoder).decode('utf-8')
        encryption_public_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        
        # Timestamps (1 year validity)
        valid_from = datetime.utcnow()
        valid_until = valid_from + timedelta(days=365)
        
        return {
            'participant_id': participant_id,
            'subscriber_id': participant_id,  # Same as participant_id for self-registration scenarios
            'uk_id': uk_id,
            'private_key_seed': signing_key_bytes.hex(),
            'signing_public_key': signing_public_key,
            'encryption_public_key': encryption_public_key,
            'valid_from': valid_from.isoformat() + 'Z',
            'valid_until': valid_until.isoformat() + 'Z'
        }
    
    def _load_config(self, config_file, tenant_name):
        """Load configuration from YAML file"""
        with open(config_file, 'r') as f:
            config_data = yaml.safe_load(f)
        
        config = config_data.get(tenant_name, {})
        return config
    
    def _send_admin_request(self, method, endpoint, data, auth_type='admin', step_name='Admin Request', expected_status=None):
        """
        Send admin API request with authentication
        
        Args:
            method: HTTP method (POST, PATCH, etc.)
            endpoint: API endpoint (relative path like "/admin/subscribe")
            data: Request payload
            auth_type: 'admin' or 'none'
            step_name: Name for logging
            expected_status: List of expected HTTP status codes (for negative tests)
            
        Returns:
            tuple: (response, success, result_message)
        """
        # Default expected status
        if expected_status is None:
            expected_status = [200, 201]
        elif not isinstance(expected_status, list):
            expected_status = [expected_status]
        headers = {'Content-Type': 'application/json'}
        
        # Add admin authentication if required
        if auth_type == 'admin':
            jwt_token = self.auth_client.get_token()
            headers['Authorization'] = f'Bearer {jwt_token}'
        
        # Debug: Check data structure
        if not data:
            return None, False, "[ERROR] No data payload provided"
        
        # Log full request details for debugging (to file)
        request_log = f"""{'='*80}
REQUEST: {method} {self.host}{endpoint}
Step: {step_name}
Headers:
  Content-Type: application/json
  Authorization: Bearer {jwt_token[:30] if jwt_token else 'N/A'}...

REQUEST PAYLOAD:
{json.dumps(data, indent=2)}
{'='*80}
"""
        self._log_evidence(f"REQUEST - {step_name}", request_log)
        print(f"\n[{step_name}] Sending {method} request to {endpoint}")
        
        start_time = time.time()
        response = None
        
        # Use catch_response to manually control success/failure
        try:
            if method.upper() == 'POST':
                with self.client.post(endpoint, json=data, headers=headers, name=step_name, catch_response=True) as resp:
                    response = resp
                    # Mark as success if status is expected (including 400 for negative tests)
                    if resp.status_code in expected_status:
                        resp.success()
                    else:
                        resp.failure(f"{step_name} - Unexpected status: {resp.status_code}, expected {expected_status}")
            elif method.upper() == 'PATCH':
                with self.client.patch(endpoint, json=data, headers=headers, name=step_name, catch_response=True) as resp:
                    response = resp
                    if resp.status_code in expected_status:
                        resp.success()
                    else:
                        resp.failure(f"{step_name} - Unexpected status: {resp.status_code}, expected {expected_status}")
            elif method.upper() == 'GET':
                with self.client.get(endpoint, headers=headers, name=step_name, catch_response=True) as resp:
                    response = resp
                    if resp.status_code in expected_status:
                        resp.success()
                    else:
                        resp.failure(f"{step_name} - Unexpected status: {resp.status_code}, expected {expected_status}")
            else:
                return None, False, f"Unsupported method: {method}"
        except Exception as e:
            # Request failed entirely (network error, etc.)
            elapsed_ms = (time.time() - start_time) * 1000
            error_msg = f"{type(e).__name__}: {str(e)[:200]}" if str(e) else f"{type(e).__name__}"
            print(f"[{step_name}] Request exception: {error_msg}")
            return None, False, f"[ERROR] {error_msg} ({elapsed_ms:.0f}ms)"
        
        # Process response
        elapsed_ms = (time.time() - start_time) * 1000
        
        # Log response details for debugging (to file)
        response_log = f"""{'='*80}
RESPONSE: {response.status_code} ({elapsed_ms:.0f}ms)
Step: {step_name}

RESPONSE BODY:
"""
        try:
            response_json = response.json()
            response_log += json.dumps(response_json, indent=2)
        except:
            response_log += f"(Raw Text) {response.text[:1000]}"
        
        response_log += f"\n{'='*80}"
        self._log_evidence(f"RESPONSE - {step_name}", response_log)
        
        # Return response without judging success/failure
        # Let caller decide based on expected_status
        print(f"[{step_name}] Response {response.status_code} ({elapsed_ms:.0f}ms)")
        
        try:
            response_data = response.json()
            return response, None, f"Response {response.status_code} ({elapsed_ms:.0f}ms)"
        except:
            return response, None, f"Response {response.status_code} (no JSON) ({elapsed_ms:.0f}ms)"
    
    def _send_v3_request(self, method, endpoint, data, test_participant, step_name='V3 Request', expected_status=None):
        """
        Send V3 API request with signature authentication
        
        Args:
            method: HTTP method (POST, PATCH, etc.)
            endpoint: API endpoint (relative path like"/subscribe")
            data: Request payload
            test_participant: Dict with private_key_seed, participant_id, uk_id
            step_name: Name for logging
            expected_status: List of expected HTTP status codes (for negative tests)
            
        Returns:
            tuple: (response, success, result_message)
        """
        # Default expected status
        if expected_status is None:
            expected_status = [200, 201]
        elif not isinstance(expected_status, list):
            expected_status = [expected_status]
        # Generate V3 signature
        private_key_seed = test_participant['private_key_seed']
        participant_id = test_participant['participant_id']
        uk_id = test_participant['uk_id']
        
        # Initialize ONDC Auth Helper for signature generation
        auth_helper = ONDCAuthHelper(private_key_seed)
        
        # Generate signature
        signature_header = auth_helper.generate_signature_header(
            json.dumps(data),
            participant_id,
            uk_id
        )
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': signature_header
        }
        
        start_time = time.time()
        response = None
        
        # Use catch_response to manually control success/failure
        try:
            if method.upper() == 'POST':
                with self.client.post(endpoint, json=data, headers=headers, name=step_name, catch_response=True) as resp:
                    response = resp
                    if resp.status_code in expected_status:
                        resp.success()
                    else:
                        resp.failure(f"{step_name} - Unexpected status: {resp.status_code}, expected {expected_status}")
            elif method.upper() == 'PATCH':
                with self.client.patch(endpoint, json=data, headers=headers, name=step_name, catch_response=True) as resp:
                    response = resp
                    if resp.status_code in expected_status:
                        resp.success()
                    else:
                        resp.failure(f"{step_name} - Unexpected status: {resp.status_code}, expected {expected_status}")
            else:
                return None, False, f"Unsupported method: {method}"
        except Exception as e:
            # Request failed entirely (network error, etc.)
            elapsed_ms = (time.time() - start_time) * 1000
            error_msg = f"{type(e).__name__}: {str(e)[:200]}" if str(e) else f"{type(e).__name__}"
            print(f"[{step_name}] Request exception: {error_msg}")
            return None, False, f"[ERROR] {error_msg} ({elapsed_ms:.0f}ms)"
        
        # Process response
        elapsed_ms = (time.time() - start_time) * 1000
        
        # Return response without judging success/failure
        # Let caller decide based on expected_status
        try:
            response_data = response.json()
            return response, None, f"Response {response.status_code} ({elapsed_ms:.0f}ms)"
        except:
            return response, None, f"Response {response.status_code} (no JSON) ({elapsed_ms:.0f}ms)"

    
    def _execute_concurrent_steps(self, steps, test_data):
        """
        Execute multiple steps concurrently
        
        Args:
            steps: List of step definitions
            test_data: Shared test data context
            
        Returns:
            list: Results from all concurrent executions
        """
        results = []
        threads = []
        lock = threading.Lock()
        
        def execute_step_thread(step, step_index):
            result = self._execute_single_step(step, test_data, concurrent=True)
            with lock:
                results.append((step_index, result))
        
        # Start all concurrent threads
        for idx, step in enumerate(steps):
            if step.get('concurrent', False):
                thread = threading.Thread(target=execute_step_thread, args=(step, idx))
                threads.append(thread)
                thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Sort results by original order
        results.sort(key=lambda x: x[0])
        return [r[1] for r in results]
    
    def _execute_batch_operation(self, step, batch_size, test_name):
        """
        Execute batch operation (create/update multiple participants)
        
        Args:
            step: Step definition
            batch_size: Number of participants to create/update
            test_name: Name for tracking
            
        Returns:
            tuple: (success_count, fail_count, elapsed_ms)
        """
        import copy
        success_count = 0
        fail_count = 0
        start_time = time.time()
        
        for i in range(batch_size):
            # Generate test data for each participant
            test_data = self._setup_test_participant()
            
            # Build payload with participant data injected
            data = copy.deepcopy(step.get('data', {}))
            
            # Inject participant_id at top level if not present
            if 'participant_id' not in data:
                data['participant_id'] = test_data['participant_id']
            
            # Inject subscriber_id into each config if not present
            if 'configs' in data:
                for config in data['configs']:
                    if 'subscriber_id' not in config:
                        config['subscriber_id'] = test_data['participant_id']
            
            # Substitute variables in data
            data = self._substitute_variables(data, test_data)
            
            # Execute request
            auth_type = step.get('auth_type', 'admin')
            method = step.get('method', 'POST')
            endpoint = step.get('endpoint', '/admin/subscribe')
            
            if auth_type == 'v3':
                response, success, _ = self._send_v3_request(method, endpoint, data, test_data, f"{test_name}_batch_{i}")
            else:
                response, success, _ = self._send_admin_request(method, endpoint, data, auth_type, f"{test_name}_batch_{i}")
            
            # Check response status (success may be None from request methods)
            expected_status = step.get('expected_status', 200)
            if not isinstance(expected_status, list):
                expected_status = [expected_status]
            
            if response and response.status_code in expected_status:
                success_count += 1
            else:
                fail_count += 1
        
        elapsed_ms = (time.time() - start_time) * 1000
        return success_count, fail_count, elapsed_ms
    
    def _substitute_variables(self, data, test_data):
        """
        Substitute variables in data with actual values from test_data
        
        Args:
            data: Dict or string with {{variable}} placeholders  
            test_data: Dict with actual values
            
        Returns:
            Substituted data
        """
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                result[key] = self._substitute_variables(value, test_data)
            return result
        elif isinstance(data, list):
            return [self._substitute_variables(item, test_data) for item in data]
        elif isinstance(data, str):
            # Replace {{variable}} with actual value
            for var_name, var_value in test_data.items():
                placeholder = f"{{{{{var_name}}}}}"
                if placeholder in data:
                    data = data.replace(placeholder, str(var_value))
            return data
        else:
            return data
    
    def _execute_single_step(self, step, test_data, concurrent=False):
        """Execute a single test step"""
        step_name = step.get('name', step.get('id', 'Unnamed Step'))
        method = step.get('method', 'POST')
        endpoint = step.get('endpoint', '/admin/subscribe')
        auth_type = step.get('auth_type', 'admin')
        expected_status = step.get('expected_status', 200)
        
        # Convert single status to list
        if not isinstance(expected_status, list):
            expected_status = [expected_status]
        
        # Substitute variables in data (idempotent if already substituted)
        data = self._substitute_variables(step.get('data', {}), test_data)
        
        # Execute request based on auth type (pass expected_status for proper handling)
        if auth_type == 'v3':
            response, success, message = self._send_v3_request(method, endpoint, data, test_data, step_name, expected_status)
        else:
            response, success, message = self._send_admin_request(method, endpoint, data, auth_type, step_name, expected_status)
        
        # Check if status matches expected (this is the authoritative success check)
        if response and response.status_code in expected_status:
            success = True
            message = f"[PASS] Status {response.status_code} (expected {expected_status})"
        elif response and response.status_code not in expected_status:
            success = False
            message = f"[FAIL] Expected {expected_status}, got {response.status_code}"
        elif response is None:
            success = False
            message = message or "[FAIL] No response received"
        
        # Save data if requested
        if success is True and step.get('save_subscriber_id', False):
            try:
                response_data = response.json()
                if 'subscriber_id' in response_data:
                    test_data['subscriber_id'] = response_data['subscriber_id']
            except:
                pass
        
        return {
            'step_name': step_name,
            'success': success,
            'message': message,
            'response': response
        }
    
    def on_stop(self):
        """Cleanup after test run"""
        self.step_name = 'ON_STOP'
        if hasattr(self, 'proxy') and self.proxy:
            self.proxy.stop_capture()
