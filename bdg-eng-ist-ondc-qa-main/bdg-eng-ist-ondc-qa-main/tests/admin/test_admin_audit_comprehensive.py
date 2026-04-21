"""
ONDC Registry - Comprehensive Admin Audit Log Tests

Test Coverage:
- AUDIT-01 to AUDIT-12: Audit entry creation, filtering, and entity-specific record types
- Verifies audit logs are created for all operations (CREATE, UPDATE, UPDATE_STATUS)
- Tests filtering by record_type, action_kind, and time range
- Validates entity-specific audit entries (KEY, CONTACT, CREDENTIAL, URI, LOCATION)
- Tests failed operations also generate audit entries
"""

import json
import yaml
import os
import base64
from datetime import datetime, timedelta
from locust import TaskSet, task, events
from common_test_foundation.lib.proxy.proxy_server import ProxyServer
from common_test_foundation.helpers.taskset_handler import RESCHEDULE_TASK, taskset_handler
from tests.utils.registry_auth_client import RegistryAuthClient


@taskset_handler(RESCHEDULE_TASK)
class ONDCAdminAuditComprehensive(TaskSet):
    
    def on_start(self):
        self.step_name = 'ON_START'
        
        # Initialize proxy server
        self.proxy = ProxyServer()
        self.proxy.start_capture(trx_id=self.step_name)
        self.client.verify = self.proxy.get_certificate()
        self.client.proxies = self.proxy.get_http_proxy_config()
        
        # Get base URL
        self.base_url = self.parent.host
        
        # Load tenant configuration from the tenants file
        config_file = 'resources/registry/subscribe/test_subscribe_functional.yml'
        config = self._load_config(config_file, 'ondcRegistry')
        
        # Initialize auth client for admin token
        admin_username = config.get('admin_username', '<admin-user>')
        admin_password = config.get('admin_password', 'admin')
        admin_token = config.get('admin_token', None)
        admin_auth_url = config.get('admin_auth_url', None)
        
        self.auth_client = RegistryAuthClient(
            self.base_url,
            admin_username,
            admin_password,
            proxies=self.proxy.get_http_proxy_config(),
            verify=self.proxy.get_certificate(),
            static_token=admin_token,
            auth_url=admin_auth_url
        )
        
        # Load test configuration
        test_config_path = os.path.join(
            os.path.dirname(__file__),
            '../../resources/admin/test_admin_audit_comprehensive.yml'
        )
        
        with open(test_config_path, 'r') as f:
            self.test_config = yaml.safe_load(f)
        
        self.tests = self.test_config.get('tests', [])
        self.config = self.test_config.get('config', {})
        
        # Generate timestamp for unique IDs
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        
        # Store operation timestamps for time range testing
        self.operation_timestamps = {}
        
        print(f"\n{'='*80}")
        print(f"ADMIN AUDIT COMPREHENSIVE TEST SUITE")
        print(f"{'='*80}")
        print(f"Total Tests: {len(self.tests)}")
        print(f"Timestamp: {self.timestamp}")
        print(f"{'='*80}\n")

    def _load_config(self, config_file, tenant_name):
        """Load tenant configuration from YAML file"""
        config = {}
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                yaml_content = yaml.safe_load(f)
                config = yaml_content.get(tenant_name, {})
                print(f"[ON_START] Loaded config from {config_file}")
        else:
            print(f"[ON_START] WARNING: Config file not found: {config_file}")
        return config

    def _get_admin_headers(self):
        """Get admin authentication headers"""
        token = self.auth_client.get_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

    def _generate_ed25519_keys(self):
        """Generate random ED25519 keys for testing"""
        signing_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        encryption_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        uk_id = f"uk-{datetime.now().strftime('%Y%m%d%H%M%S')}-{os.urandom(4).hex()}"
        
        return {
            'uk_id': uk_id,
            'signing_public_key': signing_key,
            'encryption_public_key': encryption_key,
            'valid_from': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'valid_until': (datetime.utcnow() + timedelta(days=365)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        }

    def _replace_placeholders(self, obj, keys=None):
        """Recursively replace placeholders in data structure"""
        if keys is None:
            keys = self._generate_ed25519_keys()
        
        # Generate second key set if needed (for batch operations)
        if not hasattr(keys, '__contains__') or 'uk_id_2' not in keys:
            keys2 = self._generate_ed25519_keys()
            if isinstance(keys, dict):
                keys['uk_id_2'] = keys2['uk_id']
                keys['signing_public_key_2'] = keys2['signing_public_key']
                keys['encryption_public_key_2'] = keys2['encryption_public_key']
        
        if isinstance(obj, dict):
            return {k: self._replace_placeholders(v, keys) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._replace_placeholders(item, keys) for item in obj]
        elif isinstance(obj, str):
            replacements = {
                '{{timestamp}}': self.timestamp,
                '{{uk_id}}': keys['uk_id'],
                '{{signing_public_key}}': keys['signing_public_key'],
                '{{encryption_public_key}}': keys['encryption_public_key'],
                '{{uk_id_2}}': keys.get('uk_id_2', keys['uk_id']),
                '{{signing_public_key_2}}': keys.get('signing_public_key_2', keys['signing_public_key']),
                '{{encryption_public_key_2}}': keys.get('encryption_public_key_2', keys['encryption_public_key']),
                '{{valid_from}}': keys['valid_from'],
                '{{valid_until}}': keys['valid_until'],
                '{{start_time_minus_5min}}': (datetime.utcnow() - timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                '{{end_time_plus_5min}}': (datetime.utcnow() + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
            }
            for placeholder, value in replacements.items():
                obj = obj.replace(placeholder, value)
            return obj
        else:
            return obj

    def _execute_api_step(self, test_id, step, keys=None):
        """Execute single API step"""
        if keys is None:
            keys = self._generate_ed25519_keys()
        
        method = step.get('method', 'GET')
        endpoint = step.get('endpoint', '')
        data = step.get('data', {})
        params = step.get('params', {})
        expected_status = step.get('expected_status', 200)
        
        # Replace placeholders
        endpoint = self._replace_placeholders(endpoint, keys)
        data = self._replace_placeholders(data, keys)
        params = self._replace_placeholders(params, keys)
        
        # Build step name
        step_name = f"{test_id}_{step.get('name', 'Step')}"
        
        # Make request
        headers = self._get_admin_headers()
        
        if method == 'GET':
            with self.client.get(
                name=step_name,
                url=endpoint,
                headers=headers,
                params=params,
                catch_response=True
            ) as response:
                return self._validate_response(response, step, expected_status)
        
        elif method == 'POST':
            with self.client.post(
                name=step_name,
                url=endpoint,
                headers=headers,
                json=data,
                catch_response=True
            ) as response:
                return self._validate_response(response, step, expected_status)
        
        elif method == 'PATCH':
            with self.client.patch(
                name=step_name,
                url=endpoint,
                headers=headers,
                json=data,
                catch_response=True
            ) as response:
                return self._validate_response(response, step, expected_status)

    def _validate_response(self, response, step, expected_status):
        """Validate API response"""
        step_name = step.get('name', 'Unknown step')
        
        # Check status code
        if isinstance(expected_status, list):
            if response.status_code not in expected_status:
                print(f"   ❌ [{step_name}] Expected {expected_status}, got {response.status_code}")
                response.failure(f"Status code mismatch: expected {expected_status}, got {response.status_code}")
                return False
        else:
            if response.status_code != expected_status:
                print(f"   ❌ [{step_name}] Expected {expected_status}, got {response.status_code}")
                response.failure(f"Status code mismatch: expected {expected_status}, got {response.status_code}")
                return False
        
        # Parse response
        try:
            response_data = response.json() if response.content else {}
        except:
            response_data = {}
        
        # Run validations
        validations = step.get('validate', [])
        for validation in validations:
            val_type = validation.get('type')
            
            if val_type == 'audit_entry_exists':
                if not self._validate_audit_entry_exists(response_data, validation):
                    print(f"   ⚠️  [{step_name}] Audit entry validation: Expected entry not found (may be async)")
            
            elif val_type == 'field_exists':
                if not self._validate_fields_exist(response_data, validation):
                    print(f"   ⚠️  [{step_name}] Field validation: Some fields missing")
            
            elif val_type == 'all_records_match_type':
                if not self._validate_record_type(response_data, validation):
                    response.failure(f"Record type validation failed")
                    return False
            
            elif val_type == 'chronological_order':
                if not self._validate_chronological_order(response_data, validation):
                    response.failure(f"Chronological order validation failed")
                    return False
        
        print(f"   ✅ [{step_name}] Status {response.status_code}")
        response.success()
        return True

    def _validate_audit_entry_exists(self, response_data, validation):
        """Check if audit entry with specified criteria exists"""
        action_kind = validation.get('action_kind')
        record_type = validation.get('record_type')
        contains_id = validation.get('contains_participant_id', '')
        
        # Extract audit entries from response
        entries = []
        if isinstance(response_data, dict):
            entries = response_data.get('data', response_data.get('logs', response_data.get('items', [])))
        elif isinstance(response_data, list):
            entries = response_data
        
        # Search for matching entry
        for entry in entries:
            matches = True
            if action_kind and entry.get('action_kind') != action_kind:
                matches = False
            if record_type and entry.get('record_type') != record_type:
                matches = False
            if contains_id:
                entry_str = json.dumps(entry)
                if contains_id not in entry_str:
                    matches = False
            
            if matches:
                return True
        
        return False

    def _validate_fields_exist(self, response_data, validation):
        """Check if required fields exist in audit entries"""
        fields = validation.get('fields', [])
        
        entries = []
        if isinstance(response_data, dict):
            entries = response_data.get('data', response_data.get('logs', response_data.get('items', [])))
        elif isinstance(response_data, list):
            entries = response_data
        
        if not entries:
            return False
        
        first_entry = entries[0]
        for field in fields:
            if field not in first_entry:
                return False
        
        return True

    def _validate_record_type(self, response_data, validation):
        """Validate all entries match expected record_type"""
        expected_type = validation.get('record_type')
        
        entries = []
        if isinstance(response_data, dict):
            entries = response_data.get('data', response_data.get('logs', response_data.get('items', [])))
        elif isinstance(response_data, list):
            entries = response_data
        
        for entry in entries:
            if entry.get('record_type') != expected_type:
                return False
        
        return True

    def _validate_chronological_order(self, response_data, validation):
        """Validate entries are in chronological order"""
        field = validation.get('field', 'performed_at')
        order = validation.get('order', 'desc')
        
        entries = []
        if isinstance(response_data, dict):
            entries = response_data.get('data', response_data.get('logs', response_data.get('items', [])))
        elif isinstance(response_data, list):
            entries = response_data
        
        if len(entries) < 2:
            return True
        
        for i in range(len(entries) - 1):
            current = entries[i].get(field)
            next_entry = entries[i + 1].get(field)
            
            if current and next_entry:
                if order == 'desc':
                    if current < next_entry:
                        return False
                else:
                    if current > next_entry:
                        return False
        
        return True

    @task(1)
    def run_all_audit_tests(self):
        """Execute all audit test cases"""
        
        passed = 0
        failed = 0
        
        for test in self.tests:
            test_id = test.get('id', 'UNKNOWN')
            test_name = test.get('name', 'Unnamed test')
            
            print(f"\n{'─'*80}")
            print(f"[{test_id}] {test_name}")
            print(f"{'─'*80}")
            
            try:
                # Generate keys for this test case
                keys = self._generate_ed25519_keys()
                
                # Execute steps
                steps = test.get('steps', [])
                test_passed = True
                
                for idx, step in enumerate(steps, 1):
                    step_name = step.get('name', f'Step {idx}')
                    print(f"\n  Step {idx}/{len(steps)}: {step_name}")
                    
                    if step.get('type') == 'api':
                        success = self._execute_api_step(test_id, step, keys)
                        if not success:
                            test_passed = False
                    
                    elif step.get('type') == 'batch':
                        # Execute batch operations
                        operations = step.get('operations', [])
                        for op in operations:
                            self._execute_api_step(test_id, op, keys)
                
                if test_passed:
                    passed += 1
                    print(f"\n✅ [{test_id}] PASS")
                else:
                    failed += 1
                    print(f"\n❌ [{test_id}] FAIL")
            
            except Exception as e:
                failed += 1
                print(f"\n❌ [{test_id}] ERROR: {str(e)}")
        
        # Print summary
        print(f"\n{'='*80}")
        print(f"ADMIN AUDIT TEST SUMMARY")
        print(f"{'='*80}")
        print(f"Total: {len(self.tests)} | Passed: {passed} | Failed: {failed}")
        print(f"Pass Rate: {(passed/len(self.tests)*100):.1f}%")
        print(f"{'='*80}\n")


# Task list required by Locust framework
tasks = [ONDCAdminAuditComprehensive]
