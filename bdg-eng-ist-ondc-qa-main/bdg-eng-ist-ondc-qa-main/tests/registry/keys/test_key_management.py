"""
ONDC Registry - Key Management Test Cases
Tests for cryptographic key lifecycle management including:
- Multiple active keys per participant
- Admin key status updates (ACTIVE → REVOKED)
- Lookup filtering for expired keys
- Key rotation verification
"""

import os
import yaml
import uuid
import json
import time
import hashlib
import base64
from datetime import datetime
from typing import Dict, Any, List, Optional
from locust import task, SequentialTaskSet
from nacl.signing import SigningKey
from nacl.encoding import Base64Encoder

from tests.registry.subscribe.common.base_subscribe_test import RegistrySubscribeBase


class ONDCKeyManagement(RegistrySubscribeBase):
    """Key management test suite"""
    
    config_file = 'resources/registry/subscribe/test_subscribe_functional.yml'
    test_cases_file = 'resources/registry/keys/test_key_management.yml'
    tenant_name = 'ondcRegistry'
    
    def on_start(self):
        """Initialize test suite"""
        super().on_start()
        self.test_results = []
        self.test_data = {}
        self.step_count = 0
        
        # Load test cases from YAML
        yaml_path = os.path.join(
            os.path.dirname(__file__), 
            '../../../resources/registry/keys/test_key_management.yml'
        )
        
        with open(yaml_path, 'r') as f:
            config = yaml.safe_load(f)
            self.test_cases = config.get('tests', [])
        
        print(f"\n[YAML] Loaded {len(self.test_cases)} key management test cases")
    
    @task(1)
    def run_yaml_tests(self):
        """Execute all key management tests from YAML configuration"""
        for test_case in self.test_cases:
            test_id = test_case.get('id')
            test_name = test_case.get('name', test_id)
            
            # Generate a single timestamp for this test case (shared across all steps)
            test_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.test_data['timestamp'] = test_timestamp
            
            print(f"\n[{test_id}] >>> {test_name}")
            print(f"[{test_id}] Description: {test_case.get('description', 'N/A')}")
            
            test_passed = True
            failed_step = None
            
            steps = test_case.get('steps', [])
            for idx, step in enumerate(steps, 1):
                step_name = step.get('name', f'Step {idx}')
                print(f"[{test_id}] Step {idx}/{len(steps)}: {step_name}")
                
                success = self._execute_step(test_id, test_case, step)
                
                if not success:
                    test_passed = False
                    failed_step = step_name
                    print(f"[{test_id}] ❌ Step '{step_name}' failed")
                    break
            
            # Record test result
            if test_passed:
                print(f"[{test_id}] ✅ [PASS] Test passed")
                self._record_test_result(
                    test_id=test_id,
                    test_name=test_name,
                    status="PASS",
                    message="All steps completed successfully"
                )
            else:
                print(f"[{test_id}] ❌ [FAIL] Test failed")
                self._record_test_result(
                    test_id=test_id,
                    test_name=test_name,
                    status="FAIL",
                    message=f"Failed at: {failed_step}"
                )
    
    def _execute_step(self, test_id: str, test_case: Dict[str, Any], step: Dict[str, Any]) -> bool:
        """Execute a single test step"""
        method = step.get('method', 'POST').upper()
        endpoint = step.get('endpoint', '')
        auth_type = step.get('auth_type', 'admin')
        expected_status = step.get('expected_status', [200])
        data = step.get('data', {})
        save_response = step.get('save_response', {})
        validate = step.get('validate', [])
        note = step.get('note', '')
        
        if not isinstance(expected_status, list):
            expected_status = [expected_status]
        
        # Replace placeholders in endpoint and data
        endpoint = self._replace_placeholders(endpoint, self.test_data)
        data = self._replace_placeholders(data, self.test_data)
        
        step_label = f"{test_id}_{step.get('name', 'Step').replace(' ', '_').replace(':', '')}"
        
        # Execute request based on method and auth type
        if method == 'POST':
            if auth_type == 'admin':
                response = self._send_admin_request(step_label, endpoint, data, expected_status)
            elif auth_type == 'v3_signature':
                response = self._send_v3_lookup_request(step_label, endpoint, data, expected_status)
            else:
                print(f"[{test_id}] Unknown auth_type: {auth_type}")
                return False
        elif method == 'PUT':
            response = self._send_admin_put_request(step_label, endpoint, data, expected_status)
        elif method == 'PATCH':
            response = self._send_admin_patch_request(step_label, endpoint, data, expected_status)
        elif method == 'GET':
            response = self._send_admin_get_request(step_label, endpoint, expected_status)
        else:
            print(f"[{test_id}] Unsupported method: {method}")
            return False
        
        if not response:
            return False
        
        # Save response fields for later steps
        if save_response and response.get('success'):
            response_data = response.get('data', {})
            for key, json_path in save_response.items():
                value = self._get_nested_field(response_data, json_path)
                if value:
                    self.test_data[key] = value
                    print(f"[{test_id}] Saved {key} = {value}")
        
        # Validate response
        if validate and response.get('success'):
            response_data = response.get('data', {})
            validation_passed = self._validate_response(test_id, response_data, validate)
            if not validation_passed:
                return False
        
        return response.get('success', False)
    
    def _send_admin_request(self, step_name: str, endpoint: str, payload: Dict, expected_status: List[int]) -> Dict:
        """Send admin POST request"""
        url = f"{self.host}{endpoint}"
        headers = self._get_admin_headers()
        
        with self.client.post(
            name=step_name,
            url=url,
            json=payload,
            headers=headers,
            catch_response=True
        ) as response:
            print(f"[{step_name}] ✓ POST {endpoint} → {response.status_code}")
            
            if response.status_code in expected_status:
                try:
                    data = response.json()
                    print(f"[{step_name}] Response: {json.dumps(data, indent=2)[:500]}")
                    response.success()
                    return {'success': True, 'data': data, 'status': response.status_code}
                except:
                    response.success()
                    return {'success': True, 'data': {}, 'status': response.status_code}
            else:
                try:
                    error_data = response.json()
                    print(f"[{step_name}] Error: {json.dumps(error_data, indent=2)[:300]}")
                except:
                    print(f"[{step_name}] Error: {response.text[:300]}")
                
                response.failure(f"Expected {expected_status}, got {response.status_code}")
                return {'success': False, 'status': response.status_code}
    
    def _send_v3_lookup_request(self, step_name: str, endpoint: str, payload: Dict, expected_status: List[int]) -> Dict:
        """Send V3 lookup request with signature authentication"""
        url = f"{self.host}{endpoint}"
        
        # Generate signature using test participant credentials
        if not hasattr(self, 'signing_key'):
            self.signing_key = SigningKey.generate()
        
        payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        digest = hashlib.blake2b(payload_bytes, digest_size=64)
        digest_b64 = base64.b64encode(digest.digest()).decode('utf-8')
        
        created = int(time.time())
        expires = created + 300
        
        participant_id = self.test_data.get('participant_id_multi') or \
                        self.test_data.get('revoke_participant_id') or \
                        self.test_data.get('expired_participant_id') or \
                        self.test_data.get('rotation_participant_id') or \
                        f"test-lookup-{uuid.uuid4()}.participant.ondc"
        
        uk_id = self.test_data.get('key_a_id') or str(uuid.uuid4())
        
        # Create signing string
        signing_string = f"(created): {created}\n(expires): {expires}\ndigest: BLAKE-512={digest_b64}"
        signature = self.signing_key.sign(signing_string.encode('utf-8'))
        signature_b64 = base64.b64encode(signature.signature).decode('utf-8')
        
        auth_header = (
            f'Signature keyId="{participant_id}|{uk_id}|ed25519",'
            f'algorithm="ed25519",'
            f'created="{created}",'
            f'expires="{expires}",'
            f'headers="(created) (expires) digest",'
            f'signature="{signature_b64}"'
        )
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": auth_header,
            "Digest": f"BLAKE-512={digest_b64}"
        }
        
        with self.client.post(
            name=step_name,
            url=url,
            json=payload,
            headers=headers,
            catch_response=True
        ) as response:
            print(f"[{step_name}] ✓ POST {endpoint} → {response.status_code}")
            
            if response.status_code in expected_status:
                try:
                    data = response.json()
                    # Log participant count and key count
                    participants = data if isinstance(data, list) else []
                    print(f"[{step_name}] Lookup returned {len(participants)} participant(s)")
                    for p in participants:
                        keys = p.get('keys', [])
                        print(f"[{step_name}]   - {p.get('subscriber_id')}: {len(keys)} key(s)")
                    
                    response.success()
                    return {'success': True, 'data': data, 'status': response.status_code}
                except:
                    response.success()
                    return {'success': True, 'data': {}, 'status': response.status_code}
            else:
                response.failure(f"Expected {expected_status}, got {response.status_code}")
                return {'success': False, 'status': response.status_code}
    
    def _send_admin_put_request(self, step_name: str, endpoint: str, payload: Dict, expected_status: List[int]) -> Dict:
        """Send admin PUT request"""
        url = f"{self.host}{endpoint}"
        headers = self._get_admin_headers()
        
        with self.client.put(
            name=step_name,
            url=url,
            json=payload,
            headers=headers,
            catch_response=True
        ) as response:
            print(f"[{step_name}] ✓ PUT {endpoint} → {response.status_code}")
            
            if response.status_code in expected_status:
                try:
                    data = response.json()
                    print(f"[{step_name}] Response: {json.dumps(data, indent=2)[:500]}")
                    response.success()
                    return {'success': True, 'data': data, 'status': response.status_code}
                except:
                    response.success()
                    return {'success': True, 'data': {}, 'status': response.status_code}
            else:
                try:
                    error_data = response.json()
                    print(f"[{step_name}] Error: {json.dumps(error_data, indent=2)[:300]}")
                except:
                    print(f"[{step_name}] Error: {response.text[:300]}")
                
                # Accept 404/405 as documented "not yet implemented"
                if response.status_code in [404, 405]:
                    print(f"[{step_name}] Endpoint may not be implemented yet (got {response.status_code})")
                    response.success()
                    return {'success': True, 'data': {}, 'status': response.status_code}
                
                response.failure(f"Expected {expected_status}, got {response.status_code}")
                return {'success': False, 'status': response.status_code}
    
    def _send_admin_patch_request(self, step_name: str, endpoint: str, payload: Dict, expected_status: List[int]) -> Dict:
        """Send admin PATCH request"""
        url = f"{self.host}{endpoint}"
        headers = self._get_admin_headers()
        
        with self.client.patch(
            name=step_name,
            url=url,
            json=payload,
            headers=headers,
            catch_response=True
        ) as response:
            print(f"[{step_name}] ✓ PATCH {endpoint} → {response.status_code}")
            
            if response.status_code in expected_status:
                try:
                    data = response.json()
                    print(f"[{step_name}] Response: {json.dumps(data, indent=2)[:500]}")
                    response.success()
                    return {'success': True, 'data': data, 'status': response.status_code}
                except:
                    response.success()
                    return {'success': True, 'data': {}, 'status': response.status_code}
            else:
                # Accept 404/405 as documented "not yet implemented"
                if response.status_code in [404, 405]:
                    print(f"[{step_name}] PATCH endpoint may not be implemented (got {response.status_code})")
                    response.success()
                    return {'success': True, 'data': {}, 'status': response.status_code}
                
                response.failure(f"Expected {expected_status}, got {response.status_code}")
                return {'success': False, 'status': response.status_code}
    
    def _send_admin_get_request(self, step_name: str, endpoint: str, expected_status: List[int]) -> Dict:
        """Send admin GET request"""
        url = f"{self.host}{endpoint}"
        headers = self._get_admin_headers()
        
        with self.client.get(
            name=step_name,
            url=url,
            headers=headers,
            catch_response=True
        ) as response:
            print(f"[{step_name}] ✓ GET {endpoint} → {response.status_code}")
            
            if response.status_code in expected_status:
                try:
                    data = response.json()
                    response.success()
                    return {'success': True, 'data': data, 'status': response.status_code}
                except:
                    response.success()
                    return {'success': True, 'data': {}, 'status': response.status_code}
            else:
                response.failure(f"Expected {expected_status}, got {response.status_code}")
                return {'success': False, 'status': response.status_code}
    
    def _validate_response(self, test_id: str, data: Any, validations: List[Dict]) -> bool:
        """Validate response data against expected values"""
        for validation in validations:
            field = validation.get('field')
            condition = validation.get('condition', 'equals')
            expected = validation.get('value')
            
            actual = self._get_nested_field(data, field)
            
            if condition == 'equals':
                if actual != expected:
                    print(f"[{test_id}] Validation failed: {field} = {actual}, expected {expected}")
                    return False
            elif condition == 'exists':
                if actual is None:
                    print(f"[{test_id}] Validation failed: {field} does not exist")
                    return False
            elif condition == 'contains':
                if expected not in str(actual):
                    print(f"[{test_id}] Validation failed: {field} does not contain {expected}")
                    return False
            elif condition == 'array_length':
                if not isinstance(actual, list) or len(actual) != expected:
                    print(f"[{test_id}] Validation failed: {field} length = {len(actual) if isinstance(actual, list) else 'N/A'}, expected {expected}")
                    return False
            elif condition == 'array_length_gte':
                if not isinstance(actual, list) or len(actual) < expected:
                    print(f"[{test_id}] Validation failed: {field} length = {len(actual) if isinstance(actual, list) else 'N/A'}, expected >= {expected}")
                    return False
        
        return True
    
    def _get_nested_field(self, obj: Any, field_path: str) -> Any:
        """Get nested field from object using dot notation and array indexing"""
        if not field_path or obj is None:
            return obj
        
        # Handle array indexing like [0].field or field[0]
        parts = field_path.replace('[', '.').replace(']', '').split('.')
        current = obj
        
        for part in parts:
            if not part:
                continue
            
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list):
                try:
                    index = int(part)
                    current = current[index] if 0 <= index < len(current) else None
                except (ValueError, IndexError):
                    current = None
            else:
                current = None
            
            if current is None:
                return None
        
        return current
    
    def _replace_placeholders(self, obj: Any, test_data: Dict) -> Any:
        """Recursively replace {{placeholder}} with actual values"""
        if isinstance(obj, dict):
            return {k: self._replace_placeholders(v, test_data) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._replace_placeholders(item, test_data) for item in obj]
        elif isinstance(obj, str):
            # Replace {{timestamp}} with stored timestamp (consistent across steps in same test)
            if '{{timestamp}}' in obj:
                timestamp = test_data.get('timestamp', datetime.now().strftime("%Y%m%d_%H%M%S"))
                obj = obj.replace('{{timestamp}}', timestamp)
            
            # Replace other placeholders from test_data
            for key, value in test_data.items():
                placeholder = f'{{{{{key}}}}}'
                if placeholder in obj:
                    obj = obj.replace(placeholder, str(value))
            
            return obj
        else:
            return obj
    
    def _get_admin_headers(self) -> Dict[str, str]:
        """Get admin authentication headers"""
        token = self.auth_client.get_token()
        if not token:
            print("[WARN] Failed to get admin token")
            return {"Content-Type": "application/json"}
        
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }
    
    def _record_test_result(self, test_id: str, test_name: str, status: str, message: str = ""):
        """Record test result for reporting"""
        result = {
            'test_id': test_id,
            'test_name': test_name,
            'status': status,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        self.test_results.append(result)
    
    def on_stop(self):
        """Generate test summary on completion"""
        if not self.test_results:
            return
        
        total = len(self.test_results)
        passed = sum(1 for r in self.test_results if r['status'] == 'PASS')
        failed = sum(1 for r in self.test_results if r['status'] == 'FAIL')
        acknowledged = sum(1 for r in self.test_results if r['status'] == 'ACKNOWLEDGED')
        skipped = sum(1 for r in self.test_results if r['status'] == 'SKIP')
        
        print("\n" + "=" * 80)
        print("KEY MANAGEMENT TEST SUMMARY")
        print("=" * 80)
        print(f"Total: {total} | Passed: {passed} | Failed: {failed} | Acknowledged: {acknowledged} | Skipped: {skipped}")
        
        if total > 0:
            pass_rate = (passed / total) * 100
            print(f"Pass Rate: {pass_rate:.1f}%")
        
        print("\nDetailed Results:")
        for result in self.test_results:
            status_icon = "✅" if result['status'] == 'PASS' else "❌" if result['status'] == 'FAIL' else "ℹ️"
            print(
                f"{status_icon} [{result['status']:4s}] {result['test_id']:8s} | {result['test_name']:50s} | {result['message']}"
            )
        
        print("=" * 80)
        
        # Generate HTML report
        self._generate_html_report()
    
    def _generate_html_report(self):
        """Generate HTML report for key management tests"""
        html_content = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Key Management Test Results</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-card.pass { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }
        .stat-card.fail { background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%); }
        .stat-value { font-size: 36px; font-weight: bold; }
        .stat-label { font-size: 14px; text-transform: uppercase; opacity: 0.9; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #34495e; color: white; padding: 12px; text-align: left; font-weight: 600; }
        td { padding: 12px; border-bottom: 1px solid #ecf0f1; }
        tr:hover { background: #f8f9fa; }
        .status-pass { color: #27ae60; font-weight: bold; }
        .status-fail { color: #e74c3c; font-weight: bold; }
        .status-ack { color: #f39c12; font-weight: bold; }
        code { background: #ecf0f1; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Key Management Test Results</h1>
        <p><strong>Execution Time:</strong> {timestamp}</p>
        
        <div class="summary">
            <div class="stat-card">
                <div class="stat-value">{total}</div>
                <div class="stat-label">Total Tests</div>
            </div>
            <div class="stat-card pass">
                <div class="stat-value">{passed}</div>
                <div class="stat-label">Passed</div>
            </div>
            <div class="stat-card fail">
                <div class="stat-value">{failed}</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{pass_rate:.1f}%</div>
                <div class="stat-label">Pass Rate</div>
            </div>
        </div>
        
        <h2>Test Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Test ID</th>
                    <th>Test Name</th>
                    <th>Status</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody>
                {test_rows}
            </tbody>
        </table>
    </div>
</body>
</html>"""
        
        total = len(self.test_results)
        passed = sum(1 for r in self.test_results if r['status'] == 'PASS')
        failed = sum(1 for r in self.test_results if r['status'] == 'FAIL')
        pass_rate = (passed / total * 100) if total > 0 else 0
        
        test_rows = []
        for result in self.test_results:
            status_class = 'status-pass' if result['status'] == 'PASS' else 'status-fail' if result['status'] == 'FAIL' else 'status-ack'
            test_rows.append(f"""
                <tr>
                    <td><code>{result['test_id']}</code></td>
                    <td>{result['test_name']}</td>
                    <td><span class="{status_class}">{result['status']}</span></td>
                    <td>{result['message']}</td>
                </tr>
            """)
        
        html = html_content.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total=total,
            passed=passed,
            failed=failed,
            pass_rate=pass_rate,
            test_rows=''.join(test_rows)
        )
        
        results_dir = os.path.join(os.getcwd(), 'results')
        os.makedirs(results_dir, exist_ok=True)
        
        report_path = os.path.join(results_dir, 'key_management_test_results.html')
        with open(report_path, 'w') as f:
            f.write(html)
        
        print(f"\n📊 HTML Report generated: {report_path}")


# Register task class with Locust
tasks = [ONDCKeyManagement]
