"""
V3 Test Runner

Executes V3 API tests with ONDC Ed25519 signature authentication.
"""

import uuid
from .base_runner import BaseTestRunner, TestResult
from typing import Dict


class V3TestRunner(BaseTestRunner):
    """
    Test runner for V3 API tests.
    
    Handles:
    - ONDC Ed25519 signature authentication
    - V3 self-subscribe operations
    - Prerequisite admin setup for V3 tests
    - Automatic V3 auth registration for workflow tests
    """
    
    def setup(self) -> bool:
        """
        Setup V3 test runner.
        
        Performs admin login for prerequisite operations.
        
        Returns:
            True if setup successful
        """
        print("Setting up V3 Test Runner...")
        
        # Admin login for prerequisite operations
        if not self.client.admin_login():
            print("[ERROR] Admin login failed (needed for prerequisites)")
            return False
        
        print("[OK] V3 Test Runner ready")
        return True
    
    def _execute_workflow(self, test: Dict, result: TestResult) -> bool:
        """
        Execute V3 workflow with automatic auth registration.
        
        Overrides base implementation to register V3 auth after admin creates participant.
        
        Args:
            test: Test configuration with steps
            result: TestResult to populate
            
        Returns:
            True if all steps passed, False otherwise
        """
        steps = test.get('steps', [])
        
        # Initialize context with unique IDs for this workflow
        test_id = test.get('id', 'test').lower()
        subscriber_id = self.data_gen.generate_subscriber_id(prefix=test_id, suffix=self.session_id)
        request_id = str(uuid.uuid4())
        uk_id = self.data_gen.generate_unique_key_id()
        
        context = {
            'subscriber_id': subscriber_id,
            'request_id': request_id,
            'uk_id': uk_id
        }
        
        # Track if we've registered V3 auth for this participant
        v3_auth_registered = False
        
        for i, step in enumerate(steps):
            step_name = step.get('name', f'Step {i+1}')
            print(f"  -> {step_name}")
            
            # Resolve variables in step data
            step_data = self._resolve_variables(step.get('data', {}), context)
            endpoint = self._resolve_variables(step.get('endpoint', ''), context) if isinstance(step.get('endpoint'), str) else step.get('endpoint', '')
            
            # Register V3 auth before first admin subscribe or V3 auth step
            if not v3_auth_registered:
                should_register = False
                
                # Register for admin subscribe steps (WHITELISTED participants will use V3 later)
                if (step.get('auth_type') == 'admin' and 
                    step.get('endpoint') == '/admin/subscribe' and 
                    step.get('method') in ['POST', 'PATCH']):
                    should_register = True
                
                # Register before V3 auth steps
                if step.get('auth_type') == 'v3':
                    should_register = True
                
                if should_register:
                    # Register V3 auth to generate key pair with pre-generated uk_id
                    self.client.register_v3_participant(subscriber_id, uk_id)
                    v3_auth_registered = True
                    
                    # Capture full key pair info for output
                    full_key = self.client.get_v3_full_key_info(subscriber_id)
                    if full_key:
                        result.ondc_key_info = full_key
                    
                    # Get generated public key for context
                    pub_key = self.client.get_v3_public_key(subscriber_id)
                    if pub_key:
                        # Store in context for V3 auth steps
                        context['signing_public_key'] = pub_key.get('signing_public_key')
                        context['encryption_public_key'] = pub_key.get('encryption_public_key')
                        context['valid_from'] = pub_key.get('valid_from')
                        context['valid_until'] = pub_key.get('valid_until')
                        
                        # If admin step has 'key' field, inject the generated key
                        if 'key' in step_data:
                            step_data['key'].update(pub_key)
                            print(f"    [OK] Injected generated public key for {subscriber_id}")
                            print(f"    [DEBUG] Public key (first 50 chars): {pub_key['signing_public_key'][:50]}...")
                        else:
                            print(f"    [OK] Registered V3 auth for {subscriber_id}")
                            print(f"    [DEBUG] Public key (first 50 chars): {pub_key['signing_public_key'][:50]}...")
            
            # Execute step
            # Debug log for V3 requests
            if step.get('auth_type') == 'v3' and 'key' in step_data:
                print(f"    [DEBUG] Sending V3 request with key:")
                print(f"      uk_id: {step_data['key'].get('uk_id')}")
                print(f"      signing_public_key: {step_data['key'].get('signing_public_key')[:50]}...")
                print(f"      signed_algorithm: {step_data['key'].get('signed_algorithm')}")
            
            response = self.client.request(
                method=step['method'],
                endpoint=endpoint,
                auth_type=step.get('auth_type', 'none'),
                subscriber_id=context.get('subscriber_id') if step.get('auth_type') == 'v3' else None,
                data=step_data if step_data else None,
                timeout=step.get('timeout', 30),
                invalid_signature=step.get('invalid_signature', False)
            )
            
            # Capture request details for this step
            result.request_details.append({
                "step_name": step_name,
                "method": step['method'],
                "endpoint": endpoint,
                "url": response.request.url if hasattr(response, 'request') else None,
                "query_params": None,
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
                        return False
        
        result.status_code = 200
        result.expected_status = 200
        result.passed = True
        
        return True
    
    def execute_test(self, test: Dict) -> TestResult:
        """
        Execute V3 test with prerequisite handling.
        
        Args:
            test: Test configuration
            
        Returns:
            TestResult object
        """
        result = TestResult(test['id'], test['name'])
        
        # Handle prerequisite (admin creates WHITELISTED participant)
        if 'prerequisite' in test:
            prereq = test['prerequisite']
            if 'admin_create' in prereq:
                subscriber_id = self._create_prerequisite_participant(prereq['admin_create'])
                if not subscriber_id:
                    result.passed = False
                    result.error_message = "Failed to create prerequisite participant"
                    return result
                
                # Register V3 participant for signature auth
                unique_key_id = self.data_gen.generate_unique_key_id()
                self.client.register_v3_participant(subscriber_id, unique_key_id)
                
                # Capture full key pair info for output
                full_key = self.client.get_v3_full_key_info(subscriber_id)
                if full_key:
                    result.ondc_key_info = full_key
                
                # Store in state
                self.state_mgr.register_participant(
                    subscriber_id,
                    status=prereq['admin_create'].get('action', 'WHITELISTED'),
                    unique_key_id=unique_key_id
                )
                
                # Override test data with subscriber_id
                if 'subscriber_id' not in test.get('data', {}):
                    if 'data' not in test:
                        test['data'] = {}
                    # V3 tests use subscriber_id from signature, not data
        
        # Execute the actual V3 test
        return super().execute_test(test)
    
    def _create_prerequisite_participant(self, admin_data: Dict) -> str:
        """
        Create prerequisite participant via Admin API.
        
        Args:
            admin_data: Admin creation data
            
        Returns:
            Subscriber ID of created participant
        """
        # Generate unique subscriber_id
        subscriber_id = self.data_gen.generate_subscriber_id(prefix="v3test")
        
        # Prepare admin create request
        create_data = {
            "subscriber_id": subscriber_id,
            **admin_data
        }
        
        try:
            response = self.client.post(
                "/admin/subscribe",
                auth_type="admin",
                data=create_data
            )
            
            if response.status_code == 200:
                print(f"  [OK] Prerequisite: Created {subscriber_id} as {admin_data.get('action', 'WHITELISTED')}")
                return subscriber_id
            else:
                print(f"  [ERROR] Prerequisite failed: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"  [ERROR] Prerequisite error: {e}")
            return None
    
    def _execute_single_request(self, test: Dict, result: TestResult) -> bool:
        """
        Execute V3 single request with signature auth.
        
        Args:
            test: Test configuration
            result: TestResult to populate
            
        Returns:
            True if test passed
        """
        method = test['method']
        endpoint = test['endpoint']
        data = test.get('data', {})
        expected_status = test.get('expected_status', 200)
        
        # Get subscriber_id from state (created in prerequisite)
        participants = self.state_mgr.get_all_participants()
        if not participants:
            result.error_message = "No V3 participant available for test"
            return False
        
        # Use the most recently created participant
        subscriber_id = list(participants.keys())[-1]
        participant = participants[subscriber_id]
        
        # Execute V3 request with signature
        response = self.client.request(
            method=method,
            endpoint=endpoint,
            auth_type='v3',
            subscriber_id=subscriber_id,
            data=data if data else None,
            timeout=test.get('timeout', 30)
        )
        
        # Record result
        result.status_code = response.status_code
        result.expected_status = expected_status
        
        try:
            result.response_body = response.json()
        except:
            result.response_body = response.text
        
        # Validate
        if response.status_code != expected_status:
            result.error_message = f"Expected {expected_status}, got {response.status_code}"
            return False
        
        # Field validations
        if 'validate' in test:
            for validation in test['validate']:
                if not self._validate_field(result.response_body, validation, result):
                    return False
        
        # Update state
        if response.status_code == expected_status and 'action' not in data:
            # V3 subscribe changes status to SUBSCRIBED
            self.state_mgr.update_status(subscriber_id, 'SUBSCRIBED')
        
        return True
    
    def teardown(self):
        """Cleanup V3 test runner."""
        print("Cleaning up V3 Test Runner...")
        self.client.close()
        print("[OK] Cleanup complete")
