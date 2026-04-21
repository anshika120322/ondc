"""
Combined Test Runner

Executes mixed Admin + V3 workflow tests.
"""

from .base_runner import BaseTestRunner, TestResult
from typing import Dict


class CombinedTestRunner(BaseTestRunner):
    """
    Test runner for combined Admin + V3 workflow tests.
    
    Handles:
    - Mixed authentication (Admin JWT + V3 ONDC signature)
    - Multi-step workflows with both auth types
    - State transitions across admin and V3 operations
    """
    
    def setup(self) -> bool:
        """
        Setup Combined test runner.
        
        Performs admin login and prepares for V3 operations.
        
        Returns:
            True if setup successful
        """
        print("Setting up Combined Test Runner...")
        
        # Admin login
        if not self.client.admin_login():
            print("[ERROR] Admin login failed")
            return False
        
        print("[OK] Combined Test Runner ready")
        return True
    
    def _execute_workflow(self, test: Dict, result: TestResult) -> bool:
        """
        Execute combined workflow with both Admin and V3 steps.
        
        Supports concurrent execution for advanced scenarios.
        
        Args:
            test: Test configuration
            result: TestResult to populate
            
        Returns:
            True if all steps passed
        """
        steps = test.get('steps', [])
        
        # Check if concurrent execution is requested
        if test.get('concurrent_steps', False):
            return self._execute_concurrent_combined_workflow(test, result, steps)
        
        # Sequential execution (default)
        return self._execute_sequential_combined_workflow(test, result, steps)
    
    def _execute_sequential_combined_workflow(self, test: Dict, result: TestResult, steps: list) -> bool:
        """
        Execute combined workflow steps sequentially with V3 registration support.
        
        Args:
            test: Test configuration
            result: TestResult to populate
            steps: List of workflow steps
            
        Returns:
            True if all steps passed
        """
        # Initialize context with unique subscriber_id for this workflow
        test_id = test.get('id', 'test').lower()
        subscriber_id = self.data_gen.generate_subscriber_id(prefix=test_id, suffix=self.session_id)
        context = {'subscriber_id': subscriber_id}
        
        v3_participant_registered = False
        
        for i, step in enumerate(steps):
            step_name = step.get('name', f'Step {i+1}')
            print(f"  -> {step_name}")
            
            # Resolve variables
            step_data = self._resolve_variables(step.get('data', {}), context)
            endpoint = self._resolve_variables(step.get('endpoint', ''), context) if isinstance(step.get('endpoint'), str) else step.get('endpoint', '')
            
            # Get auth details
            auth_type = step.get('auth_type', 'none')
            subscriber_id = context.get('subscriber_id')
            
            # Register V3 participant if this is first V3 step
            if auth_type == 'v3' and subscriber_id and not v3_participant_registered:
                unique_key_id = self.data_gen.generate_unique_key_id()
                self.client.register_v3_participant(subscriber_id, unique_key_id)
                participant = self.state_mgr.get_participant(subscriber_id)
                if participant:
                    participant['unique_key_id'] = unique_key_id
                v3_participant_registered = True
                full_key = self.client.get_v3_full_key_info(subscriber_id)
                if full_key:
                    result.ondc_key_info = full_key
                print(f"    [OK] Registered V3 auth for {subscriber_id}")
            
            # Generate subscriber_id for first admin step if needed
            if not subscriber_id and auth_type == 'admin' and 'subscriber_id' not in step_data:
                subscriber_id = self.data_gen.generate_subscriber_id(prefix="combined")
                step_data['subscriber_id'] = subscriber_id
                context['subscriber_id'] = subscriber_id
            
            # Execute step
            response = self.client.request(
                method=step['method'],
                endpoint=endpoint,
                auth_type=auth_type,
                subscriber_id=subscriber_id if auth_type == 'v3' else None,
                data=step_data if step_data else None,
                timeout=step.get('timeout', 30)
            )
            
            # Check status (support multiple expected statuses for concurrent scenarios)
            expected = step.get('expected_status', 200)
            expected_statuses = expected if isinstance(expected, list) else [expected]
            
            if response.status_code not in expected_statuses:
                result.error_message = f"{step_name}: Expected {expected}, got {response.status_code}"
                result.status_code = response.status_code
                result.expected_status = expected
                try:
                    result.response_body = response.json()
                except:
                    result.response_body = response.text
                return False
            
            # Save subscriber_id from first step if flagged
            if step.get('save_subscriber_id', False):
                try:
                    response_data = response.json()
                    context['subscriber_id'] = response_data.get('subscriber_id', context.get('subscriber_id'))
                    
                    # Register in state manager
                    if context['subscriber_id']:
                        status = step_data.get('action', 'WHITELISTED')
                        self.state_mgr.register_participant(
                            context['subscriber_id'],
                            status=status
                        )
                except:
                    pass
            
            # Update state on status changes
            if subscriber_id and response.status_code == expected:
                if 'action' in step_data:
                    self.state_mgr.update_status(subscriber_id, step_data['action'])
                elif auth_type == 'v3' and '/api/v3/subscribe' in step['endpoint'] and step['method'] == 'POST':
                    # V3 POST subscribe transitions to SUBSCRIBED
                    self.state_mgr.update_status(subscriber_id, 'SUBSCRIBED')
            
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
        return True
    
    def _execute_concurrent_combined_workflow(self, test: Dict, result: TestResult, steps: list) -> bool:
        """
        Execute combined workflow with concurrent steps and V3 registration support.
        
        Args:
            test: Test configuration
            result: TestResult to populate
            steps: List of workflow steps
            
        Returns:
            True if all steps passed
        """
        # Initialize context
        test_id = test.get('id', 'test').lower()
        subscriber_id = self.data_gen.generate_subscriber_id(prefix=test_id, suffix=self.session_id)
        context = {'subscriber_id': subscriber_id}
        v3_participant_registered = False
        
        # Execute steps, handling concurrent batches
        i = 0
        while i < len(steps):
            step = steps[i]
            
            # Register V3 participant if needed for this step
            auth_type = step.get('auth_type', 'none')
            if auth_type == 'v3' and context.get('subscriber_id') and not v3_participant_registered:
                unique_key_id = self.data_gen.generate_unique_key_id()
                self.client.register_v3_participant(context['subscriber_id'], unique_key_id)
                participant = self.state_mgr.get_participant(context['subscriber_id'])
                if participant:
                    participant['unique_key_id'] = unique_key_id
                v3_participant_registered = True
                full_key = self.client.get_v3_full_key_info(context['subscriber_id'])
                if full_key:
                    result.ondc_key_info = full_key
                print(f"    [OK] Registered V3 auth for {context['subscriber_id']}")
            
            # Check if this step is concurrent
            if step.get('concurrent', False):
                # Collect all consecutive concurrent steps
                concurrent_batch = []
                while i < len(steps) and steps[i].get('concurrent', False):
                    concurrent_batch.append(steps[i])
                    i += 1
                
                # Execute concurrent batch (reuse base implementation)
                if not self._execute_concurrent_steps(concurrent_batch, context, result):
                    return False
            else:
                # Execute single step sequentially with combined runner logic
                step_name = step.get('name', f'Step {i+1}')
                print(f"  -> {step_name}")
                
                if not self._execute_combined_step(step, context, result, step_name, v3_participant_registered):
                    return False
                i += 1
        
        result.status_code = 200
        result.expected_status = 200
        return True
    
    def _execute_combined_step(self, step: Dict, context: Dict, result: TestResult, step_name: str, v3_registered: bool) -> bool:
        """
        Execute a single combined workflow step with state management.
        
        Args:
            step: Step configuration
            context: Context dictionary
            result: TestResult to populate
            step_name: Name of the step
            v3_registered: Whether V3 participant is already registered
            
        Returns:
            True if step passed
        """
        # Resolve variables
        step_data = self._resolve_variables(step.get('data', {}), context)
        endpoint = self._resolve_variables(step.get('endpoint', ''), context) if isinstance(step.get('endpoint'), str) else step.get('endpoint', '')
        
        # Get auth details
        auth_type = step.get('auth_type', 'none')
        subscriber_id = context.get('subscriber_id')
        
        # Execute step
        response = self.client.request(
            method=step['method'],
            endpoint=endpoint,
            auth_type=auth_type,
            subscriber_id=subscriber_id if auth_type == 'v3' else None,
            data=step_data if step_data else None,
            timeout=step.get('timeout', 30)
        )
        
        # Capture request/response details
        result.request_details.append({
            "step_name": step_name,
            "method": step['method'],
            "endpoint": step['endpoint'],
            "url": response.request.url if hasattr(response, 'request') else None,
            "query_params": None,
            "auth_type": auth_type,
            "body": step_data
        })
        
        try:
            response_body = response.json()
        except:
            response_body = response.text
        
        result.response_details.append({
            "step_name": step_name,
            "status_code": response.status_code,
            "body": response_body
        })
        
        # Check status (support multiple expected statuses)
        expected = step.get('expected_status', 200)
        expected_statuses = expected if isinstance(expected, list) else [expected]
        
        if response.status_code not in expected_statuses:
            result.error_message = f"{step_name}: Expected {expected}, got {response.status_code}"
            result.status_code = response.status_code
            result.expected_status = expected
            result.response_body = response_body
            return False
        
        # Save subscriber_id from first step if flagged
        if step.get('save_subscriber_id', False):
            try:
                response_data = response.json()
                context['subscriber_id'] = response_data.get('subscriber_id', context.get('subscriber_id'))
                
                # Register in state manager
                if context['subscriber_id']:
                    status = step_data.get('action', 'WHITELISTED')
                    self.state_mgr.register_participant(context['subscriber_id'], status=status)
            except:
                pass
        
        # Update state on status changes
        if subscriber_id and response.status_code in expected_statuses:
            if 'action' in step_data:
                self.state_mgr.update_status(subscriber_id, step_data['action'])
            elif auth_type == 'v3' and '/api/v3/subscribe' in step['endpoint'] and step['method'] == 'POST':
                self.state_mgr.update_status(subscriber_id, 'SUBSCRIBED')
        
        # Validate step
        if 'validate' in step:
            try:
                response_data = response.json()
            except:
                response_data = {}
            
            for validation in step['validate']:
                if not self._validate_field(response_data, validation, result):
                    return False
        
        return True
    
    def teardown(self):
        """Cleanup Combined test runner."""
        print("Cleaning up Combined Test Runner...")
        self.client.close()
        print("[OK] Cleanup complete")
