from locust import task
from tests.registry.subscribe.common.advanced_subscribe_base import AdvancedSubscribeBase
import yaml
import uuid
import time
import copy

"""
================================================================================
ONDC Advanced Test Suite
================================================================================
Test File:   ondc_reg_advanced.py
Base Class:  AdvancedSubscribeBase (advanced_subscribe_base.py)
YAML Config: ondc_reg_advanced_tests.yml

Executes all 15 advanced tests (multi-domain, concurrency, edge cases)
Run with: --users 1 --iterations 1
================================================================================
"""

class ONDCRegAdvanced(AdvancedSubscribeBase):
    """Advanced test suite for multi-domain, concurrency, and edge cases"""
    
    config_file = 'resources/registry/subscribe/test_subscribe_functional.yml'
    test_cases_file = 'resources/registry/subscribe/test_advanced.yml'
    tenant_name = 'ondcRegistry'
    
    def on_start(self):
        """Initialize and load test cases from YAML"""
        super().on_start()
        
        print("\n" + "="*80)
        print("INITIALIZING ADVANCED TEST SUITE")
        print("="*80)
        
        # Load test cases from YAML
        try:
            with open(self.test_cases_file, 'r', encoding='utf-8') as f:
                test_config = yaml.safe_load(f)
                self.test_cases = test_config.get('tests', [])
                self.test_suite_info = test_config.get('test_suite', {})
                self.config_info = test_config.get('config', {})
                
            print(f"\n[YAML] Loaded {len(self.test_cases)} test cases from {self.test_cases_file}")
            print(f"[YAML] Suite: {self.test_suite_info.get('name')}")
            print(f"[YAML] Total Tests: {self.test_suite_info.get('total_tests')}")
            
            # Print first test case structure for debugging
            if self.test_cases:
                first_test = self.test_cases[0]
                print(f"[YAML] First test ID: {first_test.get('id')}")
                print(f"[YAML] First test name: {first_test.get('name')}")
                print(f"[YAML] First test workflow: {first_test.get('workflow', False)}")
                print(f"[YAML] First test keys: {list(first_test.keys())}")
            
            # Initialize test results tracking
            self.test_results = []
            
            print("="*80 + "\n")
            
        except Exception as e:
            print(f"[ERROR] Failed to load test cases from YAML: {e}")
            import traceback
            traceback.print_exc()
            self.test_cases = []
    
    def on_stop(self):
        """Display test summary"""
        super().on_stop()
        
        if not self.test_results:
            return
        
        # Display summary table
        print("\n" + "="*80)
        print("ADVANCED TEST RESULTS SUMMARY")
        print("="*80)
        
        passed = sum(1 for r in self.test_results if r['status'] == 'PASS')
        failed = sum(1 for r in self.test_results if r['status'] == 'FAIL')
        skipped = sum(1 for r in self.test_results if r['status'] == 'SKIP')
        
        total = len(self.test_results)
        print(f"Total: {total} | Passed: {passed} | Failed: {failed} | Skipped: {skipped}")
        print("-"*80)
        
        for result in self.test_results:
            status_icon = {
                'PASS': '[PASS]',
                'FAIL': '[FAIL]',
                'SKIP': '[SKIP]'
            }.get(result['status'], '?')
            
            print(f"{status_icon} {result['test_id']:5} | {result['test_name']:55} | {result['duration_ms']:8.0f}ms")
        
        print("="*80)
        
        # Display performance metrics if any
        if hasattr(self, 'performance_metrics') and self.performance_metrics:
            print("\nPERFORMANCE METRICS")
            print("-"*80)
            for metric_name, metric_value in self.performance_metrics.items():
                print(f"{metric_name}: {metric_value}")
            print("="*80)
    
    # ==========================================
    # YAML Test Execution
    # ==========================================
    
    @task
    def run_yaml_tests(self):
        """Execute all tests defined in YAML configuration"""
        print("\n" + "="*80)
        print("STARTING ADVANCED TEST EXECUTION")
        print("="*80)
        
        if not self.test_cases:
            print("[ERROR] No test cases loaded from YAML")
            return
        
        print(f"\n{'='*80}")
        print(f"{self.test_suite_info.get('name', 'Advanced Test Suite')}")
        print(f"{'='*80}")
        print(f"Total Tests: {len(self.test_cases)}")
        print(f"{'='*80}\n")
        
        for idx, test_case in enumerate(self.test_cases):
            print(f"\n>>> Processing test {idx+1}/{len(self.test_cases)}: {test_case.get('id', 'UNKNOWN')}")
            self._execute_test_case(test_case)
    
    def _execute_test_case(self, test_case):
        """Execute a single test case from YAML configuration"""
        test_id = test_case.get('id', 'UNKNOWN')
        test_name = test_case.get('name', 'Unnamed Test')
        is_workflow = test_case.get('workflow', False)
        has_batch = test_case.get('batch_size') is not None
        has_concurrent = test_case.get('concurrent_steps', False)
        
        self.step_name = f"{test_id}_{test_name[:50].replace(' ', '_')}"
        
        print(f"\n[{self.step_name}] > Test {test_id}: {test_name}")
        
        start_time = time.time()
        
        try:
            # Check test type and execute accordingly
            if has_batch:
                success = self._execute_batch_test(test_case, test_id, test_name)
            elif is_workflow and has_concurrent:
                success = self._execute_concurrent_workflow(test_case, test_id, test_name)
            elif is_workflow:
                success = self._execute_workflow(test_case, test_id, test_name)
            else:
                success = self._execute_simple_test(test_case, test_id, test_name)
            
            elapsed_ms = (time.time() - start_time) * 1000
            
            if success:
                print(f"[{self.step_name}] [PASS] {test_id}: Test passed ({elapsed_ms:.0f}ms)")
                self._record_test_result(test_id, test_name, "PASS", elapsed_ms)
            else:
                print(f"[{self.step_name}] [FAIL] {test_id}: Test failed ({elapsed_ms:.0f}ms)")
                self._record_test_result(test_id, test_name, "FAIL", elapsed_ms)
        
        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            print(f"[{self.step_name}] [FAIL] {test_id}: Exception - {str(e)}")
            import traceback
            traceback.print_exc()
            self._record_test_result(test_id, test_name, "FAIL", elapsed_ms, f"Exception: {str(e)}")
        
        time.sleep(0.5)
    
    def _execute_simple_test(self, test_case, test_id, test_name):
        """Execute a single-step test"""
        # Generate test participant data
        test_data = self._setup_test_participant()
        
        # Build payload with participant data injected
        payload = self._build_test_payload(test_case, test_data)
        
        # Create a step dict from the test_case
        step = {
            'name': test_case.get('name', test_id),
            'method': test_case.get('method', 'POST'),
            'endpoint': test_case.get('endpoint', '/admin/subscribe'),
            'auth_type': test_case.get('auth_type', 'admin'),
            'expected_status': test_case.get('expected_status', 200),
            'data': payload
        }
        
        # Execute single step
        try:
            result = self._execute_single_step(step, test_data)
            return result['success']
        except Exception as e:
            print(f"[{self.step_name}] Exception in test execution: {e}")
            return False
    
    def _build_test_payload(self, test_case, test_data):
        """Build payload from test case and inject participant data"""
        import copy
        payload = copy.deepcopy(test_case.get('data', {}))
        
        # For admin subscribe requests, inject participant_id at top level if not present
        if 'participant_id' not in payload:
            payload['participant_id'] = test_data['participant_id']
        
        # Inject subscriber_id into each config if not present
        if 'configs' in payload:
            for config in payload['configs']:
                if 'subscriber_id' not in config:
                    config['subscriber_id'] = test_data['participant_id']
        
        # Substitute any variables
        payload = self._substitute_variables(payload, test_data)
        
        return payload
    
    def _execute_workflow(self, test_case, test_id, test_name):
        """Execute multi-step workflow with shared test data"""
        steps = test_case.get('steps', [])
        
        if not steps:
            print(f"[{self.step_name}] [WARN] No steps defined in workflow")
            return False
        
        # Generate test participant data (shared across all workflow steps)
        test_data = self._setup_test_participant()
        
        print(f"[{self.step_name}] Executing {len(steps)} workflow steps")
        
        all_success = True
        for step_idx, step in enumerate(steps):
            step_name = step.get('name', f'Step {step_idx + 1}')
            print(f"[{self.step_name}]   Step {step_idx + 1}/{len(steps)}: {step_name}")
            
            # Build payload with participant data injected
            step_payload = self._build_workflow_step_payload(step, test_data)
            
            # Update step with built payload
            step_with_payload = step.copy()
            step_with_payload['data'] = step_payload
            
            result = self._execute_single_step(step_with_payload, test_data)
            
            if result['success']:
                print(f"[{self.step_name}]   [OK] {step_name} - {result['message']}")
            else:
                print(f"[{self.step_name}]   [FAIL] {step_name} - {result['message']}")
                all_success = False
                # Continue executing remaining steps even if one fails
        
        return all_success
    
    def _build_workflow_step_payload(self, step, test_data):
        """Build payload for a workflow step and inject participant data"""
        import copy
        payload = copy.deepcopy(step.get('data', {}))
        
        # For admin subscribe requests, inject participant_id at top level if not present
        # But use test_data['subscriber_id'] if it exists (from previous steps)
        if 'participant_id' not in payload:
            payload['participant_id'] = test_data.get('subscriber_id', test_data['participant_id'])
        
        # Inject subscriber_id into each config if not present
        if 'configs' in payload:
            for config in payload['configs']:
                if 'subscriber_id' not in config:
                    config['subscriber_id'] = test_data.get('subscriber_id', test_data['participant_id'])
        
        # Substitute any variables
        payload = self._substitute_variables(payload, test_data)
        
        return payload
    
    def _execute_concurrent_workflow(self, test_case, test_id, test_name):
        """Execute workflow with concurrent steps"""
        steps = test_case.get('steps', [])
        
        if not steps:
            return False
        
        # Generate test participant data
        test_data = self._setup_test_participant()
        
        print(f"[{self.step_name}] Executing workflow with concurrent steps")
        
        # Separate sequential setup steps from concurrent steps
        setup_steps = []
        concurrent_steps = []
        
        for step in steps:
            if step.get('concurrent', False):
                concurrent_steps.append(step)
            else:
                setup_steps.append(step)
        
        # Execute setup steps sequentially
        all_success = True
        for step_idx, step in enumerate(setup_steps):
            step_name = step.get('name', f'Setup Step {step_idx + 1}')
            print(f"[{self.step_name}]   Setup: {step_name}")
            
            result = self._execute_single_step(step, test_data)
            
            if not result['success']:
                print(f"[{self.step_name}]   [FAIL] Setup failed: {step_name}")
                return False
        
        # Execute concurrent steps
        if concurrent_steps:
            print(f"[{self.step_name}]   Executing {len(concurrent_steps)} concurrent requests")
            results = self._execute_concurrent_steps(concurrent_steps, test_data)
            
            # Check if at least one succeeded (for race condition tests)
            any_success = any(r['success'] for r in results)
            all_success = all_success and any_success
            
            for result in results:
                status = "[OK]" if result['success'] else "[FAIL]"
                print(f"[{self.step_name}]   {status} {result['step_name']} - {result['message']}")
        
        return all_success
    
    def _execute_batch_test(self, test_case, test_id, test_name):
        """Execute batch operation test"""
        batch_size = test_case.get('batch_size', 1)
        performance_threshold = test_case.get('performance_threshold_ms')
        
        print(f"[{self.step_name}] Executing batch operation: {batch_size} participants")
        
        success_count, fail_count, elapsed_ms = self._execute_batch_operation(
            test_case, 
            batch_size, 
            test_name
        )
        
        print(f"[{self.step_name}] Batch results: {success_count} passed, {fail_count} failed ({elapsed_ms:.0f}ms)")
        
        # Check performance threshold if specified
        if performance_threshold and elapsed_ms > performance_threshold:
            print(f"[{self.step_name}] [WARN] Performance threshold exceeded: {elapsed_ms:.0f}ms > {performance_threshold}ms")
            self.performance_metrics[test_id] = f"{elapsed_ms:.0f}ms (threshold: {performance_threshold}ms)"
            return False
        
        # Record performance metric
        self.performance_metrics[test_id] = f"{elapsed_ms:.0f}ms for {batch_size} operations"
        
        # Test passes if majority succeeded
        return success_count > (batch_size * 0.8)
    
    def _record_test_result(self, test_id, test_name, status, duration_ms, message=""):
        """Record test result for summary"""
        self.test_results.append({
            'test_id': test_id,
            'test_name': test_name,
            'status': status,
            'duration_ms': duration_ms,
            'message': message
        })


# Export tasks for CTF framework
tasks = [ONDCRegAdvanced]
