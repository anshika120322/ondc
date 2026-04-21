"""
Universal Test Runner

Single runner that handles all test categories:
- Admin JWT authentication
- V3 ONDC signature authentication (auto-registered on first v3 step)
- Combined Admin + V3 workflows
- Concurrent steps, batch tests, all workflow features

Replaces AdminTestRunner, V3TestRunner, and CombinedTestRunner.
"""

from .base_runner import BaseTestRunner


class UniversalTestRunner(BaseTestRunner):
    """
    Universal runner for all test categories.

    All execution logic lives in BaseTestRunner._execute_sequential_workflow.
    V3 key pairs are auto-registered on the first step with auth_type: v3.
    Use inject_v3_key: true at the test level to inject the generated public
    key into the step data payload (for ONDC subscribe admin steps).
    """

    def setup(self) -> bool:
        """Perform admin login."""
        print("Setting up Universal Test Runner...")
        if not self.client.admin_login():
            print("[ERROR] Admin login failed")
            return False
        print("[OK] Universal Test Runner ready")
        return True

    def teardown(self):
        """Cleanup."""
        print("Cleaning up Universal Test Runner...")
        self.client.close()
        print("[OK] Cleanup complete")
