"""
Admin Test Runner

Executes Admin API tests with JWT authentication.
"""

from .base_runner import BaseTestRunner


class AdminTestRunner(BaseTestRunner):
    """
    Test runner for Admin API tests.
    
    Handles:
    - JWT authentication
    - Admin-specific test scenarios
    - Status transition testing
    """
    
    def setup(self) -> bool:
        """
        Setup Admin test runner.
        
        Performs admin login to obtain JWT token.
        
        Returns:
            True if setup successful
        """
        print("Setting up Admin Test Runner...")
        
        # Perform admin login
        if not self.client.admin_login():
            print("[ERROR] Admin login failed")
            return False
        
        print("[OK] Admin login successful")
        return True
    
    def teardown(self):
        """Cleanup Admin test runner."""
        print("Cleaning up Admin Test Runner...")
        self.client.close()
        print("[OK] Cleanup complete")
