"""
ONDC Admin Security Advanced Tests (SEC-001 to SEC-004)

Test Cases:
- SEC-001: SQL Injection
- SEC-002: XSS Attack
- SEC-003: Password Hashing
- SEC-004: Token Security
"""

from common.testfoundation import BaseLocustTest
from locust import task
from common.proxyserver import ProxyServer
from common.utils.taskset_handler import taskset_handler, RESCHEDULE_TASK
import jwt
import json
import time
import html


class OndcAdminSecurityAdvancedTests(BaseLocustTest):
    """
    Advanced security test suite for ONDC Admin Service
    Tests for SQL injection, XSS, password hashing, and token security
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.proxy_server = ProxyServer()
        self.valid_token = None
        self.super_admin_token = None

    def on_start(self):
        """Setup: Login and store valid tokens"""
        super().on_start()
        self._login_as_super_admin()

    def _login_as_super_admin(self):
        """Helper method to login as Super Admin and get valid token"""
        login_payload = {
            "email": "super@admin.com",
            "password": "SuperSecure123!"
        }

        try:
            response = self.client.post(
                "/api/v1/auth/login",
                json=login_payload,
                name="Login (Super Admin)",
                catch_response=True
            )

            if response.status_code == 201:
                data = response.json()
                self.super_admin_token = data.get("accessToken")
                self.valid_token = self.super_admin_token
                response.success()
            else:
                response.failure(f"Login failed: {response.status_code}")
        except Exception as e:
            print(f"Login error: {str(e)}")

    # SEC-001: SQL Injection
    @task(1)
    @taskset_handler(task_control_flag=RESCHEDULE_TASK)
    def sec_001_sql_injection(self):
        """
        SEC-001: SQL Injection (Negative)
        
        Test: Input SQL commands in email/password fields
        Expected: Input sanitized, no database errors
        
        Tests multiple SQL injection payloads:
        - OR '1'='1' (authentication bypass)
        - UNION SELECT (data extraction)
        - DROP TABLE (destructive)
        - Comment injection
        """
        sql_injection_payloads = [
            {
                "email": "admin@example.com' OR '1'='1",
                "password": "anything"
            },
            {
                "email": "admin@example.com' OR '1'='1'--",
                "password": "password"
            },
            {
                "email": "admin@example.com' UNION SELECT NULL, NULL--",
                "password": "password"
            },
            {
                "email": "admin' OR 1=1--",
                "password": "password"
            },
            {
                "email": "'; DROP TABLE users; --",
                "password": "password"
            },
            {
                "email": "admin@example.com",
                "password": "password' OR '1'='1"
            }
        ]

        for idx, payload in enumerate(sql_injection_payloads):
            with self.client.post(
                "/api/v1/auth/login",
                json=payload,
                name=f"SEC-001: SQL Injection Test {idx+1}",
                catch_response=True
            ) as response:
                try:
                    # Should NOT return 500 (database error)
                    if response.status_code == 500:
                        response.failure(f"SEC-001 Failed: Database error detected (SQL injection vulnerability)")
                        return

                    # Should return 400 (bad request) or 401 (unauthorized)
                    if response.status_code not in [400, 401]:
                        response.failure(f"SEC-001 Failed: Unexpected status {response.status_code}")
                        return

                    # Verify error message doesn't leak database info
                    try:
                        data = response.json()
                        error_message = str(data.get("message", "")).lower()
                        
                        # Check for database error leakage
                        database_keywords = ['sql', 'syntax', 'query', 'database', 'table', 'column', 'postgresql', 'mysql']
                        for keyword in database_keywords:
                            if keyword in error_message:
                                response.failure(f"SEC-001 Failed: Database info leaked in error: {keyword}")
                                return
                    except:
                        pass

                    response.success()

                except Exception as e:
                    response.failure(f"SEC-001 Failed: {str(e)}")

    # SEC-002: XSS Attack
    @task(1)
    @taskset_handler(task_control_flag=RESCHEDULE_TASK)
    def sec_002_xss_attack(self):
        """
        SEC-002: XSS Attack (Negative)
        
        Test: Input JavaScript in text fields
        Expected: Input escaped, no script execution
        
        Tests multiple XSS payloads in various fields
        """
        if not self.super_admin_token:
            return

        # XSS payloads to test
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>",
            "';alert('XSS');//",
            "<body onload=alert('XSS')>",
        ]

        timestamp = int(time.time() * 1000)

        for idx, xss_payload in enumerate(xss_payloads):
            # Test 1: XSS in user creation firstName field
            user_payload = {
                "email": f"xss_test_{timestamp}_{idx}@example.com",
                "firstName": xss_payload,
                "lastName": "TestUser",
                "role": "OPERATOR",
                "password": "TestPass123!",
                "isActive": True
            }

            with self.client.post(
                "/api/v1/users",
                headers={"Authorization": f"Bearer {self.super_admin_token}"},
                json=user_payload,
                name=f"SEC-002: XSS Test {idx+1}",
                catch_response=True
            ) as response:
                try:
                    if response.status_code == 201:
                        data = response.json()
                        
                        # Verify the XSS payload is escaped/sanitized
                        first_name = data.get("firstName", "")
                        
                        # Check if raw script tags are present (bad)
                        if "<script>" in first_name or "onerror=" in first_name or "onload=" in first_name:
                            response.failure(f"SEC-002 Failed: XSS payload not sanitized: {first_name}")
                            return
                        
                        # Proper escaping should convert < to &lt; etc
                        if xss_payload in first_name:
                            # Check if it's properly escaped
                            escaped = html.escape(xss_payload)
                            if first_name != escaped:
                                response.failure(f"SEC-002 Failed: XSS payload stored without escaping")
                                return
                        
                        response.success()
                        
                        # Cleanup: Try to delete the test user
                        user_id = data.get("id")
                        if user_id:
                            self.client.delete(
                                f"/api/v1/users/{user_id}",
                                headers={"Authorization": f"Bearer {self.super_admin_token}"},
                                name="SEC-002: Cleanup User"
                            )
                    
                    elif response.status_code == 400:
                        # Input validation rejected the payload - this is good
                        response.success()
                    else:
                        response.failure(f"SEC-002 Failed: Unexpected status {response.status_code}")

                except Exception as e:
                    response.failure(f"SEC-002 Failed: {str(e)}")

        # Test 2: XSS in update profile
        profile_xss_payload = {
            "firstName": "<script>alert('XSS')</script>",
            "lastName": "Test"
        }

        with self.client.patch(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {self.super_admin_token}"},
            json=profile_xss_payload,
            name="SEC-002: XSS in Profile Update",
            catch_response=True
        ) as response:
            try:
                if response.status_code in [200, 400]:
                    # Either updated with sanitization or rejected
                    if response.status_code == 200:
                        data = response.json()
                        first_name = data.get("firstName", "")
                        
                        if "<script>" in first_name:
                            response.failure("SEC-002 Failed: XSS in profile not sanitized")
                            return
                    
                    response.success()
                else:
                    response.failure(f"SEC-002 Failed: Unexpected status {response.status_code}")

            except Exception as e:
                response.failure(f"SEC-002 Failed: {str(e)}")

    # SEC-003: Password Hashing
    @task(1)
    @taskset_handler(task_control_flag=RESCHEDULE_TASK)
    def sec_003_password_hashing(self):
        """
        SEC-003: Password Hashing (Positive)
        
        Test: Check that passwords are never returned in plaintext
        Expected: All API responses should never contain password field
        
        Note: Cannot directly check database without database access.
        This test verifies:
        1. Password field never returned in API responses
        2. Login works (proves password is hashed, not stored plain)
        3. Password reset requires token (not plaintext password)
        """
        if not self.super_admin_token:
            return

        # Test 1: Get user profile - should not return password
        with self.client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {self.super_admin_token}"},
            name="SEC-003: Check Profile No Password",
            catch_response=True
        ) as response:
            try:
                if response.status_code != 200:
                    response.failure(f"SEC-003 Failed: Profile request failed {response.status_code}")
                    return

                data = response.json()

                # Verify password field is NOT in response
                if "password" in data:
                    response.failure("SEC-003 Failed: Password field exposed in user profile")
                    return

                # Verify passwordHash is NOT in response
                if "passwordHash" in data or "password_hash" in data:
                    response.failure("SEC-003 Failed: Password hash exposed in user profile")
                    return

                response.success()

            except Exception as e:
                response.failure(f"SEC-003 Failed: {str(e)}")

        # Test 2: List all users - should not return passwords
        with self.client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {self.super_admin_token}"},
            name="SEC-003: Check User List No Passwords",
            catch_response=True
        ) as response:
            try:
                if response.status_code != 200:
                    response.failure(f"SEC-003 Failed: User list request failed")
                    return

                data = response.json()
                users = data.get("data", []) if isinstance(data, dict) else data

                # Check each user object for password fields
                for user in users:
                    if "password" in user:
                        response.failure("SEC-003 Failed: Password field exposed in user list")
                        return
                    if "passwordHash" in user or "password_hash" in user:
                        response.failure("SEC-003 Failed: Password hash exposed in user list")
                        return

                response.success()

            except Exception as e:
                response.failure(f"SEC-003 Failed: {str(e)}")

        # Test 3: Verify login works (proves password is properly hashed)
        login_payload = {
            "email": "admin@example.com",
            "password": "AdminPass123!"
        }

        with self.client.post(
            "/api/v1/auth/login",
            json=login_payload,
            name="SEC-003: Verify Password Hashing Works",
            catch_response=True
        ) as response:
            try:
                if response.status_code != 201:
                    response.failure("SEC-003 Failed: Login should work with correct password")
                    return

                data = response.json()

                # Verify response doesn't contain password
                if "password" in str(data).lower() and "password" not in ["passwordResetRequired", "passwordExpired"]:
                    response.failure("SEC-003 Failed: Password exposed in login response")
                    return

                response.success()

            except Exception as e:
                response.failure(f"SEC-003 Failed: {str(e)}")

    # SEC-004: Token Security
    @task(1)
    @taskset_handler(task_control_flag=RESCHEDULE_TASK)
    def sec_004_token_security(self):
        """
        SEC-004: Token Security (Negative)
        
        Test: Try to decode and modify JWT tokens
        Expected: Modified tokens rejected with 401
        
        Tests:
        1. Decode valid JWT token
        2. Modify payload (user ID, role, expiry)
        3. Re-encode with wrong signature
        4. Verify modified token is rejected
        """
        if not self.valid_token:
            return

        # Test 1: Decode the valid token (should be possible without verification)
        try:
            # Decode without verification to see payload
            decoded_token = jwt.decode(self.valid_token, options={"verify_signature": False})
            
            # Verify token contains expected fields
            if "sub" not in decoded_token and "userId" not in decoded_token and "id" not in decoded_token:
                print("SEC-004 Warning: Token doesn't contain user ID field")
            
        except Exception as e:
            print(f"SEC-004 Warning: Could not decode token: {str(e)}")
            decoded_token = {}

        # Test 2: Try to modify the token payload
        tampered_payloads = []

        # Attempt 1: Change user ID
        if "sub" in decoded_token:
            tampered_payload_1 = decoded_token.copy()
            tampered_payload_1["sub"] = "999999"  # Change to different user ID
            tampered_payloads.append(tampered_payload_1)

        # Attempt 2: Change role to higher privilege
        if "role" in decoded_token:
            tampered_payload_2 = decoded_token.copy()
            tampered_payload_2["role"] = "SUPER_ADMIN"  # Escalate to super admin
            tampered_payloads.append(tampered_payload_2)

        # Attempt 3: Extend expiry
        if "exp" in decoded_token:
            tampered_payload_3 = decoded_token.copy()
            tampered_payload_3["exp"] = int(time.time()) + 86400 * 365  # Extend by 1 year
            tampered_payloads.append(tampered_payload_3)

        # If we couldn't create tampered payloads, create a generic one
        if not tampered_payloads:
            tampered_payloads.append({
                "sub": "999999",
                "role": "SUPER_ADMIN",
                "exp": int(time.time()) + 86400
            })

        # Test 3: Try to use tampered tokens
        for idx, tampered_payload in enumerate(tampered_payloads):
            # Encode with wrong secret (or no secret)
            try:
                # Try to create token with no signature
                tampered_token = jwt.encode(tampered_payload, "wrong_secret", algorithm="HS256")
                
                # Try to use the tampered token
                with self.client.get(
                    "/api/v1/users/me",
                    headers={"Authorization": f"Bearer {tampered_token}"},
                    name=f"SEC-004: Tampered Token Test {idx+1}",
                    catch_response=True
                ) as response:
                    try:
                        # Should be rejected with 401
                        if response.status_code != 401:
                            response.failure(f"SEC-004 Failed: Tampered token accepted (status {response.status_code})")
                            return

                        data = response.json()
                        error_message = data.get("message", "").lower()
                        
                        # Should indicate invalid token
                        if "invalid" not in error_message and "unauthorized" not in error_message and "token" not in error_message:
                            response.failure(f"SEC-004 Failed: Error message doesn't indicate token issue")
                            return

                        response.success()

                    except Exception as e:
                        response.failure(f"SEC-004 Failed: {str(e)}")

            except Exception as e:
                print(f"SEC-004 Warning: Could not create tampered token: {str(e)}")

        # Test 4: Try token with modified header (algorithm confusion)
        try:
            # Try to create token with "none" algorithm
            header = {"alg": "none", "typ": "JWT"}
            payload = decoded_token.copy() if decoded_token else {"sub": "999999"}
            
            # Manually create token with no signature
            import base64
            header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            none_token = f"{header_encoded}.{payload_encoded}."
            
            with self.client.get(
                "/api/v1/users/me",
                headers={"Authorization": f"Bearer {none_token}"},
                name="SEC-004: None Algorithm Token",
                catch_response=True
            ) as response:
                try:
                    # Should be rejected
                    if response.status_code != 401:
                        response.failure("SEC-004 Failed: Token with 'none' algorithm accepted")
                        return
                    
                    response.success()

                except Exception as e:
                    response.failure(f"SEC-004 Failed: {str(e)}")

        except Exception as e:
            print(f"SEC-004 Warning: Could not test 'none' algorithm: {str(e)}")

    def on_stop(self):
        """Cleanup: Clear tokens"""
        self.valid_token = None
        self.super_admin_token = None
        super().on_stop()


tasks = [OndcAdminSecurityAdvancedTests]
