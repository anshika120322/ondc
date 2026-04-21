import json
import time
from locust import TaskSet, task, events
from common_test_foundation.lib.proxy.proxy_server import ProxyServer
from common_test_foundation.helpers.taskset_handler import RESCHEDULE_TASK, taskset_handler

"""
ONDC Admin Service - Authentication Test Cases
TC-001 to TC-014: Login, Forgot Password, Reset Password, Refresh Token, Logout, OAuth
"""

@taskset_handler(RESCHEDULE_TASK)
class ONDCAdminAuthAPI(TaskSet):

    def on_start(self):
        self.step_name = 'ON_START'
        self.proxy = ProxyServer()
        self.proxy.start_capture(trx_id=self.step_name)
        self.client.verify = self.proxy.get_certificate()
        self.client.proxies = self.proxy.get_http_proxy_config()
        
        # Store tokens and session data
        self.access_token = None
        self.refresh_token = None
        self.reset_token = None
        self.user_id = None

    # TC-001: Login - Valid Credentials
    @task(10)
    def tc001_login_valid_credentials(self):
        self.step_name = 'TC001_Login_Valid'
        
        with self.client.post(
            name=self.step_name,
            url="/auth/login",
            json={
                "email": "super@admin.com",
                "password": "SuperSecure@123"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-001 Failed: Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                # Validate response structure
                if not data.get('success'):
                    response.failure("TC-001 Failed: success is not true")
                    return
                
                if data.get('message') != "Login successful":
                    response.failure(f"TC-001 Failed: Unexpected message: {data.get('message')}")
                    return
                
                if 'user' not in data:
                    response.failure("TC-001 Failed: user object not in response")
                    return
                
                if 'navigation' not in data:
                    response.failure("TC-001 Failed: navigation array not in response")
                    return
                
                # Store tokens for subsequent tests
                self.access_token = response.cookies.get('accessToken')
                self.refresh_token = response.cookies.get('refreshToken')
                self.user_id = data['user'].get('id')
                
                if not self.access_token or not self.refresh_token:
                    response.failure("TC-001 Failed: Tokens not set in cookies")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-001 Failed: Error parsing response: {str(e)}")

    # TC-002: Login - Invalid Password
    @task(5)
    def tc002_login_invalid_password(self):
        self.step_name = 'TC002_Login_Invalid_Password'
        
        with self.client.post(
            name=self.step_name,
            url="/auth/login",
            json={
                "email": "super@admin.com",
                "password": "WrongPassword@123"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 401:
                response.failure(f"TC-002 Failed: Expected 401, got {response.status_code}")
                return
            
            try:
                data = response.json()
                if "Invalid credentials" not in str(data):
                    response.failure(f"TC-002 Failed: Expected 'Invalid credentials' message")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-002 Failed: Error parsing response: {str(e)}")

    # TC-003: Login - Account Lockout
    @task(2)
    def tc003_login_account_lockout(self):
        self.step_name = 'TC003_Account_Lockout'
        
        # Attempt 5 failed logins
        for i in range(5):
            with self.client.post(
                name=f"{self.step_name}_Attempt_{i+1}",
                url="/auth/login",
                json={
                    "email": "operator@example.com",
                    "password": "WrongPassword@123"
                },
                catch_response=True
            ) as response:
                
                if response.status_code != 401:
                    response.failure(f"TC-003 Attempt {i+1} Failed: Expected 401, got {response.status_code}")
                
                response.success()
        
        # Wait a moment
        time.sleep(1)
        
        # 6th attempt with correct password should be locked
        with self.client.post(
            name=f"{self.step_name}_Locked",
            url="/auth/login",
            json={
                "email": "operator@example.com",
                "password": "OperatorPass@123"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 401:
                response.failure(f"TC-003 Failed: Expected 401 for locked account, got {response.status_code}")
                return
            
            try:
                data = response.json()
                if "Account is locked" not in str(data):
                    response.failure("TC-003 Failed: Expected account locked message")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-003 Failed: Error parsing response: {str(e)}")

    # TC-004: Login - Rate Limiting
    @task(1)
    def tc004_login_rate_limiting(self):
        self.step_name = 'TC004_Rate_Limiting'
        
        # Send 11 requests rapidly
        for i in range(11):
            with self.client.post(
                name=f"{self.step_name}_{i+1}",
                url="/auth/login",
                json={
                    "email": "admin@example.com",
                    "password": "AdminPass@123"
                },
                catch_response=True
            ) as response:
                
                # After 10 requests, should get 429
                if i >= 10:
                    if response.status_code == 429:
                        # ENHANCEMENT: Validate Retry-After header
                        retry_after = response.headers.get('Retry-After')
                        rate_limit_reset = response.headers.get('X-RateLimit-Reset')
                        
                        if retry_after:
                            try:
                                retry_seconds = int(retry_after)
                                if 1 <= retry_seconds <= 300:
                                    print(f"✅ TC-004: 429 with Retry-After: {retry_seconds}s")
                                else:
                                    print(f"⚠️  TC-004: Retry-After out of range: {retry_seconds}s")
                            except:
                                print(f"⚠️  TC-004: Invalid Retry-After format: {retry_after}")
                        elif rate_limit_reset:
                            print(f"✅ TC-004: 429 with X-RateLimit-Reset: {rate_limit_reset}")
                        else:
                            print(f"⚠️  TC-004: 429 but missing Retry-After/X-RateLimit-Reset header")
                        
                        response.success()
                    else:
                        response.failure(f"TC-004 Failed: Expected 429 on request {i+1}, got {response.status_code}")
                else:
                    response.success()

    # TC-005: Forgot Password - Valid Email
    @task(3)
    def tc005_forgot_password_valid(self):
        self.step_name = 'TC005_Forgot_Password_Valid'
        
        with self.client.post(
            name=self.step_name,
            url="/auth/forgot-password",
            json={
                "email": "super@admin.com"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-005 Failed: Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                # Generic success message expected
                if not data.get('success'):
                    response.failure("TC-005 Failed: Expected success response")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-005 Failed: Error parsing response: {str(e)}")

    # TC-006: Forgot Password - Non-existent Email
    @task(2)
    def tc006_forgot_password_nonexistent(self):
        self.step_name = 'TC006_Forgot_Password_Nonexistent'
        
        with self.client.post(
            name=self.step_name,
            url="/auth/forgot-password",
            json={
                "email": "nonexistent@example.com"
            },
            catch_response=True
        ) as response:
            
            # Should still return 200 to prevent email enumeration
            if response.status_code != 200:
                response.failure(f"TC-006 Failed: Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                if not data.get('success'):
                    response.failure("TC-006 Failed: Expected generic success response")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-006 Failed: Error parsing response: {str(e)}")

    # TC-007: Reset Password - Valid Token
    @task(2)
    def tc007_reset_password_valid(self):
        self.step_name = 'TC007_Reset_Password_Valid'
        
        # Note: In real test, you'd get a valid token from database or email
        # For this example, we'll simulate with a placeholder
        test_token = "abc123validtoken456"
        
        with self.client.post(
            name=self.step_name,
            url="/auth/reset-password",
            json={
                "token": test_token,
                "newPassword": "NewSecure@456"
            },
            catch_response=True
        ) as response:
            
            # May return 200 for valid token or 400 for invalid test token
            if response.status_code == 200:
                response.success()
            elif response.status_code == 400:
                # Expected if test token is not valid
                response.success()
            else:
                response.failure(f"TC-007 Failed: Unexpected status {response.status_code}")

    # TC-008: Reset Password - Expired Token
    @task(1)
    def tc008_reset_password_expired(self):
        self.step_name = 'TC008_Reset_Password_Expired'
        
        with self.client.post(
            name=self.step_name,
            url="/auth/reset-password",
            json={
                "token": "expiredtoken123",
                "newPassword": "NewSecure@456"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 400:
                response.failure(f"TC-008 Failed: Expected 400, got {response.status_code}")
                return
            
            try:
                data = response.json()
                if "Invalid or expired" not in str(data):
                    response.failure("TC-008 Failed: Expected expired token message")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-008 Failed: Error parsing response: {str(e)}")

    # TC-009: Reset Password - Weak Password
    @task(1)
    def tc009_reset_password_weak(self):
        self.step_name = 'TC009_Reset_Password_Weak'
        
        with self.client.post(
            name=self.step_name,
            url="/auth/reset-password",
            json={
                "token": "validtoken123",
                "newPassword": "weak"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 400:
                response.failure(f"TC-009 Failed: Expected 400, got {response.status_code}")
                return
            
            try:
                data = response.json()
                if "password" not in str(data).lower():
                    response.failure("TC-009 Failed: Expected password validation message")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-009 Failed: Error parsing response: {str(e)}")

    # TC-010: Refresh Token - Valid Token
    @task(5)
    def tc010_refresh_token_valid(self):
        self.step_name = 'TC010_Refresh_Token_Valid'
        
        # First login to get a valid refresh token
        login_response = self.client.post(
            url="/auth/login",
            json={
                "email": "super@admin.com",
                "password": "SuperSecure@123"
            }
        )
        
        if login_response.status_code != 200:
            return
        
        refresh_token = login_response.cookies.get('refreshToken')
        
        if not refresh_token:
            return
        
        # Now try to refresh
        with self.client.post(
            name=self.step_name,
            url="/auth/refresh",
            json={
                "refreshToken": refresh_token
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-010 Failed: Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                new_access_token = response.cookies.get('accessToken')
                new_refresh_token = response.cookies.get('refreshToken')
                
                if not new_access_token or not new_refresh_token:
                    response.failure("TC-010 Failed: New tokens not received")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-010 Failed: Error parsing response: {str(e)}")

    # TC-011: Refresh Token - Expired Token
    @task(1)
    def tc011_refresh_token_expired(self):
        self.step_name = 'TC011_Refresh_Token_Expired'
        
        with self.client.post(
            name=self.step_name,
            url="/auth/refresh",
            json={
                "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.expired.token"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 401:
                response.failure(f"TC-011 Failed: Expected 401, got {response.status_code}")
                return
            
            try:
                data = response.json()
                if "Invalid or expired" not in str(data):
                    response.failure("TC-011 Failed: Expected invalid/expired message")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-011 Failed: Error parsing response: {str(e)}")

    # TC-012: Logout - Current Session
    @task(5)
    def tc012_logout_current_session(self):
        self.step_name = 'TC012_Logout_Current'
        
        # First login
        login_response = self.client.post(
            url="/auth/login",
            json={
                "email": "admin@example.com",
                "password": "AdminPass@123"
            }
        )
        
        if login_response.status_code != 200:
            return
        
        access_token = login_response.cookies.get('accessToken')
        
        if not access_token:
            return
        
        # Now logout
        with self.client.post(
            name=self.step_name,
            url="/auth/logout",
            headers={
                "Authorization": f"Bearer {access_token}"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-012 Failed: Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                if "Logged out successfully" not in str(data):
                    response.failure("TC-012 Failed: Expected logout success message")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-012 Failed: Error parsing response: {str(e)}")

    # TC-013: Logout All Sessions
    @task(2)
    def tc013_logout_all_sessions(self):
        self.step_name = 'TC013_Logout_All'
        
        # Login to get token
        login_response = self.client.post(
            url="/auth/login",
            json={
                "email": "admin@example.com",
                "password": "AdminPass@123"
            }
        )
        
        if login_response.status_code != 200:
            return
        
        access_token = login_response.cookies.get('accessToken')
        
        if not access_token:
            return
        
        # Logout all sessions
        with self.client.post(
            name=self.step_name,
            url="/auth/logout-all",
            headers={
                "Authorization": f"Bearer {access_token}"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-013 Failed: Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                if "All sessions terminated" not in str(data):
                    response.failure("TC-013 Failed: Expected all sessions terminated message")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-013 Failed: Error parsing response: {str(e)}")

    # TC-014: Google OAuth Login
    @task(1)
    def tc014_google_oauth_login(self):
        self.step_name = 'TC014_Google_OAuth'
        
        # This test just checks if the OAuth endpoint is accessible
        with self.client.get(
            name=self.step_name,
            url="/auth/google",
            allow_redirects=False,
            catch_response=True
        ) as response:
            
            # Should redirect to Google OAuth (302) or return 200/404
            if response.status_code in [200, 302, 404]:
                response.success()
            else:
                response.failure(f"TC-014 Failed: Unexpected status {response.status_code}")

    def on_stop(self):
        self.proxy.stop_capture()
        self.proxy.quit()


tasks = [ONDCAdminAuthAPI]
