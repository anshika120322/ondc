import json
import time
from locust import TaskSet, task, events
from common_test_foundation.lib.proxy.proxy_server import ProxyServer
from common_test_foundation.helpers.taskset_handler import RESCHEDULE_TASK, taskset_handler

"""
ONDC Admin Service - User Management Test Cases
TC-015 to TC-028: User profile, password, CRUD operations, and sessions
"""

@taskset_handler(RESCHEDULE_TASK)
class ONDCAdminUsersAPI(TaskSet):

    def on_start(self):
        self.step_name = 'ON_START'
        self.proxy = ProxyServer()
        self.proxy.start_capture(trx_id=self.step_name)
        self.client.verify = self.proxy.get_certificate()
        self.client.proxies = self.proxy.get_http_proxy_config()
        
        # Store tokens for different roles
        self.super_admin_token = None
        self.admin_token = None
        self.operator_token = None
        
        # Store created resources
        self.created_user_id = None
        self.active_session_id = None
        
        # Login as different users to get tokens
        self._login_all_roles()

    def _login_all_roles(self):
        """Helper method to login as all role types"""
        # Super Admin login
        super_admin_response = self.client.post(
            url="/auth/login",
            json={
                "email": "super@admin.com",
                "password": "SuperSecure@123"
            }
        )
        if super_admin_response.status_code == 200:
            self.super_admin_token = super_admin_response.cookies.get('accessToken')
        
        # Admin login
        admin_response = self.client.post(
            url="/auth/login",
            json={
                "email": "admin@example.com",
                "password": "AdminPass@123"
            }
        )
        if admin_response.status_code == 200:
            self.admin_token = admin_response.cookies.get('accessToken')
        
        # Operator login
        operator_response = self.client.post(
            url="/auth/login",
            json={
                "email": "operator@example.com",
                "password": "OperatorPass@123"
            }
        )
        if operator_response.status_code == 200:
            self.operator_token = operator_response.cookies.get('accessToken')

    # TC-015: Get Current User Profile
    @task(10)
    def tc015_get_current_user_profile(self):
        self.step_name = 'TC015_Get_Current_User_Profile'
        
        with self.client.get(
            name=self.step_name,
            url="/users/me",
            headers={
                "Authorization": f"Bearer {self.super_admin_token}"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-015 Failed: Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                # Verify required fields
                required_fields = ['id', 'email', 'firstName', 'lastName', 'role', 'status']
                for field in required_fields:
                    if field not in data:
                        response.failure(f"TC-015 Failed: Missing field {field}")
                        return
                
                # Ensure password and tokens are not exposed
                if 'password' in data:
                    response.failure("TC-015 Failed: Password exposed in response")
                    return
                
                if 'accessToken' in data or 'refreshToken' in data:
                    response.failure("TC-015 Failed: Tokens exposed in response")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-015 Failed: Error parsing response: {str(e)}")

    # TC-016: Update Own Profile
    @task(8)
    def tc016_update_own_profile(self):
        self.step_name = 'TC016_Update_Own_Profile'
        
        with self.client.patch(
            name=self.step_name,
            url="/users/me",
            headers={
                "Authorization": f"Bearer {self.admin_token}"
            },
            json={
                "firstName": "Updated",
                "lastName": "Name"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-016 Failed: Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                if data.get('firstName') != "Updated":
                    response.failure("TC-016 Failed: firstName not updated")
                    return
                
                if data.get('lastName') != "Name":
                    response.failure("TC-016 Failed: lastName not updated")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-016 Failed: Error parsing response: {str(e)}")

    # TC-017: Update Own Profile - Change Email (Negative)
    @task(5)
    def tc017_update_own_profile_change_email_negative(self):
        self.step_name = 'TC017_Update_Email_Negative'
        
        with self.client.patch(
            name=self.step_name,
            url="/users/me",
            headers={
                "Authorization": f"Bearer {self.operator_token}"
            },
            json={
                "email": "newemail@example.com"
            },
            catch_response=True
        ) as response:
            
            # Email change should be ignored or return validation error
            if response.status_code in [200, 400]:
                if response.status_code == 200:
                    try:
                        data = response.json()
                        # Email should not have changed
                        if data.get('email') == "newemail@example.com":
                            response.failure("TC-017 Failed: Email should not be changeable")
                            return
                    except:
                        pass
                
                response.success()
            else:
                response.failure(f"TC-017 Failed: Unexpected status {response.status_code}")

    # TC-018: Change Password - Success
    @task(6)
    def tc018_change_password_success(self):
        self.step_name = 'TC018_Change_Password_Success'
        
        with self.client.post(
            name=self.step_name,
            url="/users/change-password",
            headers={
                "Authorization": f"Bearer {self.super_admin_token}"
            },
            json={
                "currentPassword": "SuperSecure@123",
                "newPassword": "NewPassword@456"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-018 Failed: Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                # Should have success message
                if not data.get('success') and 'success' not in str(data).lower():
                    response.failure("TC-018 Failed: Expected success message")
                    return
                
                response.success()
                
                # Note: In real scenario, all sessions except current should be invalidated
                
            except Exception as e:
                response.failure(f"TC-018 Failed: Error parsing response: {str(e)}")

    # TC-019: Change Password - Wrong Current Password
    @task(4)
    def tc019_change_password_wrong_current(self):
        self.step_name = 'TC019_Change_Password_Wrong_Current'
        
        with self.client.post(
            name=self.step_name,
            url="/users/change-password",
            headers={
                "Authorization": f"Bearer {self.admin_token}"
            },
            json={
                "currentPassword": "WrongPassword@123",
                "newPassword": "NewPassword@456"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 401:
                response.failure(f"TC-019 Failed: Expected 401, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                if "current password" not in str(data).lower() and "incorrect" not in str(data).lower():
                    response.failure("TC-019 Failed: Expected current password incorrect message")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-019 Failed: Error parsing response: {str(e)}")

    # TC-020: List All Users - Admin
    @task(10)
    def tc020_list_all_users_admin(self):
        self.step_name = 'TC020_List_All_Users_Admin'
        
        with self.client.get(
            name=self.step_name,
            url="/users?page=1&limit=10",
            headers={
                "Authorization": f"Bearer {self.admin_token}"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-020 Failed: Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                # Check if paginated response
                if isinstance(data, dict):
                    # Paginated response with metadata
                    if 'data' not in data and 'users' not in data and 'items' not in data:
                        response.failure("TC-020 Failed: Expected paginated structure")
                        return
                    
                    # Check for total count
                    if 'total' not in data and 'totalCount' not in data:
                        response.failure("TC-020 Failed: Expected total count")
                        return
                    
                    users = data.get('data') or data.get('users') or data.get('items')
                elif isinstance(data, list):
                    users = data
                else:
                    response.failure("TC-020 Failed: Unexpected response format")
                    return
                
                # Verify no passwords in response
                for user in users:
                    if 'password' in user:
                        response.failure("TC-020 Failed: Password exposed in user list")
                        return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-020 Failed: Error parsing response: {str(e)}")

    # TC-021: List All Users - Operator (Negative)
    @task(6)
    def tc021_list_all_users_operator_negative(self):
        self.step_name = 'TC021_List_Users_Operator_Negative'
        
        with self.client.get(
            name=self.step_name,
            url="/users",
            headers={
                "Authorization": f"Bearer {self.operator_token}"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 403:
                response.failure(f"TC-021 Failed: Expected 403, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                if "insufficient permissions" not in str(data).lower() and "forbidden" not in str(data).lower():
                    response.failure("TC-021 Failed: Expected insufficient permissions message")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-021 Failed: Error parsing response: {str(e)}")

    # TC-022: Create User - Admin
    @task(8)
    def tc022_create_user_admin(self):
        self.step_name = 'TC022_Create_User_Admin'
        
        timestamp = int(time.time())
        
        with self.client.post(
            name=self.step_name,
            url="/users",
            headers={
                "Authorization": f"Bearer {self.admin_token}"
            },
            json={
                "email": f"qa_newuser{timestamp}@example.com",
                "password": "TempPass@123",
                "firstName": "New",
                "lastName": "User",
                "role": "OPERATOR"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 201:
                response.failure(f"TC-022 Failed: Expected 201, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                if not data.get('id'):
                    response.failure("TC-022 Failed: User ID not returned")
                    return
                
                # Store created user ID
                self.created_user_id = data.get('id')
                
                if data.get('role') != "OPERATOR":
                    response.failure(f"TC-022 Failed: Expected OPERATOR role, got {data.get('role')}")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-022 Failed: Error parsing response: {str(e)}")

    # TC-023: Create User Without Role - Admin
    @task(5)
    def tc023_create_user_without_role(self):
        self.step_name = 'TC023_Create_User_Without_Role'
        
        timestamp = int(time.time())
        
        with self.client.post(
            name=self.step_name,
            url="/users",
            headers={
                "Authorization": f"Bearer {self.admin_token}"
            },
            json={
                "email": f"qa_norole{timestamp}@example.com",
                "password": "TempPass@123",
                "firstName": "No",
                "lastName": "Role"
            },
            catch_response=True
        ) as response:
            
            # Should either create with default OPERATOR role (201) or require role field (400)
            if response.status_code == 201:
                try:
                    data = response.json()
                    
                    if data.get('role') != "OPERATOR":
                        response.failure(f"TC-023 Failed: Expected default OPERATOR role, got {data.get('role')}")
                        return
                    
                    response.success()
                except Exception as e:
                    response.failure(f"TC-023 Failed: Error parsing response: {str(e)}")
            elif response.status_code == 400:
                # Role field is required
                response.success()
            else:
                response.failure(f"TC-023 Failed: Expected 201 or 400, got {response.status_code}")

    # TC-024: Update User Role - Admin
    @task(6)
    def tc024_update_user_role_admin(self):
        self.step_name = 'TC024_Update_User_Role_Admin'
        
        # Get a user to update
        if not self.created_user_id:
            users_response = self.client.get(
                url="/users",
                headers={
                    "Authorization": f"Bearer {self.super_admin_token}"
                }
            )
            
            if users_response.status_code == 200:
                try:
                    data = users_response.json()
                    users = data.get('data') or data.get('users') or data.get('items') or data
                    
                    if isinstance(users, list) and len(users) > 0:
                        for user in users:
                            if user.get('role') == 'OPERATOR':
                                self.created_user_id = user.get('id')
                                break
                except:
                    pass
        
        if not self.created_user_id:
            return
        
        with self.client.patch(
            name=self.step_name,
            url=f"/users/{self.created_user_id}",
            headers={
                "Authorization": f"Bearer {self.super_admin_token}"
            },
            json={
                "role": "ADMIN"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-024 Failed: Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                if data.get('role') != "ADMIN":
                    response.failure("TC-024 Failed: User role not updated")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-024 Failed: Error parsing response: {str(e)}")

    # TC-025: Delete User - Super Admin
    @task(5)
    def tc025_delete_user_super_admin(self):
        self.step_name = 'TC025_Delete_User_Super_Admin'
        
        # Create a user to delete
        timestamp = int(time.time())
        create_response = self.client.post(
            url="/users",
            headers={
                "Authorization": f"Bearer {self.super_admin_token}"
            },
            json={
                "email": f"deleteme{timestamp}@example.com",
                "password": "DeleteMe@123",
                "firstName": "Delete",
                "lastName": "Me",
                "role": "OPERATOR"
            }
        )
        
        if create_response.status_code != 201:
            return
        
        try:
            created_user = create_response.json()
            user_id = created_user.get('id')
        except:
            return
        
        with self.client.delete(
            name=self.step_name,
            url=f"/users/{user_id}",
            headers={
                "Authorization": f"Bearer {self.super_admin_token}"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-025 Failed: Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                # Verify success message
                if not data.get('success') and 'success' not in str(data).lower():
                    response.failure("TC-025 Failed: Expected success message")
                    return
                
                response.success()
                
                # Note: User status should be set to INACTIVE, sessions invalidated
                
            except Exception as e:
                response.failure(f"TC-025 Failed: Error parsing response: {str(e)}")

    # TC-026: Delete Own Account (Negative)
    @task(4)
    def tc026_delete_own_account_negative(self):
        self.step_name = 'TC026_Delete_Own_Account_Negative'
        
        # Get current user's ID
        profile_response = self.client.get(
            url="/users/me",
            headers={
                "Authorization": f"Bearer {self.super_admin_token}"
            }
        )
        
        if profile_response.status_code != 200:
            return
        
        try:
            profile = profile_response.json()
            current_user_id = profile.get('id')
        except:
            return
        
        with self.client.delete(
            name=self.step_name,
            url=f"/users/{current_user_id}",
            headers={
                "Authorization": f"Bearer {self.super_admin_token}"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 400:
                response.failure(f"TC-026 Failed: Expected 400, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                if "cannot delete" not in str(data).lower() and "own account" not in str(data).lower():
                    response.failure("TC-026 Failed: Expected cannot delete own account message")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-026 Failed: Error parsing response: {str(e)}")

    # TC-027: View Active Sessions
    @task(6)
    def tc027_view_active_sessions(self):
        self.step_name = 'TC027_View_Active_Sessions'
        
        with self.client.get(
            name=self.step_name,
            url="/sessions/active",
            headers={
                "Authorization": f"Bearer {self.admin_token}"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-027 Failed: Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                if not isinstance(data, list):
                    response.failure("TC-027 Failed: Expected array of sessions")
                    return
                
                if len(data) == 0:
                    response.failure("TC-027 Failed: Expected at least one active session")
                    return
                
                # Verify session structure
                first_session = data[0]
                required_fields = ['sessionId', 'ipAddress', 'userAgent', 'createdAt']
                for field in required_fields:
                    if field not in first_session and field.lower() not in str(first_session).lower():
                        response.failure(f"TC-027 Failed: Session missing field {field}")
                        return
                
                # Store session ID for next test
                self.active_session_id = first_session.get('sessionId') or first_session.get('id')
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-027 Failed: Error parsing response: {str(e)}")

    # TC-028: Terminate Specific Session
    @task(4)
    def tc028_terminate_specific_session(self):
        self.step_name = 'TC028_Terminate_Specific_Session'
        
        # First, create a new session by logging in
        new_login_response = self.client.post(
            url="/auth/login",
            json={
                "email": "admin@example.com",
                "password": "AdminPass@123"
            }
        )
        
        if new_login_response.status_code != 200:
            return
        
        new_token = new_login_response.cookies.get('accessToken')
        
        # Get active sessions to find the session ID
        sessions_response = self.client.get(
            url="/sessions/active",
            headers={
                "Authorization": f"Bearer {new_token}"
            }
        )
        
        if sessions_response.status_code != 200:
            return
        
        try:
            sessions = sessions_response.json()
            if isinstance(sessions, list) and len(sessions) > 1:
                # Get a session that is not the current one
                session_to_terminate = sessions[0].get('sessionId') or sessions[0].get('id')
            else:
                return
        except:
            return
        
        with self.client.delete(
            name=self.step_name,
            url=f"/sessions/{session_to_terminate}",
            headers={
                "Authorization": f"Bearer {new_token}"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-028 Failed: Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                # Verify success message
                if not data.get('success') and 'success' not in str(data).lower():
                    response.failure("TC-028 Failed: Expected success message")
                    return
                
                response.success()
                
                # Note: Other sessions should remain active
                
            except Exception as e:
                response.failure(f"TC-028 Failed: Error parsing response: {str(e)}")

    def on_stop(self):
        self.proxy.stop_capture()
        self.proxy.quit()


tasks = [ONDCAdminUsersAPI]
