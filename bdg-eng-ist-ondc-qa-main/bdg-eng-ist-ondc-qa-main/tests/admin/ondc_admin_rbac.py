import json
import time
from locust import TaskSet, task, events
from common_test_foundation.lib.proxy.proxy_server import ProxyServer
from common_test_foundation.helpers.taskset_handler import RESCHEDULE_TASK, taskset_handler

"""
ONDC Admin Service - RBAC (Role-Based Access Control) Test Cases
TC-029 to TC-036: Pages, Groups, and RBAC Management
"""

@taskset_handler(RESCHEDULE_TASK)
class ONDCAdminRbacAPI(TaskSet):

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
        
        # Store created resources for dependent tests
        self.created_page_id = None
        self.created_group_id = None
        self.created_user_id = None
        
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

    # TC-029: View My Pages - Super Admin
    @task(10)
    def tc029_view_my_pages_super_admin(self):
        self.step_name = 'TC029_View_My_Pages_Super_Admin'
        
        with self.client.get(
            name=self.step_name,
            url="/rbac/my-pages",
            headers={
                "Authorization": f"Bearer {self.super_admin_token}"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-029 Failed: Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                if not isinstance(data, list):
                    response.failure("TC-029 Failed: Expected array of pages")
                    return
                
                # Super Admin should have access to 5 pages
                expected_pages = ["Dashboard", "Users", "Settings", "Reports", "Analytics"]
                
                if len(data) != 5:
                    response.failure(f"TC-029 Failed: Expected 5 pages, got {len(data)}")
                    return
                
                # Validate each page has required fields
                required_fields = ['id', 'name', 'path', 'icon', 'description']
                for page in data:
                    for field in required_fields:
                        if field not in page:
                            response.failure(f"TC-029 Failed: Page missing field {field}")
                            return
                
                # Verify expected page names are present
                page_names = [page.get('name') for page in data]
                for expected_page in expected_pages:
                    if expected_page not in page_names:
                        response.failure(f"TC-029 Failed: Missing expected page {expected_page}")
                        return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-029 Failed: Error parsing response: {str(e)}")

    # TC-030: View My Pages - Admin
    @task(8)
    def tc030_view_my_pages_admin(self):
        self.step_name = 'TC030_View_My_Pages_Admin'
        
        with self.client.get(
            name=self.step_name,
            url="/rbac/my-pages",
            headers={
                "Authorization": f"Bearer {self.admin_token}"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-030 Failed: Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                if not isinstance(data, list):
                    response.failure("TC-030 Failed: Expected array of pages")
                    return
                
                # Admin should have access to 4 pages (Dashboard, Users, Settings, Reports)
                expected_pages = ["Dashboard", "Users", "Settings", "Reports"]
                excluded_pages = ["Analytics"]
                
                if len(data) != 4:
                    response.failure(f"TC-030 Failed: Expected 4 pages, got {len(data)}")
                    return
                
                # Verify expected page names are present
                page_names = [page.get('name') for page in data]
                for expected_page in expected_pages:
                    if expected_page not in page_names:
                        response.failure(f"TC-030 Failed: Missing expected page {expected_page}")
                        return
                
                # Verify Analytics is not included
                for excluded_page in excluded_pages:
                    if excluded_page in page_names:
                        response.failure(f"TC-030 Failed: {excluded_page} should not be included for Admin")
                        return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-030 Failed: Error parsing response: {str(e)}")

    # TC-031: View My Pages - Operator
    @task(6)
    def tc031_view_my_pages_operator(self):
        self.step_name = 'TC031_View_My_Pages_Operator'
        
        with self.client.get(
            name=self.step_name,
            url="/rbac/my-pages",
            headers={
                "Authorization": f"Bearer {self.operator_token}"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-031 Failed: Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                if not isinstance(data, list):
                    response.failure("TC-031 Failed: Expected array of pages")
                    return
                
                # Operator should have access to 3 pages (Dashboard, Reports, Settings)
                expected_pages = ["Dashboard", "Reports", "Settings"]
                excluded_pages = ["Users", "Analytics"]
                
                if len(data) != 3:
                    response.failure(f"TC-031 Failed: Expected 3 pages, got {len(data)}")
                    return
                
                # Verify expected page names are present
                page_names = [page.get('name') for page in data]
                for expected_page in expected_pages:
                    if expected_page not in page_names:
                        response.failure(f"TC-031 Failed: Missing expected page {expected_page}")
                        return
                
                # Verify Users and Analytics are not included
                for excluded_page in excluded_pages:
                    if excluded_page in page_names:
                        response.failure(f"TC-031 Failed: {excluded_page} should not be included for Operator")
                        return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-031 Failed: Error parsing response: {str(e)}")

    # TC-032: Create Page - Admin
    @task(5)
    def tc032_create_page_admin(self):
        self.step_name = 'TC032_Create_Page_Admin'
        
        timestamp = int(time.time())
        
        with self.client.post(
            name=self.step_name,
            url="/pages",
            headers={
                "Authorization": f"Bearer {self.admin_token}"
            },
            json={
                "name": "QA Test Page",
                "path": f"/qa-test-{timestamp}",
                "icon": "test",
                "description": "QA Testing Page",
                "isActive": True
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 201:
                response.failure(f"TC-032 Failed: Expected 201, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                if not data.get('id'):
                    response.failure("TC-032 Failed: Page ID not returned")
                    return
                
                # Store page ID for dependent tests
                self.created_page_id = data.get('id')
                
                if data.get('name') != "QA Test Page":
                    response.failure("TC-032 Failed: Page name mismatch")
                    return
                
                if data.get('path') != f"/qa-test-{timestamp}":
                    response.failure("TC-032 Failed: Page path mismatch")
                    return
                
                if data.get('icon') != "test":
                    response.failure("TC-032 Failed: Page icon mismatch")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-032 Failed: Error parsing response: {str(e)}")

    # TC-033: Assign Page to Role
    @task(4)
    def tc033_assign_page_to_role(self):
        self.step_name = 'TC033_Assign_Page_To_Role'
        
        # First, get or create a page
        if not self.created_page_id:
            # Get existing pages
            pages_response = self.client.get(
                url="/pages",
                headers={
                    "Authorization": f"Bearer {self.admin_token}"
                }
            )
            
            if pages_response.status_code == 200:
                try:
                    pages = pages_response.json()
                    if isinstance(pages, list) and len(pages) > 0:
                        self.created_page_id = pages[0].get('id')
                except:
                    pass
        
        if not self.created_page_id:
            # Skip test if no page available
            return
        
        with self.client.post(
            name=self.step_name,
            url="/pages/role-page",
            headers={
                "Authorization": f"Bearer {self.admin_token}"
            },
            json={
                "pageId": self.created_page_id,
                "role": "OPERATOR"
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 201:
                response.failure(f"TC-033 Failed: Expected 201, got {response.status_code}")
                return
            
            try:
                # Verify assignment was created
                response.success()
                
            except Exception as e:
                response.failure(f"TC-033 Failed: Error parsing response: {str(e)}")

    # TC-034: Create Group
    @task(6)
    def tc034_create_group(self):
        self.step_name = 'TC034_Create_Group'
        
        timestamp = int(time.time())
        
        with self.client.post(
            name=self.step_name,
            url="/groups",
            headers={
                "Authorization": f"Bearer {self.admin_token}"
            },
            json={
                "name": f"QA Testers {timestamp}",
                "description": "Quality Assurance Team",
                "isActive": True
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 201:
                response.failure(f"TC-034 Failed: Expected 201, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                if not data.get('id'):
                    response.failure("TC-034 Failed: Group ID not returned")
                    return
                
                # Store group ID for dependent tests
                self.created_group_id = data.get('id')
                
                if data.get('name') != f"QA Testers {timestamp}":
                    response.failure("TC-034 Failed: Group name mismatch")
                    return
                
                if data.get('description') != "Quality Assurance Team":
                    response.failure("TC-034 Failed: Group description mismatch")
                    return
                
                response.success()
                
            except Exception as e:
                response.failure(f"TC-034 Failed: Error parsing response: {str(e)}")

    # TC-035: Assign User to Group
    @task(5)
    def tc035_assign_user_to_group(self):
        self.step_name = 'TC035_Assign_User_To_Group'
        
        # Get or create necessary resources
        if not self.created_group_id:
            # Get existing groups
            groups_response = self.client.get(
                url="/groups",
                headers={
                    "Authorization": f"Bearer {self.admin_token}"
                }
            )
            
            if groups_response.status_code == 200:
                try:
                    groups = groups_response.json()
                    if isinstance(groups, list) and len(groups) > 0:
                        self.created_group_id = groups[0].get('id')
                except:
                    pass
        
        # Get a user to assign
        if not self.created_user_id:
            users_response = self.client.get(
                url="/users",
                headers={
                    "Authorization": f"Bearer {self.admin_token}"
                }
            )
            
            if users_response.status_code == 200:
                try:
                    users = users_response.json()
                    if isinstance(users, list) and len(users) > 0:
                        # Find an operator user
                        for user in users:
                            if user.get('role') == 'OPERATOR':
                                self.created_user_id = user.get('id')
                                break
                except:
                    pass
        
        if not self.created_group_id or not self.created_user_id:
            # Skip test if resources not available
            return
        
        with self.client.post(
            name=self.step_name,
            url="/groups/assign-user",
            headers={
                "Authorization": f"Bearer {self.admin_token}"
            },
            json={
                "userId": self.created_user_id,
                "groupId": self.created_group_id
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 201:
                response.failure(f"TC-035 Failed: Expected 201, got {response.status_code}")
                return
            
            try:
                # Verify user-group association created
                response.success()
                
            except Exception as e:
                response.failure(f"TC-035 Failed: Error parsing response: {str(e)}")

    # TC-036: Assign Page to Group
    @task(4)
    def tc036_assign_page_to_group(self):
        self.step_name = 'TC036_Assign_Page_To_Group'
        
        # Get or create necessary resources
        if not self.created_page_id:
            pages_response = self.client.get(
                url="/pages",
                headers={
                    "Authorization": f"Bearer {self.admin_token}"
                }
            )
            
            if pages_response.status_code == 200:
                try:
                    pages = pages_response.json()
                    if isinstance(pages, list) and len(pages) > 0:
                        self.created_page_id = pages[0].get('id')
                except:
                    pass
        
        if not self.created_group_id:
            groups_response = self.client.get(
                url="/groups",
                headers={
                    "Authorization": f"Bearer {self.admin_token}"
                }
            )
            
            if groups_response.status_code == 200:
                try:
                    groups = groups_response.json()
                    if isinstance(groups, list) and len(groups) > 0:
                        self.created_group_id = groups[0].get('id')
                except:
                    pass
        
        if not self.created_page_id or not self.created_group_id:
            # Skip test if resources not available
            return
        
        with self.client.post(
            name=self.step_name,
            url="/groups/assign-page",
            headers={
                "Authorization": f"Bearer {self.admin_token}"
            },
            json={
                "pageId": self.created_page_id,
                "groupId": self.created_group_id
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 201:
                response.failure(f"TC-036 Failed: Expected 201, got {response.status_code}")
                return
            
            try:
                # Verify page-group association created
                response.success()
                
            except Exception as e:
                response.failure(f"TC-036 Failed: Error parsing response: {str(e)}")

    def on_stop(self):
        self.proxy.stop_capture()
        self.proxy.quit()


tasks = [ONDCAdminRbacAPI]
