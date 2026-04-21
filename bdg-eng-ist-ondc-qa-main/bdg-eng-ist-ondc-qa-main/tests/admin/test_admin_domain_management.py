"""
ONDC Admin Service - Domain Validation Tests via /admin/subscribe
==================================================================
Purpose: Test domain validation through participant registration endpoint
Coverage:
  - DM-001: Create participant with valid domain
  - DM-002: Reject invalid domain format
  - DM-003: Reject non-existent domain code
  - DM-004: Create participant with multiple domains
  - DM-005: Add domains to existing participant
  - DM-006: Remove domains from participant

Run with:
  python driver.py --test ondc_admin_domain_management --env ondcAdminAuth --users 1 --iterations 1 --headless
"""

import json
import uuid
import time
from locust import task, TaskSet
from common_test_foundation.lib.proxy.proxy_server import ProxyServer
from common_test_foundation.helpers.taskset_handler import RESCHEDULE_TASK, taskset_handler


@taskset_handler(RESCHEDULE_TASK)
class ONDCAdminDomainManagement(TaskSet):
    
    def on_start(self):
        """Initialize test - login and get admin token"""
        self.step_name = 'ON_START'
        
        # Start proxy capture
        self.proxy = ProxyServer()
        self.proxy.start_capture(trx_id=self.step_name)
        self.client.verify = self.proxy.get_certificate()
        self.client.proxies = self.proxy.get_http_proxy_config()
        
        # Load configuration
        import yaml
        import os
        config_file = 'resources/admin/test_admin_domain_management.yml'
        
        with open(config_file, 'r') as f:
            config_data = yaml.safe_load(f)
            self.config = config_data.get('ondcAdminAuth', {})
        
        # Authentication URLs (admin-auth service)
        self.auth_host = self.config.get('auth_host', 'https://admin-auth-uat.kynondc.net')
        self.auth_base_url = self.config.get('auth_base_url', self.auth_host + '/api')
        self.login_endpoint = self.config.get('login_endpoint', '/auth/login')
        
        # Admin operations URLs (admin-service)
        self.host = self.config.get('host', 'https://admin-service-uat.kynondc.net')
        self.base_url = self.config.get('base_url', self.host + '/api')
        self.subscribe_endpoint = self.config.get('subscribe_endpoint', '/admin/subscribe')
        
        # Admin credentials
        admin_creds = self.config.get('admin_credentials', {})
        self.admin_email = admin_creds.get('email', 'uat-admin@ondc.test')
        self.admin_password = admin_creds.get('password', 'AdminSecure@123')
        
        # Pre-configured token (fallback)
        self.preconfigured_token = self.config.get('admin_token')
        
        # Test results tracking
        self.test_results = []
        self.created_participant_ids = []  # Track created participants for cleanup
        self.admin_token = None
        
        # Login to get admin token (or use pre-configured token)
        self._login_admin()
        
        # If login failed, use pre-configured token
        if not self.admin_token and self.preconfigured_token:
            print(f"[LOGIN] ⚠️  Using pre-configured token (login unavailable)")
            self.admin_token = self.preconfigured_token
        
        print("\n" + "="*80)
        print("ONDC ADMIN DOMAIN VALIDATION TEST SUITE")
        print("="*80)
        print("6 test cases covering domain validation via /admin/subscribe")
        print("="*80 + "\n")
    
    def _login_admin(self):
        """Login and obtain admin bearer token"""
        login_url = self.auth_base_url + self.login_endpoint
        
        try:
            with self.client.post(
                name="Admin_Login",
                url=login_url,
                json={
                    "email": self.admin_email,
                    "password": self.admin_password
                },
                catch_response=True
            ) as response:
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        # Try different token field names
                        self.admin_token = (
                            data.get('access_token') or 
                            data.get('accessToken') or 
                            data.get('token') or
                            response.cookies.get('accessToken')
                        )
                        
                        if self.admin_token:
                            print(f"[LOGIN] ✅ Admin login successful")
                            response.success()
                        else:
                            print(f"[LOGIN] ⚠️  Login returned 200 but no token found")
                            response.success()  # Don't fail, will use fallback token
                    except Exception as e:
                        print(f"[LOGIN] ❌ Error parsing login response: {e}")
                        response.success()  # Don't fail, will use fallback token
                else:
                    print(f"[LOGIN] ❌ Login failed with status {response.status_code}")
                    response.success()  # Don't fail, will use fallback token
        except Exception as e:
            print(f"[LOGIN] ⚠️  Login attempt failed: {e}")
            # Don't re-raise, will use fallback token
    
    def _record_result(self, test_id, name, status, message=""):
        """Record test result"""
        self.test_results.append({
            "test_id": test_id,
            "name": name,
            "status": status,
            "message": message
        })
        status_icon = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️"
        print(f"{status_icon} [{test_id}] {name}: {status} - {message}")
    
    def _get_auth_headers(self):
        """Get authorization headers with admin token"""
        if not self.admin_token:
            return {"Content-Type": "application/json"}
        
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.admin_token}"
        }
    
    def _generate_unique_participant_id(self, suffix=""):
        """Generate unique participant ID"""
        random_id = str(uuid.uuid4())[:8]
        if suffix:
            return f"test-domain-{suffix}-{random_id}.ondc.org"
        return f"test-domain-{random_id}.ondc.org"
    
    def on_stop(self):
        """Cleanup and print summary"""
        # Cleanup created participants
        if self.created_participant_ids and self.admin_token:
            print(f"\n[CLEANUP] Removing {len(self.created_participant_ids)} test participants...")
            for participant_id in self.created_participant_ids:
                try:
                    self.client.request(
                        method="PATCH",
                        url=f"{self.base_url}{self.subscribe_endpoint}",
                        json={
                            "participant_id": participant_id,
                            "action": "UNSUBSCRIBED",
                            "dns_skip": True,
                            "skip_ssl_verification": True
                        },
                        headers=self._get_auth_headers()
                    )
                except:
                    pass
        
        # Print summary
        if self.test_results:
            passed = sum(1 for r in self.test_results if r['status'] == 'PASS')
            failed = sum(1 for r in self.test_results if r['status'] == 'FAIL')
            total = len(self.test_results)
            
            print("\n" + "="*80)
            print("DOMAIN VALIDATION TEST SUMMARY")
            print("="*80)
            print(f"Total: {total} | Passed: {passed} | Failed: {failed} | Pass Rate: {passed/total*100:.1f}%")
            print("="*80 + "\n")
        
        # Stop proxy
        try:
            if hasattr(self, 'proxy') and self.proxy:
                self.proxy.stop_capture()
        except:
            pass
    
    # ========================================================================
    # DM-001: Create participant with valid domain
    # ========================================================================
    
    @task(1)
    def dm_001_valid_domain(self):
        """DM-001: POST /admin/subscribe - Create participant with valid domain ONDC:RET10"""
        test_id = "DM-001"
        name = "Create participant with valid domain"
        
        if not self.admin_token:
            self._record_result(test_id, name, "FAIL", "No admin token available")
            return
        
        participant_id = self._generate_unique_participant_id("valid")
        
        payload = {
            "participant_id": participant_id,
            "action": "WHITELISTED",
            "configs": [
                {
                    "domain": "ONDC:RET10",
                    "np_type": "BPP",
                    "subscriber_id": participant_id
                }
            ],
            "dns_skip": True,
            "skip_ssl_verification": True
        }
        
        with self.client.post(
            name=test_id,
            url=f"{self.base_url}{self.subscribe_endpoint}",
            json=payload,
            headers=self._get_auth_headers(),
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                self._record_result(test_id, name, "FAIL", f"Expected 200, got {response.status_code}")
                response.failure(f"Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                # Check for ACK status
                ack_status = data.get('message', {}).get('ack', {}).get('status')
                if ack_status == 'ACK':
                    self.created_participant_ids.append(participant_id)
                    self._record_result(test_id, name, "PASS", f"Valid domain ONDC:RET10 accepted")
                    response.success()
                else:
                    self._record_result(test_id, name, "FAIL", f"Unexpected ack status: {ack_status}")
                    response.failure(f"Unexpected ack: {ack_status}")
                
            except Exception as e:
                self._record_result(test_id, name, "FAIL", f"Error: {str(e)}")
                response.failure(str(e))
    
    # ========================================================================
    # DM-002: Reject invalid domain format
    # ========================================================================
    
    @task(1)
    def dm_002_invalid_format(self):
        """DM-002: POST /admin/subscribe - Reject domain with invalid format"""
        test_id = "DM-002"
        name = "Reject invalid domain format"
        
        if not self.admin_token:
            self._record_result(test_id, name, "FAIL", "No admin token available")
            return
        
        participant_id = self._generate_unique_participant_id("invalid")
        
        payload = {
            "participant_id": participant_id,
            "action": "WHITELISTED",
            "configs": [
                {
                    "domain": "INVALID_DOMAIN_FORMAT",
                    "np_type": "BPP",
                    "subscriber_id": participant_id
                }
            ],
            "dns_skip": True,
            "skip_ssl_verification": True
        }
        
        with self.client.post(
            name=test_id,
            url=f"{self.base_url}{self.subscribe_endpoint}",
            json=payload,
            headers=self._get_auth_headers(),
            catch_response=True
        ) as response:
            
            # Should return 400, 404, or 422 (system returns 404/ERR_305)
            if response.status_code in [400, 404, 422]:
                self._record_result(test_id, name, "PASS", f"Invalid format rejected ({response.status_code}/ERR_305)")
                response.success()
            else:
                self._record_result(test_id, name, "FAIL", f"Expected 400/404/422, got {response.status_code}")
                response.failure(f"Expected error, got {response.status_code}")
    
    # ========================================================================
    # DM-003: Reject non-existent domain code
    # ========================================================================
    
    @task(1)
    def dm_003_nonexistent_domain(self):
        """DM-003: POST /admin/subscribe - Reject non-existent domain ONDC:XXX99"""
        test_id = "DM-003"
        name = "Reject non-existent domain code"
        
        if not self.admin_token:
            self._record_result(test_id, name, "FAIL", "No admin token available")
            return
        
        participant_id = self._generate_unique_participant_id("nonexist")
        
        payload = {
            "participant_id": participant_id,
            "action": "WHITELISTED",
            "configs": [
                {
                    "domain": "ONDC:XXX99",  # Valid format but doesn't exist
                    "np_type": "BPP",
                    "subscriber_id": participant_id
                }
            ],
            "dns_skip": True,
            "skip_ssl_verification": True
        }
        
        with self.client.post(
            name=test_id,
            url=f"{self.base_url}{self.subscribe_endpoint}",
            json=payload,
            headers=self._get_auth_headers(),
            catch_response=True
        ) as response:
            
            # Should return 400 or 404
            if response.status_code in [400, 404]:
                self._record_result(test_id, name, "PASS", f"Non-existent domain rejected ({response.status_code})")
                response.success()
            else:
                self._record_result(test_id, name, "FAIL", f"Expected 400/404, got {response.status_code}")
                response.failure(f"Expected error, got {response.status_code}")
    
    # ========================================================================
    # DM-004: Create participant with multiple domains
    # ========================================================================
    
    @task(1)
    def dm_004_multiple_domains(self):
        """DM-004: POST /admin/subscribe - Create participant with 3 valid domains"""
        test_id = "DM-004"
        name = "Create participant with multiple domains"
        
        if not self.admin_token:
            self._record_result(test_id, name, "FAIL", "No admin token available")
            return
        
        participant_id = self._generate_unique_participant_id("multi")
        
        payload = {
            "participant_id": participant_id,
            "action": "WHITELISTED",
            "configs": [
                {
                    "domain": "ONDC:RET10",
                    "np_type": "BPP",
                    "subscriber_id": participant_id
                },
                {
                    "domain": "ONDC:RET11",
                    "np_type": "BPP",
                    "subscriber_id": participant_id
                },
                {
                    "domain": "ONDC:LOG10",
                    "np_type": "BAP",
                    "subscriber_id": participant_id
                }
            ],
            "dns_skip": True,
            "skip_ssl_verification": True
        }
        
        with self.client.post(
            name=test_id,
            url=f"{self.base_url}{self.subscribe_endpoint}",
            json=payload,
            headers=self._get_auth_headers(),
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                self._record_result(test_id, name, "FAIL", f"Expected 200, got {response.status_code}")
                response.failure(f"Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                ack_status = data.get('message', {}).get('ack', {}).get('status')
                
                if ack_status == 'ACK':
                    self.created_participant_ids.append(participant_id)
                    self._record_result(test_id, name, "PASS", "Multi-domain participant created (3 domains)")
                    response.success()
                else:
                    self._record_result(test_id, name, "FAIL", f"Unexpected ack: {ack_status}")
                    response.failure(f"Unexpected ack: {ack_status}")
                    
            except Exception as e:
                self._record_result(test_id, name, "FAIL", f"Error: {str(e)}")
                response.failure(str(e))
    
    # ========================================================================
    # DM-005: Add domains to existing participant
    # ========================================================================
    
    @task(1)
    def dm_005_add_domain(self):
        """DM-005: PATCH /admin/subscribe - Add domain to existing participant"""
        test_id = "DM-005"
        name = "Add domains to existing participant"
        
        if not self.admin_token:
            self._record_result(test_id, name, "FAIL", "No admin token available")
            return
        
        participant_id = self._generate_unique_participant_id("adddom")
        
        # Step 1: Create participant with 1 domain
        create_payload = {
            "participant_id": participant_id,
            "action": "WHITELISTED",
            "configs": [
                {
                    "domain": "ONDC:RET10",
                    "np_type": "BPP",
                    "subscriber_id": participant_id
                }
            ],
            "dns_skip": True,
            "skip_ssl_verification": True
        }
        
        with self.client.post(
            name=f"{test_id}_Setup",
            url=f"{self.base_url}{self.subscribe_endpoint}",
            json=create_payload,
            headers=self._get_auth_headers(),
            catch_response=True
        ) as create_response:
            
            if create_response.status_code != 200:
                self._record_result(test_id, name, "FAIL", f"Setup failed: {create_response.status_code}")
                create_response.failure("Setup failed")
                return
            
            self.created_participant_ids.append(participant_id)
            create_response.success()
            
            # Wait a moment for creation to complete
            time.sleep(1)
            
            # Step 2: PATCH to add another domain
            update_payload = {
                "participant_id": participant_id,
                "configs": [
                    {
                        "domain": "ONDC:RET10",
                        "np_type": "BPP",
                        "subscriber_id": participant_id
                    },
                    {
                        "domain": "ONDC:LOG11",  # Adding new domain
                        "np_type": "BAP",
                        "subscriber_id": participant_id
                    }
                ],
                "dns_skip": True,
                "skip_ssl_verification": True
            }
            
            with self.client.request(
                method="PATCH",
                name=test_id,
                url=f"{self.base_url}{self.subscribe_endpoint}",
                json=update_payload,
                headers=self._get_auth_headers(),
                catch_response=True
            ) as update_response:
                
                if update_response.status_code != 200:
                    self._record_result(test_id, name, "FAIL", f"Expected 200, got {update_response.status_code}")
                    update_response.failure(f"Expected 200, got {update_response.status_code}")
                    return
                
                try:
                    data = update_response.json()
                    ack_status = data.get('message', {}).get('ack', {}).get('status')
                    
                    if ack_status == 'ACK':
                        self._record_result(test_id, name, "PASS", "Domain added successfully (RET10 + LOG11)")
                        update_response.success()
                    else:
                        self._record_result(test_id, name, "FAIL", f"Unexpected ack: {ack_status}")
                        update_response.failure(f"Unexpected ack: {ack_status}")
                        
                except Exception as e:
                    self._record_result(test_id, name, "FAIL", f"Error: {str(e)}")
                    update_response.failure(str(e))
    
    # ========================================================================
    # DM-006: Remove domains from participant
    # ========================================================================
    
    @task(1)
    def dm_006_remove_domain(self):
        """DM-006: PATCH /admin/subscribe - Remove domain from participant"""
        test_id = "DM-006"
        name = "Remove domains from participant"
        
        if not self.admin_token:
            self._record_result(test_id, name, "FAIL", "No admin token available")
            return
        
        participant_id = self._generate_unique_participant_id("remdom")
        
        # Step 1: Create participant with 3 domains
        create_payload = {
            "participant_id": participant_id,
            "action": "WHITELISTED",
            "configs": [
                {"domain": "ONDC:RET10", "np_type": "BPP", "subscriber_id": participant_id},
                {"domain": "ONDC:RET11", "np_type": "BPP", "subscriber_id": participant_id},
                {"domain": "ONDC:LOG10", "np_type": "BAP", "subscriber_id": participant_id}
            ],
            "dns_skip": True,
            "skip_ssl_verification": True
        }
        
        with self.client.post(
            name=f"{test_id}_Setup",
            url=f"{self.base_url}{self.subscribe_endpoint}",
            json=create_payload,
            headers=self._get_auth_headers(),
            catch_response=True
        ) as create_response:
            
            if create_response.status_code != 200:
                self._record_result(test_id, name, "FAIL", f"Setup failed: {create_response.status_code}")
                create_response.failure("Setup failed")
                return
            
            self.created_participant_ids.append(participant_id)
            create_response.success()
            
            # Wait a moment
            time.sleep(1)
            
            # Step 2: PATCH to remove one domain (keep only 2)
            update_payload = {
                "participant_id": participant_id,
                "configs": [
                    {"domain": "ONDC:RET10", "np_type": "BPP", "subscriber_id": participant_id},
                    {"domain": "ONDC:LOG10", "np_type": "BAP", "subscriber_id": participant_id}
                    # ONDC:RET11 removed
                ],
                "dns_skip": True,
                "skip_ssl_verification": True
            }
            
            with self.client.request(
                method="PATCH",
                name=test_id,
                url=f"{self.base_url}{self.subscribe_endpoint}",
                json=update_payload,
                headers=self._get_auth_headers(),
                catch_response=True
            ) as update_response:
                
                if update_response.status_code != 200:
                    self._record_result(test_id, name, "FAIL", f"Expected 200, got {update_response.status_code}")
                    update_response.failure(f"Expected 200, got {update_response.status_code}")
                    return
                
                try:
                    data = update_response.json()
                    ack_status = data.get('message', {}).get('ack', {}).get('status')
                    
                    if ack_status == 'ACK':
                        self._record_result(test_id, name, "PASS", "Domain removed (3→2 domains)")
                        update_response.success()
                    else:
                        self._record_result(test_id, name, "FAIL", f"Unexpected ack: {ack_status}")
                        update_response.failure(f"Unexpected ack: {ack_status}")
                        
                except Exception as e:
                    self._record_result(test_id, name, "FAIL", f"Error: {str(e)}")
                    update_response.failure(str(e))


# ============================================================================
# Locust Task Configuration - Required by framework
# ============================================================================
tasks = [ONDCAdminDomainManagement]
