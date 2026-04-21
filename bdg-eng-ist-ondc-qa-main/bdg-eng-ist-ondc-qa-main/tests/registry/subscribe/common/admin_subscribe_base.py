"""
================================================================================
ADMIN SUBSCRIBE BASE CLASS
================================================================================
File: admin_subscribe_base.py
Class: AdminSubscribeBase

Base class specifically for Admin Comprehensive test scenarios.

USED BY:
  - ondc_admin_comprehensive.py (45 admin tests)
    YML: ondc_admin_comprehensive_tests.yml

PROVIDES:
  - Admin-specific operations
  - State transition workflows
  - Credential and contact management
  - YAML-driven test execution
  - Admin API authentication
================================================================================
"""
import json
import uuid
import base64
import yaml
import os
from datetime import datetime, timedelta
from locust import SequentialTaskSet
from common_test_foundation.lib.proxy.proxy_server import ProxyServer
from common_test_foundation.helpers.taskset_handler import RESCHEDULE_TASK, taskset_handler
from tests.utils.registry_auth_client import RegistryAuthClient
from tests.utils.ondc_auth_helper import ONDCAuthHelper

# For proper Ed25519 key generation
from nacl.signing import SigningKey
from nacl.encoding import Base64Encoder


@taskset_handler(RESCHEDULE_TASK)
class AdminSubscribeBase(SequentialTaskSet):
    """Base class for ONDC Admin Subscribe API tests with sequential execution"""
    
    # Configuration
    config_file = 'resources/registry/ondc_reg_subscribe_functional.yml'
    tenant_name = 'ondcRegistry'
    
    def on_start(self):
        """Initialize test data and configuration"""
        self.step_name = 'ON_START'
        self.proxy = ProxyServer()
        self.proxy.start_capture(trx_id=self.step_name)
        self.client.verify = self.proxy.get_certificate()
        self.client.proxies = self.proxy.get_http_proxy_config()
        
        # Load configuration
        config_file = getattr(self, 'config_file', 'resources/registry/ondc_reg_subscribe_functional.yml')
        tenant_name = getattr(self, 'tenant_name', 'ondcRegistry')
        
        config = self._load_config(config_file, tenant_name)
        self.config = config  # Store for _setup_test_participant
        
        # Load config
        self.host = config.get('host', 'http://localhost:8080')
        
        # Check if using fixed participant
        self.use_fixed_participant = config.get('use_fixed_participant', False)
        if self.use_fixed_participant:
            print(f"[ON_START] Using fixed participant: {config.get('participant_id')}")
        
        # Initialize Registry Auth Client for dynamic token generation
        admin_username = config.get('admin_username', '<admin-user>')
        admin_password = config.get('admin_password', 'admin')
        admin_token = config.get('admin_token', None)  # Static token (optional)
        admin_auth_url = config.get('admin_auth_url', None)  # External auth service URL (optional)
        
        # Pass proxy configuration to auth client so login goes through proxy
        self.auth_client = RegistryAuthClient(
            self.host, 
            admin_username, 
            admin_password,
            proxies=self.proxy.get_http_proxy_config(),
            verify=self.proxy.get_certificate(),
            static_token=admin_token,
            auth_url=admin_auth_url
        )
        
        if admin_token:
            print(f"[ON_START] Using static admin token (no login required)")
        elif admin_auth_url:
            print(f"[ON_START] Using external auth service: {admin_auth_url}")
        else:
            print(f"[ON_START] Admin auth client initialized (will auto-refresh tokens)")
        
        # Test data
        self.domains = config.get('domains', ['ONDC:RET10', 'ONDC:RET11', 'ONDC:RET12', 'ONDC:AGR10', 'ONDC:TRV10'])
        self.cities = config.get('cities', ['std:080', 'std:011', 'std:022', 'std:033', 'std:044'])
        self.np_types = config.get('np_types', ['seller', 'buyer', 'logistics'])
        
        # Initialize test context for state management between tasks
        self.test_context = {}
    
    def _setup_test_participant(self):
        """
        Generate fresh Ed25519 keypair and participant ID for a single test.
        If use_fixed_participant is enabled, returns the pre-configured participant.
        Each test should call this to get isolated credentials.
        
        Returns:
            dict: Contains participant_id, uk_id, private_key_seed, 
                  signing_public_key, encryption_public_key, valid_from, valid_until
        """
        # Check if using fixed participant from config
        if hasattr(self, 'use_fixed_participant') and self.use_fixed_participant:
            config = self.config
            if config.get('participant_id') and config.get('private_key_seed'):
                print(f"[_setup_test_participant] Using fixed participant: {config.get('participant_id')}")
                
                # Add timestamp validity (1 year from now)
                now = datetime.utcnow()
                future = now + timedelta(days=365)
                valid_from = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
                valid_until = future.strftime("%Y-%m-%dT%H:%M:%S.000Z")
                
                return {
                    'participant_id': config.get('participant_id'),
                    'subscriber_id': config.get('participant_id'),
                    'uk_id': config.get('uk_id', str(uuid.uuid4())),
                    'request_id': str(uuid.uuid4()),
                    'private_key_seed': config.get('private_key_seed'),
                    'signing_public_key': config.get('signing_public_key'),
                    'encryption_public_key': config.get('encryption_public_key'),
                    'valid_from': valid_from,
                    'valid_until': valid_until
                }
        
        # Generate fresh Ed25519 keypair
        signing_key = SigningKey.generate()
        signing_key_bytes = bytes(signing_key)  # 32-byte seed
        
        # Generate unique IDs
        session_suffix = str(uuid.uuid4())[:6]
        participant_id = f"ctf-admin-{session_suffix}.participant.ondc"
        uk_id = str(uuid.uuid4())
        
        # Add timestamp validity (1 year from now)
        now = datetime.utcnow()
        future = now + timedelta(days=365)
        valid_from = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        valid_until = future.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        return {
            'participant_id': participant_id,
            'subscriber_id': participant_id,  # Same as participant_id for self-registration scenarios
            'uk_id': uk_id,
            'request_id': str(uuid.uuid4()),
            'private_key_seed': signing_key_bytes.hex(),
            'signing_public_key': signing_key.verify_key.encode(encoder=Base64Encoder).decode('utf-8'),
            'encryption_public_key': base64.b64encode(os.urandom(32)).decode('utf-8'),
            'valid_from': valid_from,
            'valid_until': valid_until
        }
    
    def _load_config(self, config_file, tenant_name):
        """Load tenant configuration from YAML file"""
        config = {}
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                yaml_content = yaml.safe_load(f)
                config = yaml_content.get(tenant_name, {})
                print(f"[ON_START] Loaded config from {config_file}")
        else:
            print(f"[ON_START] WARNING: Config file not found: {config_file}")
        return config
    
    def _generate_admin_headers(self):
        """Generate headers for admin API calls with fresh token"""
        # Always get fresh token (auto-refreshes if expired)
        return {
            'Authorization': f'Bearer {self.auth_client.get_token()}',
            'Content-Type': 'application/json'
        }
    
    def _send_admin_subscribe_request(self, step_name, payload, expected_status=[200], auth_type='admin'):
        """
        Send admin subscribe request (POST /admin/subscribe)
        
        Args:
            auth_type: 'admin' (default) or 'none' (no auth header)
        
        Returns:
            tuple: (success, data, status_code, response)
        """
        if auth_type == 'none':
            headers = {'Content-Type': 'application/json'}
        else:
            headers = self._generate_admin_headers()
        
        with self.client.post(
            name=step_name,
            url="/admin/subscribe",
            json=payload,
            headers=headers,
            catch_response=True
        ) as response:
            status_code = response.status_code
            
            if status_code in expected_status:
                try:
                    data = response.json()
                    response.success()
                    return True, data, status_code, response
                except Exception as e:
                    error_msg = f"Error parsing response: {e}"
                    print(f"[{step_name}] {error_msg}")
                    response.failure(error_msg)
                    return False, None, status_code, response
            else:
                try:
                    error_data = response.json()
                    error_msg = f"Expected {expected_status}, got {status_code}: {error_data}"
                    print(f"[{step_name}] {error_msg}")
                    response.failure(error_msg)
                    return False, error_data, status_code, response
                except:
                    error_msg = f"Expected {expected_status}, got {status_code}: {response.text[:200]}"
                    print(f"[{step_name}] {error_msg}")
                    response.failure(error_msg)
                    return False, None, status_code, response
    
    def _send_admin_patch_request(self, step_name, payload, expected_status=[200]):
        """
        Send admin patch request (PATCH /admin/subscribe)
        
        Returns:
            tuple: (success, data, status_code, response)
        """
        headers = self._generate_admin_headers()
        
        with self.client.patch(
            name=step_name,
            url="/admin/subscribe",
            json=payload,
            headers=headers,
            catch_response=True
        ) as response:
            status_code = response.status_code
            
            if status_code in expected_status:
                try:
                    data = response.json()
                    response.success()
                    return True, data, status_code, response
                except Exception as e:
                    error_msg = f"Error parsing response: {e}"
                    print(f"[{step_name}] {error_msg}")
                    response.failure(error_msg)
                    return False, None, status_code, response
            else:
                try:
                    error_data = response.json()
                    error_msg = f"Expected {expected_status}, got {status_code}: {error_data}"
                    print(f"[{step_name}] {error_msg}")
                    response.failure(error_msg)
                    return False, error_data, status_code, response
                except:
                    error_msg = f"Expected {expected_status}, got {status_code}: {response.text[:200]}"
                    print(f"[{step_name}] {error_msg}")
                    response.failure(error_msg)
                    return False, None, status_code, response
    
    def _send_admin_delete_request(self, step_name, endpoint, expected_status=[200, 204]):
        """
        Send admin delete request (DELETE /admin/configs/{config_id})
        
        Args:
            step_name: Name of the step for tracking
            endpoint: Full endpoint path (e.g., '/admin/configs/config-123')
            expected_status: List of expected HTTP status codes
        
        Returns:
            tuple: (success, data, status_code, response)
        """
        headers = self._generate_admin_headers()
        
        with self.client.delete(
            name=step_name,
            url=endpoint,
            headers=headers,
            catch_response=True
        ) as response:
            status_code = response.status_code
            
            if status_code in expected_status:
                # Success case - may or may not have response body
                try:
                    data = response.json() if response.text else {}
                    response.success()
                    return True, data, status_code, response
                except Exception as e:
                    # No JSON body is OK for DELETE (e.g., 204 No Content)
                    response.success()
                    return True, {}, status_code, response
            else:
                # Failure case
                try:
                    error_data = response.json()
                    error_msg = f"Expected {expected_status}, got {status_code}: {error_data}"
                    print(f"[{step_name}] {error_msg}")
                    response.failure(error_msg)
                    return False, error_data, status_code, response
                except:
                    error_msg = f"Expected {expected_status}, got {status_code}: {response.text[:200]}"
                    print(f"[{step_name}] {error_msg}")
                    response.failure(error_msg)
                    return False, None, status_code, response
    
    def _send_lookup_request(self, step_name, participant_id, credentials, expected_status=[200]):
        """
        Send V3 lookup request to fetch participant details (including config_ids)
        Uses ONDC V3 lookup API with ED25519 signing
        
        Args:
            step_name: Name of the step for tracking
            participant_id: Participant ID to lookup
            credentials: Dict with 'participant_id', 'uk_id', 'private_key_seed'
            expected_status: List of expected HTTP status codes
        
        Returns:
            tuple: (success, data, status_code, response)
                   where data contains the participant info with configs array
        """
        # Generate lookup payload
        payload = {
            "country": "IND",
            "type": "BPP",
            "subscriber_id": participant_id  # V3 uses subscriber_id to query
        }
        
        try:
            # Initialize ONDC auth helper for V3 signing
            private_key_bytes = bytes.fromhex(credentials['private_key_seed'])
            auth_helper = ONDCAuthHelper(
                credentials['participant_id'],
                credentials['uk_id'],
                private_key_bytes
            )
            
            # Generate signed headers
            headers = auth_helper.generate_headers(payload)
            
            # Extract pre-serialized body (important for signature validation)
            serialized_body = headers.pop('serialized_body', None)
            if not serialized_body:
                serialized_body = json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
            
            # Send lookup request
            with self.client.post(
                name=step_name,
                url="/v3.0/lookup",
                data=serialized_body,
                headers=headers,
                catch_response=True
            ) as response:
                status_code = response.status_code
                
                if status_code in expected_status:
                    try:
                        data = response.json()
                        response.success()
                        return True, data, status_code, response
                    except Exception as e:
                        error_msg = f"Error parsing lookup response: {e}"
                        print(f"[{step_name}] {error_msg}")
                        response.failure(error_msg)
                        return False, None, status_code, response
                else:
                    try:
                        error_data = response.json()
                        error_msg = f"Expected {expected_status}, got {status_code}: {error_data}"
                        print(f"[{step_name}] {error_msg}")
                        response.failure(error_msg)
                        return False, error_data, status_code, response
                    except:
                        error_msg = f"Expected {expected_status}, got {status_code}: {response.text[:200]}"
                        print(f"[{step_name}] {error_msg}")
                        response.failure(error_msg)
                        return False, None, status_code, response
        
        except Exception as e:
            error_msg = f"Lookup request failed: {e}"
            print(f"[{step_name}] {error_msg}")
            return False, None, 0, None
    
    def on_stop(self):
        """Cleanup after test run"""
        self.step_name = 'ON_STOP'
        if hasattr(self, 'proxy') and self.proxy:
            self.proxy.stop_capture()
