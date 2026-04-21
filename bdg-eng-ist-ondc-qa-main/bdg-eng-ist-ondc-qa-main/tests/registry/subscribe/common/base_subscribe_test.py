"""
================================================================================
REGISTRY SUBSCRIBE BASE CLASS (SHARED)
================================================================================
File: registry_subscribe_base.py
Class: RegistrySubscribeBase

Shared base class for multiple Registry Subscribe API test suites.

USED BY:
  - ondc_reg_subscribe_functional.py (TC-01 to TC-23)
  - ondc_reg_subscribe_negative.py (TC-028 to TC-067)
  - ondc_reg_subscribe_performance.py (Performance tests)
  - ondc_reg_v3_comprehensive.py (26 V3 tests)

PROVIDES:
  - JWT Bearer token authentication
  - ED25519 signature generation for V3 API
  - Admin and V3 API request methods
  - Payload generators and helpers
  - Key management and cryptography
================================================================================
"""
import json
import uuid
import base64
import yaml
import os
from datetime import datetime
from locust import SequentialTaskSet
from common_test_foundation.lib.proxy.proxy_server import ProxyServer
from common_test_foundation.helpers.taskset_handler import RESCHEDULE_TASK, taskset_handler
from tests.utils.ondc_auth_helper import ONDCAuthHelper
from tests.utils.registry_auth_client import RegistryAuthClient

# For proper Ed25519 key generation
from nacl.signing import SigningKey
from nacl.encoding import Base64Encoder


@taskset_handler(RESCHEDULE_TASK)
class RegistrySubscribeBase(SequentialTaskSet):
    """Base class for ONDC Registry Subscribe API tests with sequential execution"""
    
    # Configuration
    config_file = 'resources/registry/ondc_reg_subscribe_functional.yml'
    tenant_name = 'ondcRegistry'
    
    def on_start(self):
        """Initialize test data and configuration with fresh Ed25519 keypair"""
        self.step_name = 'ON_START'
        self.proxy = ProxyServer()
        self.proxy.start_capture(trx_id=self.step_name)
        self.client.verify = self.proxy.get_certificate()
        self.client.proxies = self.proxy.get_http_proxy_config()
        
        # Load configuration
        config_file = getattr(self, 'config_file', 'resources/registry/ondc_reg_subscribe_functional.yml')
        tenant_name = getattr(self, 'tenant_name', 'ondcRegistry')
        
        config = self._load_config(config_file, tenant_name)
        
        # Load config
        self.host = config.get('host', 'http://localhost:8080')
        
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
        
        # ========================================
        # PARTICIPANT CREDENTIALS SETUP
        # ========================================
        # Check if we should use pre-registered participant or generate fresh keys
        use_fixed_participant = config.get('use_fixed_participant', False)
        self.use_fixed_participant = use_fixed_participant  # Store for use in _setup_test_participant
        
        if use_fixed_participant and config.get('participant_id') and config.get('private_key_seed'):
            # Use pre-registered participant from config (for UAT with DNS validation)
            print(f"[ON_START] Using pre-registered participant from config")
            self.participant_id = config.get('participant_id')
            self.uk_id = config.get('uk_id')
            self.private_key_seed = config.get('private_key_seed')
            self.signing_public_key = config.get('signing_public_key')
            self.encryption_public_key = config.get('encryption_public_key')
            
            print(f"[ON_START] Participant ID: {self.participant_id}")
            print(f"[ON_START] UK ID: {self.uk_id}")
            print(f"[ON_START] Using fixed credentials (DNS validation enabled)")
        else:
            # Generate fresh ED25519 keypair for this test run
            # This ensures each test iteration gets a unique participant
            # matching test-suite-v2's approach
            signing_key = SigningKey.generate()
            
            # Get the 32-byte seed (not the 64-byte expanded key)
            # SigningKey stores the seed in _seed attribute OR we can export/import
            signing_key_bytes = bytes(signing_key)  # This gives us the 32-byte seed!
            self.private_key_seed = signing_key_bytes.hex()
            self.signing_public_key = signing_key.verify_key.encode(encoder=Base64Encoder).decode('utf-8')
            
            # Generate X25519 encryption key (simplified - using random bytes)
            # In production, derive from Ed25519 key or generate proper X25519 keypair
            self.encryption_public_key = base64.b64encode(os.urandom(32)).decode('utf-8')
            
            # Generate unique IDs for this test run
            session_suffix = str(uuid.uuid4())[:6]
            self.participant_id = f"ctf-test-{session_suffix}.participant.ondc"
            self.uk_id = str(uuid.uuid4())
            
            print(f"[ON_START] Generated fresh Ed25519 keypair")
            print(f"[ON_START] Participant ID: {self.participant_id}")
            print(f"[ON_START] UK ID: {self.uk_id}")
            print(f"[ON_START] Public key (first 50 chars): {self.signing_public_key[:50]}...")
        
        # Test data
        self.domains = config.get('domains', ['ONDC:RET10', 'ONDC:RET11', 'ONDC:RET12', 'ONDC:AGR10', 'ONDC:TRV10'])
        self.cities = config.get('cities', ['std:080', 'std:011', 'std:022', 'std:033', 'std:044'])
        self.np_types = config.get('np_types', ['seller', 'buyer', 'logistics'])
        
        # Initialize test context for state management between tasks
        self.test_context = {}
    
    def _setup_test_participant(self, auto_cleanup=False):
        """
        Generate fresh Ed25519 keypair and participant ID for a single test.
        Each test should call this to get isolated credentials.
        
        If use_fixed_participant is enabled, returns the pre-configured participant.
        
        Args:
            auto_cleanup: If True, deletes participant if it already exists (default: False)
        
        Returns:
            dict: Contains participant_id, uk_id, private_key_seed, 
                  signing_public_key, encryption_public_key
        """
        print(f"[DEBUG-MODULE-LOAD] _setup_test_participant called with auto_cleanup={auto_cleanup}")
        print(f"[DEBUG-MODULE-LOAD] This should ONLY appear if new code is loaded!")
        
        # Check if we should use pre-registered participant
        if hasattr(self, 'use_fixed_participant') and self.use_fixed_participant:
            # Return the pre-registered participant credentials
            return {
                'participant_id': self.participant_id,
                'uk_id': self.uk_id,
                'private_key_seed': self.private_key_seed,
                'signing_public_key': self.signing_public_key,
                'encryption_public_key': self.encryption_public_key
            }
        
        # Generate fresh Ed25519 keypair
        signing_key = SigningKey.generate()
        signing_key_bytes = bytes(signing_key)  # 32-byte seed
        
        # Generate unique IDs with timestamp to reduce collision probability
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        session_suffix = str(uuid.uuid4())[:8]
        participant_id = f"test-qa-{timestamp}-{session_suffix}.participant.ondc"
        uk_id = str(uuid.uuid4())
        
        # Optional: Cleanup if participant already exists
        if auto_cleanup:
            self._cleanup_participant_if_exists(participant_id)
        
        return {
            'participant_id': participant_id,
            'uk_id': uk_id,
            'private_key_seed': signing_key_bytes.hex(),
            'signing_public_key': signing_key.verify_key.encode(encoder=Base64Encoder).decode('utf-8'),
            'encryption_public_key': base64.b64encode(os.urandom(32)).decode('utf-8')
        }
    
    def _cleanup_participant_if_exists(self, participant_id):
        """
        Delete a participant via admin API if it already exists.
        This prevents "Participant already exists" (ERR_301) errors.
        
        Args:
            participant_id: The participant ID to delete
        
        Returns:
            bool: True if deleted or doesn't exist, False on error
        """
        try:
            headers = self._generate_admin_headers()
            
            # Try to delete the participant
            with self.client.delete(
                name=f"Cleanup_{participant_id}",
                url=f"/admin/subscribe/{participant_id}",
                headers=headers,
                catch_response=True
            ) as response:
                if response.status_code == 200:
                    print(f"[CLEANUP] Deleted existing participant: {participant_id}")
                    response.success()
                    return True
                elif response.status_code == 404:
                    print(f"[CLEANUP] Participant not found (OK): {participant_id}")
                    response.success()
                    return True
                else:
                    print(f"[CLEANUP] Delete failed (status {response.status_code}), will retry creation: {participant_id}")
                    response.success()  # Don't fail cleanup, test will proceed
                    return False
        except Exception as e:
            print(f"[CLEANUP] Exception during cleanup (will ignore): {e}")
            return False
    
    def _delete_test_participant(self, participant_id):
        """
        Delete a test participant via admin API.
        
        Args:
            participant_id: The participant ID to delete
        
        Returns:
            tuple: (success: bool, status_code: int)
        """
        try:
            headers = self._generate_admin_headers()
            
            with self.client.delete(
                name=f"Delete_{participant_id}",
                url=f"/admin/subscribe/{participant_id}",
                headers=headers,
                catch_response=True
            ) as response:
                if response.status_code in [200, 404]:
                    response.success()
                    return True, response.status_code
                else:
                    response.failure(f"Delete failed: {response.status_code}")
                    return False, response.status_code
        except Exception as e:
            print(f"[DELETE] Exception: {e}")
            return False, 0
    
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
    
    def _generate_v3_headers(self, payload, signature_mode='normal'):
        """Generate headers with ED25519 signature for V3 API calls
        
        Args:
            payload: Request payload
            signature_mode: 'normal' (default), 'none' (no signature), 'invalid' (bad signature)
        """
        try:
            from tests.utils.ondc_auth_helper import ONDCAuthHelper
            
            # Handle special signature modes for negative testing
            if signature_mode == 'none':
                print("[DEBUG V3 Headers] Generating headers WITHOUT signature (negative test)")
                import json
                serialized_body = json.dumps(payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False)
                return {
                    'Content-Type': 'application/json',
                    'serialized_body': serialized_body
                }
            
            if signature_mode == 'invalid':
                print("[DEBUG V3 Headers] Generating headers with INVALID signature (negative test)")
                import json
                serialized_body = json.dumps(payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False)
                participant_id = payload.get('participant_id', self.participant_id)
                uk_id = payload.get('uk_id') or payload.get('key', {}).get('uk_id') or self.uk_id
                return {
                    'Content-Type': 'application/json',
                    'Authorization': f'Signature keyId="{participant_id}|{uk_id}|ed25519",algorithm="ed25519",created="9999999999",expires="9999999999",headers="(created) (expires) digest",signature="INVALID_SIGNATURE_BASE64_STRING_AAABBBCCCDDDEEEFFF"',
                    'Digest': 'BLAKE-512=INVALID_DIGEST_HASH_VALUE',
                    'serialized_body': serialized_body
                }
            
            # Normal signature mode
            if self.private_key_seed:
                # Debug: Check key format
                print(f"[DEBUG V3 Headers] private_key_seed length: {len(self.private_key_seed)} chars")
                print(f"[DEBUG V3 Headers] private_key_seed (first 20 chars): {self.private_key_seed[:20]}...")
                
                private_key_bytes = bytes.fromhex(self.private_key_seed) if isinstance(self.private_key_seed, str) else self.private_key_seed
                print(f"[DEBUG V3 Headers] private_key_bytes length: {len(private_key_bytes)} bytes")
                
                # Use participant_id and uk_id from payload (for V3, these must match configured keys)
                participant_id = payload.get('participant_id', self.participant_id)
                uk_id = payload.get('uk_id') or payload.get('key', {}).get('uk_id') or self.uk_id
                print(f"[DEBUG V3 Headers] Signing for participant_id={participant_id}, uk_id={uk_id}")
                
                auth_helper = ONDCAuthHelper(participant_id, uk_id, private_key_bytes)
                return auth_helper.generate_headers(payload)
            else:
                print("[ERROR V3 Headers] No private_key_seed available!")
                # Fallback to basic headers if no key configured
                return {
                    'Content-Type': 'application/json',
                    'Authorization': f'Signature keyId="{self.participant_id}|{self.uk_id}|ed25519",algorithm="ed25519",created="1234567890",expires="1234567899",headers="(created) (expires) digest",signature="dummy"',
                    'Digest': 'BLAKE-512=dummy'
                }
        except Exception as e:
            print(f"[ERROR V3 Headers] Error generating V3 headers: {e}")
            import traceback
            traceback.print_exc()
            return {
                'Content-Type': 'application/json'
            }
    
    def _generate_test_payload(self, np_type='seller', domain='ONDC:RET10', action='WHITELISTED', additional_data=None, use_v3_keys=False):
        """Generate a test subscribe payload for Registry 3.0
        
        Args:
            np_type: Participant type (BPP=seller, BAP=buyer, GATEWAY=logistics)
            domain: ONDC domain (ONDC:RET10, ONDC:LOG10, etc.)
            action: Action for admin API (WHITELISTED, SUBSCRIBED, etc.)
            additional_data: Optional dict of additional business metadata
            use_v3_keys: If True, use configured participant_id and keys (required for V3 API signature)
                        Note: V3 API validates signature against participant_id, so all V3 tests must use same ID
        """
        participant_suffix = str(uuid.uuid4())[:6]
        
        # For V3 API calls: Use configured keys (signature validation requires matching participant_id)
        if use_v3_keys and self.participant_id and self.uk_id:
            participant_id = self.participant_id  # MUST use configured ID for signature to work
            uk_id = self.uk_id
            signing_key = self.signing_public_key
            encryption_key = self.encryption_public_key
            print(f"[DEBUG] Using V3 keys: participant_id={participant_id}, uk_id={uk_id}")
        else:
            # For Admin API calls: Generate random IDs (Admin doesn't validate signatures)
            participant_id = f"{np_type}-{participant_suffix}.participant.ondc"
            uk_id = str(uuid.uuid4())
            signing_key = base64.b64encode(os.urandom(32)).decode('utf-8')
            encryption_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        
        # Generate IDs for references
        cred_id = f"cred_{participant_suffix}_001"
        contact_id = f"contact_{participant_suffix}_001"
        uri_id = f"uri_{participant_suffix}_001"
        location_id = f"loc_{participant_suffix}_001"
        
        # Map np_type to proper Registry 3.0 values
        np_type_map = {
            'seller': 'BPP',
            'buyer': 'BAP',
            'logistics': 'GATEWAY',
            'BPP': 'BPP',
            'BAP': 'BAP',
            'GATEWAY': 'GATEWAY'
        }
        normalized_np_type = np_type_map.get(np_type, 'BPP')
        
        # Registry 3.0 Schema - Note singular fields (key, uri, location) and renamed configs
        payload = {
            "participant_id": participant_id,
            "credentials": [
                {
                    "cred_id": cred_id,
                    "type": "GST",  # V3: changed from cred_type to type
                    "cred_data": {
                        "pan": "ABCDE1234F",
                        "gstin": "22ABCDE1234F1Z5",
                        "business_name": "Test Business Ltd"
                    }
                }
            ],
            "contacts": [
                {
                    "contact_id": contact_id,
                    "type": "TECHNICAL",  # V3: Field name changed from contact_type to type, value stays TECHNICAL
                    "name": "John Doe",
                    "email": f"tech-{participant_suffix}@example.com",
                    "phone": "+919876543210",
                    "address": "123 Tech Street, Bangalore",
                    "designation": "Technical Lead",
                    "is_primary": True
                }
            ],
            "key": {
                "uk_id": uk_id,
                "signing_public_key": signing_key,
                "encryption_public_key": encryption_key,
                "signed_algorithm": "ED25519",
                "encryption_algorithm": "X25519",
                "valid_from": "2024-01-01T00:00:00.000Z",
                "valid_until": "2026-12-31T23:59:59.000Z"
            },
            "configs": [  # Admin API V3: uses 'configs' (not network_participant, uris, locations)
                {
                    "domain": domain,
                    "np_type": normalized_np_type,
                    "subscriber_id": participant_id
                }
            ]
        }
        
        # Store location/uri data for later use (not sent to Admin API)
        payload['_meta'] = {
            'location': {
                "location_id": location_id,
                "country": "IND",
                "city": ["std:080"],
                "type": "SERVICEABLE"
            },
            'uri': {
                "uri_id": uri_id,
                "type": "CALLBACK",
                "url": f"https://{participant_id}/ondc"
            }
        }
        
        # Add additional_data if provided
        if additional_data:
            payload["additional_data"] = additional_data
        
        # V3: SUBSCRIBED status requires PAN credential, AUTHORISED_SIGNATORY, and BUSINESS contacts
        if action == 'SUBSCRIBED':
            pan_cred_id = f"cred_{participant_suffix}_002_pan"
            payload['credentials'].append({
                "cred_id": pan_cred_id,
                "type": "PAN",
                "cred_data": {
                    "pan": "ABCDE1234F",
                    "name": "Test Business Owner"
                }
            })
            
            # Add AUTHORISED_SIGNATORY contact
            auth_contact_id = f"contact_{participant_suffix}_002_auth"
            payload['contacts'].append({
                "contact_id": auth_contact_id,
                "type": "AUTHORISED_SIGNATORY",
                "name": "Authorized Signatory",
                "email": f"auth-{participant_suffix}@example.com",
                "phone": "+919876543211",
                "designation": "Authorized Signatory",
                "is_primary": False
            })
            
            # Add BUSINESS contact (required for SUBSCRIBED)
            business_contact_id = f"contact_{participant_suffix}_003_business"
            payload['contacts'].append({
                "contact_id": business_contact_id,
                "type": "BUSINESS",
                "name": "Business Manager",
                "email": f"business-{participant_suffix}@example.com",
                "phone": "+919876543212",
                "designation": "Business Head",
                "is_primary": False
            })
        
        # Always include action for Admin API (V3 sender will remove it)
        payload["action"] = action
        
        # Add DNS skip and SSL verification skip for UAT testing
        payload["dns_skip"] = True
        payload["skip_ssl_verification"] = True
        
        return payload
    
    def _ensure_subscribed_requirements(self, credentials, contacts):
        """
        Ensure credentials and contacts meet SUBSCRIBED status requirements.
        
        SUBSCRIBED status requires:
        - PAN credential
        - AUTHORISED_SIGNATORY contact
        - BUSINESS contact
        
        Args:
            credentials: List of credential objects
            contacts: List of contact objects
            
        Returns:
            tuple: (credentials_list, contacts_list) with required items added if missing
        """
        # Deep copy to avoid modifying original
        import copy
        creds = copy.deepcopy(credentials)
        conts = copy.deepcopy(contacts)
        
        # Ensure PAN credential exists
        has_pan = any(c.get('type') == 'PAN' for c in creds)
        if not has_pan:
            participant_suffix = str(uuid.uuid4())[:6]
            creds.append({
                "cred_id": f"cred_pan_{participant_suffix}",
                "type": "PAN",
                "cred_data": {
                    "pan": "ABCDE1234F",
                    "name": "Test Business Owner"
                }
            })
            print(f"[DEBUG] Added required PAN credential for SUBSCRIBED status")
        
        # Ensure AUTHORISED_SIGNATORY contact exists
        has_auth_signatory = any(c.get('type') == 'AUTHORISED_SIGNATORY' for c in conts)
        if not has_auth_signatory:
            participant_suffix = str(uuid.uuid4())[:6]
            conts.append({
                "contact_id": f"contact_auth_{participant_suffix}",
                "type": "AUTHORISED_SIGNATORY",
                "name": "Authorized Signatory",
                "email": f"auth-{participant_suffix}@example.com",
                "phone": "+919876543211",
                "designation": "Authorized Signatory",
                "is_primary": False
            })
            print(f"[DEBUG] Added required AUTHORISED_SIGNATORY contact for SUBSCRIBED status")
        
        # Ensure BUSINESS contact exists
        has_business = any(c.get('type') == 'BUSINESS' for c in conts)
        if not has_business:
            participant_suffix = str(uuid.uuid4())[:6]
            conts.append({
                "contact_id": f"contact_business_{participant_suffix}",
                "type": "BUSINESS",
                "name": "Business Manager",
                "email": f"business-{participant_suffix}@example.com",
                "phone": "+919876543212",
                "designation": "Business Head",
                "is_primary": False
            })
            print(f"[DEBUG] Added required BUSINESS contact for SUBSCRIBED status")
        
        return creds, conts
    
    def _create_whitelisted_and_subscribe(self, step_name, np_type='seller', domain='ONDC:RET10', participant_keys=None):
        """
        Correctly implement the WHITELISTED → SUBSCRIBED workflow.
        
        Generates fresh Ed25519 keypair for each test to ensure isolation.
        This matches the test-suite-v2 pattern:
        1. Admin creates WHITELISTED participant with unique ID
        2. Participant uses V3 self-subscribe to move to SUBSCRIBED  
        
        Args:
            step_name: Test step name for logging
            np_type: Participant type (seller, buyer, logistics)
            domain: ONDC domain
            participant_keys: Optional dict with pre-generated keys. If None, generates fresh keys.
            
        Returns:
            tuple: (success: bool, participant_data: dict, subscribed_response: Response)
            participant_data contains: participant_id, uk_id, signing_public_key, etc.
        """
        
        # Generate fresh keys for THIS test to avoid conflicts
        if participant_keys is None:
            participant_keys = self._setup_test_participant(auto_cleanup=True)
            print(f"[{step_name}] Generated fresh keypair: {participant_keys['participant_id']}")
        
        # Temporarily override instance variables for this workflow
        # (methods like _generate_v3_headers need these)
        orig_participant_id = self.participant_id
        orig_uk_id = self.uk_id
        orig_private_key_seed = self.private_key_seed
        orig_signing_public_key = self.signing_public_key
        orig_encryption_public_key = self.encryption_public_key
        
        # Override with fresh keys
        self.participant_id = participant_keys['participant_id']
        self.uk_id = participant_keys['uk_id']
        self.private_key_seed = participant_keys['private_key_seed']
        self.signing_public_key = participant_keys['signing_public_key']
        self.encryption_public_key = participant_keys['encryption_public_key']
        
        # Step 1: Admin creates WHITELISTED participant
        whitelisted_payload = self._generate_test_payload(
            np_type=np_type, 
            domain=domain, 
            action='WHITELISTED',
            use_v3_keys=True  # Now uses the fresh keys we just set
        )
        
        success, data, status, response = self._send_admin_subscribe_request(
            f"{step_name}_CreateWhitelisted", 
            whitelisted_payload, 
            expected_status=[200]  # Expect success with fresh participant
        )
        
        if not success:
            print(f"[{step_name}] Failed to create WHITELISTED participant")
            # Restore original values before returning
            self.participant_id = orig_participant_id
            self.uk_id = orig_uk_id
            self.private_key_seed = orig_private_key_seed
            self.signing_public_key = orig_signing_public_key
            self.encryption_public_key = orig_encryption_public_key
            return False, None, response
        
        # Extract participant details for V3 call
        participant_id = whitelisted_payload['participant_id']
        uk_id = whitelisted_payload['key']['uk_id']
        
        print(f"[{step_name}] [OK] Created WHITELISTED participant: {participant_id}")
        
        # Step 2: V3 self-subscribe to SUBSCRIBED
        # This payload must have ALL required fields for SUBSCRIBED status
        subscribe_payload = {
            "request_id": str(uuid.uuid4()),
            "uk_id": uk_id,
            "participant_id": participant_id,
            "credentials": [
                {
                    "cred_id": f"cred_gst_{str(uuid.uuid4())[:6]}",
                    "type": "GST",
                    "cred_data": {
                        "gstin": "29ABCDE1234F1Z5",
                        "legal_name": "Test Company Private Limited"
                    }
                },
                {
                    "cred_id": f"cred_pan_{str(uuid.uuid4())[:6]}",
                    "type": "PAN",
                    "cred_data": {
                        "pan_no": "ABCDE1234F"
                    }
                }
            ],
            "contacts": [
                {
                    "contact_id": f"contact_auth_{str(uuid.uuid4())[:6]}",
                    "type": "AUTHORISED_SIGNATORY",
                    "name": "Authorized Signatory",
                    "email": f"auth-{str(uuid.uuid4())[:6]}@example.com",
                    "phone": "+919876543210",
                    "designation": "Authorized Signatory",
                    "is_primary": False
                },
                {
                    "contact_id": f"contact_business_{str(uuid.uuid4())[:6]}",
                    "type": "BUSINESS",
                    "name": "Business Manager",
                    "email": f"business-{str(uuid.uuid4())[:6]}@example.com",
                    "phone": "+919876543211",
                    "designation": "Business Head",
                    "is_primary": False
                }
            ],
            "key": {
                "uk_id": uk_id,
                "signing_public_key": whitelisted_payload['key']['signing_public_key'],
                "encryption_public_key": whitelisted_payload['key']['encryption_public_key'],
                "signed_algorithm": "ED25519",
                "encryption_algorithm": "X25519",
                "valid_from": whitelisted_payload['key']['valid_from'],
                "valid_until": whitelisted_payload['key']['valid_until']
            },
            "location": whitelisted_payload.get('_meta', {}).get('location', {
                "location_id": "loc001",
                "country": "IND",
                "city": ["std:080"],
                "type": "SERVICEABLE"
            }),
            "uri": whitelisted_payload.get('_meta', {}).get('uri', {
                "uri_id": "uri001",
                "type": "CALLBACK",
                "url": f"https://{participant_id}/ondc"
            }),
            "configs": [{
                "domain": domain,
                "np_type": whitelisted_payload.get('configs', [{}])[0].get('np_type', 'BPP'),
                "subscriber_id": participant_id,
                "location_id": whitelisted_payload.get('_meta', {}).get('location', {}).get('location_id', 'loc001'),
                "uri_id": whitelisted_payload.get('_meta', {}).get('uri', {}).get('uri_id', 'uri001'),
                "key_id": uk_id
            }],
            "dns_skip": True,
            "skip_ssl_verification": True
        }
        
        success, data, status, response = self._send_v3_subscribe_request(
            f"{step_name}_V3Subscribe",
            subscribe_payload,
            expected_status=[200]
        )
        
        if not success:
            print(f"[{step_name}] Failed V3 self-subscribe to SUBSCRIBED")
            # Restore original values before returning
            self.participant_id = orig_participant_id
            self.uk_id = orig_uk_id
            self.private_key_seed = orig_private_key_seed
            self.signing_public_key = orig_signing_public_key
            self.encryption_public_key = orig_encryption_public_key
            return False, None, response
        
        # Return participant details for subsequent V3 operations
        participant_data = {
            'participant_id': participant_id,
            'subscriber_id': participant_id,  # Same as participant_id for self-registration scenarios
            'uk_id': uk_id,
            'request_id': subscribe_payload['request_id'],  # Include request_id from subscribe payload
            'private_key_seed': participant_keys['private_key_seed'],  # Include for PATCH operations
            'signing_public_key': whitelisted_payload['key']['signing_public_key'],
            'encryption_public_key': whitelisted_payload['key']['encryption_public_key'],
            'valid_from': whitelisted_payload['key']['valid_from'],  # Include timestamp fields
            'valid_until': whitelisted_payload['key']['valid_until'],  # Include timestamp fields
            'credentials': subscribe_payload['credentials'],
            'contacts': subscribe_payload['contacts'],
            'locations': [subscribe_payload['location']],  # Store as array for compatibility
            'uris': [subscribe_payload['uri']],  # Store as array for compatibility
            'configs': subscribe_payload['configs']
        }
        
        print(f"[{step_name}] SUCCESS: WHITELISTED → SUBSCRIBED workflow completed")
        
        # Restore original values
        self.participant_id = orig_participant_id
        self.uk_id = orig_uk_id
        self.private_key_seed = orig_private_key_seed
        self.signing_public_key = orig_signing_public_key
        self.encryption_public_key = orig_encryption_public_key
        
        return True, participant_data, response
    
    def _send_admin_subscribe_request(self, step_name, payload, expected_status=[200]):
        """Send admin subscribe request
        
        Returns:
            tuple: (success: bool, data: dict, status_code: int, response: Response)
        """
        # Clean up internal metadata before sending
        clean_payload = {k: v for k, v in payload.items() if k != '_meta'}
        
        headers = self._generate_admin_headers()
        
        with self.client.post(
            name=step_name,
            url="/admin/subscribe",
            json=clean_payload,
            headers=headers,
            catch_response=True
        ) as response:
            
            if response.status_code not in expected_status:
                error_msg = f"{step_name} Failed: Expected {expected_status}, got {response.status_code}"
                # Log response body for debugging 500 errors
                try:
                    error_data = response.json()
                    print(f"[{step_name}] Error response: {error_data}")
                    error_msg += f" - {error_data.get('error', {}).get('message', 'Unknown error')}"
                except:
                    print(f"[{step_name}] Error response text: {response.text[:500]}")
                    error_msg += f" - {response.text[:200]}"
                response.failure(error_msg)
                return False, None, response.status_code, response
            
            try:
                data = response.json()
                # Don't mark as success yet - let caller validate business logic
                return True, data, response.status_code, response
            except Exception as e:
                response.failure(f"{step_name} Failed: Error parsing response: {str(e)}")
                return False, None, response.status_code, response
    
    def _send_v3_subscribe_request(self, step_name, payload, expected_status=[200], signature_mode='normal'):
        """Send V3 subscribe request with signature
        
        Args:
            step_name: Name for tracking request
            payload: Request payload
            expected_status: List of acceptable status codes
            signature_mode: 'normal' (default), 'none' (no signature), 'invalid' (bad signature)
        
        Returns:
            tuple: (success: bool, data: dict, status_code: int, response: Response)
        """
        # Transform payload for V3 API format
        # Remove action field (Admin API only)
        payload.pop('action', None)
        
        # Add uk_id at root level (required for V3 API, taken from key object)
        if 'key' in payload and 'uk_id' in payload['key']:
            payload['uk_id'] = payload['key']['uk_id']
        
        # Add request_id if not present (required for V3 API)
        if 'request_id' not in payload:
            payload['request_id'] = str(uuid.uuid4())
        
        # DEBUG: Log configs to see what's being sent
        if 'configs' in payload:
            print(f"[DEBUG {step_name}] Sending configs: {payload['configs']}")
        
        headers = self._generate_v3_headers(payload, signature_mode=signature_mode)
        
        # CRITICAL: Use pre-serialized JSON body to ensure digest matches
        # Extract the serialized body from headers (returned by generate_headers)
        serialized_body = headers.pop('serialized_body', None)
        if not serialized_body:
            # Fallback if not present
            import json
            serialized_body = json.dumps(payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False)
        
        with self.client.post(
            name=step_name,
            url="/api/v3/subscribe",
            data=serialized_body,  # Use data= with pre-serialized JSON
            headers=headers,
            catch_response=True
        ) as response:
            
            if response.status_code not in expected_status:
                response.failure(f"{step_name} Failed: Expected {expected_status}, got {response.status_code}")
                return False, None, response.status_code, response
            
            try:
                data = response.json()
                # Mark HTTP-level success for CTF tracking (inside context)
                response.success()
                return True, data, response.status_code, response
            except Exception as e:
                response.failure(f"{step_name} Failed: Error parsing response: {str(e)}")
                return False, None, response.status_code, response
    
    def _send_admin_patch_request(self, step_name, payload, expected_status=[200]):
        """Send admin PATCH request for state/action changes
        
        Returns:
            tuple: (success: bool, data: dict, status_code: int, response: Response)
        """
        # Clean up internal metadata before sending
        clean_payload = {k: v for k, v in payload.items() if k != '_meta'}
        
        headers = self._generate_admin_headers()
        
        with self.client.patch(
            name=step_name,
            url="/admin/subscribe",
            json=clean_payload,
            headers=headers,
            catch_response=True
        ) as response:
            
            if response.status_code not in expected_status:
                error_msg = f"{step_name} Failed: Expected {expected_status}, got {response.status_code}"
                try:
                    error_data = response.json()
                    print(f"[{step_name}] Error response: {error_data}")
                    error_msg += f" - {error_data.get('error', {}).get('message', 'Unknown error')}"
                except:
                    print(f"[{step_name}] Error response text: {response.text[:500]}")
                    error_msg += f" - {response.text[:200]}"
                response.failure(error_msg)
                return False, None, response.status_code, response
            
            try:
                data = response.json()
                # Mark HTTP-level success for CTF tracking (inside context)
                response.success()
                return True, data, response.status_code, response
            except Exception as e:
                response.failure(f"{step_name} Failed: Error parsing response: {str(e)}")
                return False, None, response.status_code, response
    
    def _send_v3_patch_request(self, step_name, payload, expected_status=[200], signature_mode='normal'):
        """Send V3 PATCH request for updates
        
        Args:
            step_name: Name for tracking request
            payload: Request payload
            expected_status: List of acceptable status codes
            signature_mode: 'normal' (default), 'none' (no signature), 'invalid' (bad signature)
        
        Returns:
            tuple: (success: bool, data: dict, status_code: int, response: Response)
        """
        # Transform payload for V3 API format
        # Remove action field (Admin API only)
        payload.pop('action', None)
        
        # Add uk_id at root level (required for V3 API) ONLY if not already present
        # For key rotation: root uk_id = current key (for auth), payload['key']['uk_id'] = new key
        if 'uk_id' not in payload:
            # If uk_id not at root, try getting from key object (for non-rotation updates)
            if 'key' in payload and 'uk_id' in payload['key']:
                payload['uk_id'] = payload['key']['uk_id']
        
        # Add request_id if not present (required for V3 API)
        if 'request_id' not in payload:
            payload['request_id'] = str(uuid.uuid4())
        
        headers = self._generate_v3_headers(payload, signature_mode=signature_mode)
        
        # CRITICAL: Use pre-serialized JSON body to ensure digest matches
        serialized_body = headers.pop('serialized_body', None)
        if not serialized_body:
            import json
            serialized_body = json.dumps(payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False)
        
        with self.client.patch(
            name=step_name,
            url="/api/v3/subscribe",
            data=serialized_body,  # Use data= with pre-serialized JSON
            headers=headers,
            catch_response=True
        ) as response:
            
            if response.status_code not in expected_status:
                response.failure(f"{step_name} Failed: Expected {expected_status}, got {response.status_code}")
                return False, None, response.status_code, response
            
            try:
                data = response.json()
                # Mark HTTP-level success for CTF tracking (inside context)
                response.success()
                return True, data, response.status_code, response
            except Exception as e:
                response.failure(f"{step_name} Failed: Error parsing response: {str(e)}")
                return False, None, response.status_code, response
    
    # Helper methods for building structured data matching successful test patterns
    
    def _create_credential(self, cred_type, cred_data, cred_id=None):
        """Create a properly formatted credential object for Registry 3.0
        
        Args:
            cred_type: GST, PAN, FSSAI (valid credential types)
            cred_data: Dict with credential-specific data
            cred_id: Optional ID, auto-generated if not provided
        """
        if not cred_id:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            rand_suffix = uuid.uuid4().hex[:6]
            cred_id = f"cred-{cred_type.lower()}-{timestamp}-{rand_suffix}"
        
        return {
            "cred_id": cred_id,
            "type": cred_type,  # V3: changed from cred_type to type
            "cred_data": cred_data
        }
    
    def _create_contact(self, contact_type, name, email, phone, address=None, 
                       designation=None, is_primary=False, contact_data=None, contact_id=None):
        """Create a properly formatted contact object for Registry 3.0
        
        Args:
            contact_type: TECHNICAL, SUPPORT, BUSINESS, GRIEVANCE, etc.
            name: Contact person name
            email: Contact email
            phone: Contact phone
            address: Optional address
            designation: Optional job title
            is_primary: Whether this is the primary contact
            contact_data: Optional dict with additional contact metadata (deprecated in V3)
            contact_id: Optional ID, auto-generated if not provided
        """
        if not contact_id:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            rand_suffix = uuid.uuid4().hex[:6]
            contact_id = f"contact-{contact_type.lower().replace('_', '-')}-{timestamp}-{rand_suffix}"
        
        # V3: Flattened structure - no contact_data wrapper
        contact = {
            "contact_id": contact_id,
            "type": contact_type,  # V3: changed from contact_type to type
            "name": name,
            "email": email,
            "phone": phone,
            "is_primary": is_primary
        }
        
        if address:
            contact["address"] = address
        if designation:
            contact["designation"] = designation
        # Note: contact_data still supported but flattened fields are preferred
        if contact_data:
            contact["contact_data"] = contact_data
        
        return contact
    
    def _create_uri(self, uri_type, url, description=None, uri_id=None):
        """Create a properly formatted URI object for Registry 3.0"""
        if not uri_id:
            uri_id = f"uri-{uri_type.lower().replace('_', '-')}-{str(uuid.uuid4())[:6]}"
        
        uri = {
            "uri_id": uri_id,
            "type": uri_type,  # API_ENDPOINT, WEBHOOK_URL
            "url": url
        }
        
        if description:
            uri["description"] = description
        
        return uri
    
    def _create_location(self, country, city, location_type="SERVICEABLE", 
                        description=None, location_id=None):
        """Create a properly formatted location object for Registry 3.0
        
        Args:
            country: Single ISO 3-letter code (e.g., 'IND')
            city: Array of city codes (e.g., ['std:080']) or single string
            location_type: SERVICEABLE, REGISTRATION, DISCOVERABLE, STORE (uppercase)
        """
        if not location_id:
            location_id = f"loc-{country.lower()}-{str(uuid.uuid4())[:6]}"
        
        location = {
            "location_id": location_id,
            "country": country,  # V3: single string (not array)
            "city": city if isinstance(city, list) else [city],
            "type": location_type
        }
        
        if description:
            location["description"] = description
        
        return location
    
    def _query_participant(self, participant_id):
        """Query participant details to get config_ids and other metadata
        
        Returns:
            tuple: (success: bool, participant_data: dict or None)
        """
        try:
            # Try V3 API first
            with self.client.get(
                name=f"Query_Participant_{participant_id[:10]}",
                url=f"/api/v3/participant/{participant_id}",
                catch_response=True
            ) as response:
                if response.status_code == 200:
                    data = response.json()
                    response.success()
                    return True, data
                else:
                    print(f"[Query Participant] V3 API returned: {response.status_code}")
                    # Maybe try admin endpoint if V3 fails?
                    response.failure(f"Query participant failed: {response.status_code}")
                    return False, None
        except Exception as e:
            print(f"[Query Participant] Exception: {str(e)}")
            return False, None

