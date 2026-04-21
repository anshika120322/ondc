import json
import uuid
import yaml
import os
import re
from datetime import datetime
from locust import SequentialTaskSet
from common_test_foundation.lib.proxy.proxy_server import ProxyServer
from common_test_foundation.helpers.taskset_handler import RESCHEDULE_TASK, taskset_handler
from tests.utils.registry_auth_client import RegistryAuthClient
from tests.utils.ondc_auth_helper import ONDCAuthHelper


@taskset_handler(RESCHEDULE_TASK)
class RegistryLookupBase(SequentialTaskSet):
    """
    Base class for ONDC Registry Lookup API tests
    Supports:
    - Admin Lookup API (/admin/lookup)
    - Public Lookup API (/lookup)
    - V3 Lookup API (/v3.0/lookup)
    
    Uses SequentialTaskSet to run each @task method exactly once in order
    """

    # Configuration
    config_file = 'resources/registry/ondc_reg_lookup_functional.yml'
    tenant_name = 'ondcRegistry'

    def on_start(self):

        self.step_name = 'ON_START'

        # Start proxy capture
        self.proxy = ProxyServer()
        self.proxy.start_capture(trx_id=self.step_name)

        self.client.verify = self.proxy.get_certificate()
        self.client.proxies = self.proxy.get_http_proxy_config()

        # Load configuration
        config = self._load_config(self.config_file, self.tenant_name)
        
        # Store config for subclasses to access
        self.config = config

        self.host = config.get('host', 'http://localhost:8080')

        # Admin credentials
        admin_username = config.get('admin_username', '<admin-user>')
        admin_password = config.get('admin_password', 'admin')
        admin_token = config.get('admin_token')  # Pre-configured JWT token
        admin_auth_url = config.get('admin_auth_url')  # External auth service URL

        # Initialize Auth Client
        self.auth_client = RegistryAuthClient(
            self.host,
            admin_username,
            admin_password,
            proxies=self.proxy.get_http_proxy_config(),
            verify=self.proxy.get_certificate(),
            static_token=admin_token,  # Use pre-configured token if available
            auth_url=admin_auth_url  # Use external auth URL if configured
        )

        print("[LOOKUP_BASE] Auth client initialized")

        # Default lookup parameters
        self.default_domains = config.get(
            'domains',
            ['ONDC:RET10', 'ONDC:RET11', 'ONDC:LOG10']
        )

        self.default_cities = config.get(
            'cities',
            ['std:080', 'std:011']
        )

        self.default_np_types = config.get(
            'np_types',
            ['buyer', 'seller', 'logistics']
        )

        # Lookup types and countries from config
        self.lookup_types = config.get(
            'lookup_types',
            ['BPP', 'BAP', 'BG', 'REGISTRY']
        )

        self.countries = config.get(
            'countries',
            ['IND']
        )
        
        # Aliases for compatibility
        self.default_countries = self.countries
        self.default_lookup_types = self.lookup_types

        # V3 API ED25519 credentials for signature generation
        self.participant_id = config.get('participant_id')
        self.uk_id = config.get('uk_id')
        self.private_key_seed = config.get('private_key_seed')
        self.signing_public_key = config.get('signing_public_key')
        self.encryption_public_key = config.get('encryption_public_key')

        # Initialize ONDC Auth Helper for V3 API signatures
        self.ondc_auth_helper = None
        if self.participant_id and self.uk_id and self.private_key_seed:
            try:
                import base64
                private_key_bytes = None
                try:
                    # Format 1: 64-char hex-encoded raw 32-byte seed
                    private_key_bytes = bytes.fromhex(self.private_key_seed)
                except ValueError:
                    try:
                        decoded = base64.b64decode(self.private_key_seed)
                    except Exception as b64_exc:
                        raise ValueError(
                            f"private_key_seed is neither hex nor valid base64: {b64_exc}"
                        ) from b64_exc
                    if len(decoded) == 64:
                        # Format 2: 64-byte raw Ed25519 key (seed + public key);
                        # first 32 bytes are the private seed
                        private_key_bytes = decoded[:32]
                    elif len(decoded) == 32:
                        # Format 3: base64-encoded 32-byte raw Ed25519 seed
                        private_key_bytes = decoded
                    else:
                        # Format 4: base64-encoded DER PKCS#8 Ed25519 private key
                        from cryptography.hazmat.primitives.serialization import (
                            load_der_private_key, Encoding, PrivateFormat, NoEncryption
                        )
                        pk = load_der_private_key(decoded, password=None)
                        private_key_bytes = pk.private_bytes(
                            encoding=Encoding.Raw,
                            format=PrivateFormat.Raw,
                            encryption_algorithm=NoEncryption()
                        )
                self.ondc_auth_helper = ONDCAuthHelper(
                    self.participant_id,
                    self.uk_id,
                    private_key_bytes
                )
                print(f"[LOOKUP_BASE] V3 Auth initialized for participant: {self.participant_id}")
            except Exception as e:
                print(f"[LOOKUP_BASE] Warning: Failed to initialize V3 auth: {e}")
        else:
            print("[LOOKUP_BASE] Warning: V3 credentials not configured")

    def on_stop(self):
        """Cleanup resources when test completes"""
        try:
            if hasattr(self, 'proxy') and self.proxy:
                self.proxy.stop_capture()
                print("[LOOKUP_BASE] Proxy cleanup completed")
        except Exception as e:
            print(f"[LOOKUP_BASE] Warning: Proxy cleanup failed: {e}")

    # ---------------------------------------------------------------------
    # CONFIG LOADER
    # ---------------------------------------------------------------------

    def _load_config(self, config_file, tenant_name):

        config = {}

        if os.path.exists(config_file):

            with open(config_file, 'r') as f:

                yaml_content = yaml.safe_load(f)

                config = yaml_content.get(tenant_name, {})

                print(f"[LOOKUP_BASE] Loaded config: {config_file}")

        else:

            print(f"[LOOKUP_BASE] Config not found: {config_file}")

        return config


    # ---------------------------------------------------------------------
    # HEADER GENERATORS
    # ---------------------------------------------------------------------

    def _generate_admin_headers(self):

        return {
            'Authorization': f'Bearer {self.auth_client.get_token()}',
            'Content-Type': 'application/json'
        }


    def _generate_public_headers(self):

        return {
            'Content-Type': 'application/json'
        }


    def _generate_v2_headers(self, payload):
        """
        Generate headers with ED25519 signature for V2 API calls
        V2 uses the same authentication mechanism as V3
        
        Args:
            payload: Request payload dictionary
        
        Returns:
            dict: Headers with Authorization, Digest, Content-Type, and serialized_body
        """
        if not self.ondc_auth_helper:
            print("[LOOKUP_BASE] Warning: V2 auth not initialized, using basic headers")
            return self._generate_public_headers()
        
        try:
            headers = self.ondc_auth_helper.generate_headers(payload)
            return headers
        except Exception as e:
            print(f"[LOOKUP_BASE] Error generating V2 headers: {e}")
            import traceback
            traceback.print_exc()
            return self._generate_public_headers()


    def _generate_v3_headers(self, payload):
        """
        Generate headers with ED25519 signature for V3 API calls
        
        Args:
            payload: Request payload dictionary
        
        Returns:
            dict: Headers with Authorization, Digest, Content-Type, and serialized_body
        """
        if not self.ondc_auth_helper:
            print("[LOOKUP_BASE] Warning: V3 auth not initialized, using basic headers")
            return self._generate_public_headers()
        
        try:
            headers = self.ondc_auth_helper.generate_headers(payload)
            return headers
        except Exception as e:
            print(f"[LOOKUP_BASE] Error generating V3 headers: {e}")
            import traceback
            traceback.print_exc()
            return self._generate_public_headers()


    # ---------------------------------------------------------------------
    # LOOKUP PAYLOAD GENERATORS
    # ---------------------------------------------------------------------

    def _generate_v3_lookup_payload(self, country=None, lookup_type=None, **overrides):
        """
        Generate V3 lookup payload with optional parameters and flexible overrides
        Similar to gateway's _generate_search_payload pattern
        
        Args:
            country: Country code (default: from config or 'IND')
            lookup_type: Type of participant (default: from config or 'BPP')
            **overrides: Any additional fields to add/override in payload
                       Supports: domain, city, participant_id, max_results, 
                                select_keys, include_sections, npType, etc.
        
        Returns:
            dict: V3 lookup payload
        
        Examples:
            # Basic usage (backward compatible)
            payload = self._generate_v3_lookup_payload()
            
            # With domain and city filters
            payload = self._generate_v3_lookup_payload(
                domain=['ONDC:RET10'], 
                city=['std:080']
            )
            
            # Boundary testing
            payload = self._generate_v3_lookup_payload(max_results=0)
            
            # Negative testing
            payload = self._generate_v3_lookup_payload(
                domain=['invalid'],
                participant_id='test@domain.com'
            )
        """
        import random
        
        # Get default payload from config or use fallback
        default_payload = self.config.get('default_lookup_payload', {})
        
        # Start with base required fields
        payload = {
            "country": country or default_payload.get('country') or random.choice(self.countries),
            "type": lookup_type or default_payload.get('type') or random.choice(self.lookup_types)
        }
        
        # Apply any additional overrides (enables boundary & negative testing)
        payload.update(overrides)
        
        # Add request_id if not present (will be added in _send_v3_lookup_request)
        return payload

    def _generate_admin_lookup_payload(
            self,
            participant_id=None,
            domain=None,
            city=None,
            np_type=None,
            country=None,
            lookup_type=None,
            **overrides
    ):
        """
        Generate admin lookup payload for /admin/lookup API
        Supports multiple query parameters with flexible overrides
        
        Args:
            participant_id: Specific participant ID to lookup
            domain: ONDC domain (can be string or list)
            city: City code (can be string or list)
            np_type: Network participant type
            country: Country code
            lookup_type: Participant type (BPP, BAP, etc.)
            **overrides: Any additional fields to add/override in payload
        
        Returns:
            dict: Admin lookup payload
        
        Examples:
            # Single participant lookup
            payload = self._generate_admin_lookup_payload(
                participant_id='example.com'
            )
            
            # Domain and city filter
            payload = self._generate_admin_lookup_payload(
                domain=['ONDC:RET10'],
                city=['std:080']
            )
            
            # With custom fields
            payload = self._generate_admin_lookup_payload(
                domain=['ONDC:RET10'],
                max_results=10,
                select_keys=['subscriber_id', 'participant_id']
            )
        """
        payload = {}

        if participant_id:
            payload["participant_id"] = participant_id

        if domain:
            payload["domain"] = domain

        if city:
            payload["city"] = city

        if np_type:
            payload["np_type"] = np_type

        if country:
            payload["country"] = country

        if lookup_type:
            payload["type"] = lookup_type
        
        # Apply any additional overrides
        payload.update(overrides)

        return payload

    def _generate_public_lookup_payload(
            self,
            domain=None,
            city=None,
            np_type=None,
            country=None
    ):
        """
        Generate public lookup payload for /lookup API
        
        Args:
            domain: ONDC domain
            city: City code
            np_type: Network participant type
            country: Country code
        
        Returns:
            dict: Public lookup payload
        """
        import random
        
        payload = {}

        if domain:
            payload["domain"] = domain
        elif not domain and self.default_domains:
            payload["domain"] = random.choice(self.default_domains)

        if city:
            payload["city"] = city

        if np_type:
            payload["np_type"] = np_type

        if country:
            payload["country"] = country

        return payload

    def _generate_v1_lookup_payload(
            self,
            country=None,
            lookup_type=None
    ):
        """
        Generate V1 lookup payload for /lookup API (simplest form)
        V1 only requires country and type parameters
        
        Args:
            country: Country code (default: 'IND')
            lookup_type: Type of participant (default: 'BAP')
        
        Returns:
            dict: V1 lookup payload
        
        Example:
            {
                "country": "IND",
                "type": "BAP"
            }
        """
        payload = {
            "country": country or "IND",
            "type": lookup_type or "BAP"
        }
        
        return payload

    def _generate_v2_lookup_payload(
            self,
            country=None,
            lookup_type=None,
            domain=None,
            city=None,
            subscriber_id=None,
            max_results=None
    ):
        """
        Generate V2 lookup payload for /v2/lookup API
        Similar to V3 but with V2-specific parameters
        
        Args:
            country: Country code (default: from config or 'IND')
            lookup_type: Type of participant (default: from config or 'BPP')
            domain: ONDC domain filter
            city: City code (can be array or string)
            subscriber_id: Specific subscriber ID to lookup
            max_results: Maximum number of results to return
        
        Returns:
            dict: V2 lookup payload
        """
        import random
        
        payload = {}

        # Country is required for V2
        payload["country"] = country or random.choice(self.countries)

        # Optional parameters
        if lookup_type:
            payload["type"] = lookup_type

        if domain:
            payload["domain"] = domain

        if city:
            # V2 expects city as string (not array like V3)
            if isinstance(city, list):
                payload["city"] = city[0]  # Take first element if array
            else:
                payload["city"] = city

        if subscriber_id:
            payload["subscriber_id"] = subscriber_id

        if max_results is not None:
            payload["max_results"] = max_results

        return payload


    # ---------------------------------------------------------------------
    # ADMIN LOOKUP REQUEST
    # ---------------------------------------------------------------------

    def _send_admin_lookup_request(
            self,
            step_name,
            payload,
            expected_status=[200]
    ):

        headers = self._generate_admin_headers()

        with self.client.post(
                name=step_name,
                url="/admin/lookup",
                json=payload,
                headers=headers,
                catch_response=True
        ) as response:

            if response.status_code not in expected_status:

                try:
                    error = response.json()

                    response.failure(
                        f"{step_name} Failed: {error}"
                    )

                except:

                    response.failure(
                        f"{step_name} Failed: {response.text}"
                    )

                return False, None, response.status_code, response

            try:

                data = response.json()
                response.success()

                return True, data, response.status_code, response

            except Exception as e:

                response.failure(str(e))

                return False, None, response.status_code, response


    # ---------------------------------------------------------------------
    # PUBLIC LOOKUP REQUEST
    # ---------------------------------------------------------------------

    def _send_public_lookup_request(
            self,
            step_name,
            payload,
            expected_status=[200]
    ):

        headers = self._generate_public_headers()

        with self.client.post(
                name=step_name,
                url="/lookup",
                json=payload,
                headers=headers,
                catch_response=True
        ) as response:

            if response.status_code not in expected_status:

                response.failure(
                    f"{step_name} Failed: {response.text}"
                )

                return False, None, response.status_code, response

            try:

                data = response.json()

                return True, data, response.status_code, response

            except Exception as e:

                response.failure(str(e))

                return False, None, response.status_code, response


    # ---------------------------------------------------------------------
    # V3 LOOKUP REQUEST
    # ---------------------------------------------------------------------

    def _send_v3_lookup_request(
            self,
            step_name,
            payload,
            expected_status=[200],
            auto_mark_success=True
    ):

        # V3 API does not accept request_id field - do not add it
        # (unlike admin API which requires it)

        # Check if auto-registration is needed (first time only)
        if not hasattr(self, '_auto_registration_attempted'):
            self._auto_registration_attempted = False

        # Generate headers with ED25519 signature
        headers = self._generate_v3_headers(payload)

        # Extract pre-serialized body if available (important for signature validation)
        serialized_body = headers.pop('serialized_body', None)
        if not serialized_body:
            # Fallback if signature generation failed
            serialized_body = json.dumps(
                payload,
                separators=(',', ':'),
                ensure_ascii=False
            )

        with self.client.post(
                name=step_name,
                url="/v3.0/lookup",
                data=serialized_body,
                headers=headers,
                catch_response=True
        ) as response:

            if response.status_code not in expected_status:
                # Check if error is "Subscriber not found" (error code 15040)
                try:
                    error_data = response.json()
                    if (isinstance(error_data, dict) and 
                        error_data.get('error', {}).get('code') == '15040' and 
                        not self._auto_registration_attempted):
                        
                        print(f"[{step_name}] Subscriber not found (15040) - attempting auto-registration...")
                        self._auto_registration_attempted = True
                        
                        # Attempt to register the participant
                        if self._auto_register_participant():
                            print(f"[{step_name}] Auto-registration successful - retrying lookup...")
                            # Wait for sync
                            import time
                            time.sleep(5)
                            # Retry the request (recursion with auto-registration already attempted)
                            return self._send_v3_lookup_request(step_name, payload, expected_status, auto_mark_success)
                        else:
                            print(f"[{step_name}] Auto-registration failed")
                except:
                    pass  # If JSON parsing fails, continue with normal failure handling

                response.failure(
                    f"{step_name} Failed: {response.text}"
                )

                return False, None, response.status_code, response

            try:

                data = response.json()
                
                # CRITICAL: Mark as success for Locust tracking  
                # Without this, Locust won't record the request in statistics
                # BUT: Only auto-mark if caller didn't disable it (for tests that need additional validation)
                if auto_mark_success:
                    response.success()

                return True, data, response.status_code, response

            except Exception as e:

                response.failure(str(e))

                return False, None, response.status_code, response
    
    # ---------------------------------------------------------------------
    # AUTO-REGISTRATION HELPER
    # ---------------------------------------------------------------------
    
    def _auto_register_participant(self):
        """
        Auto-register the test participant when not found.
        Returns True if registration successful, False otherwise.
        """
        try:
            if not all([self.participant_id, self.uk_id, self.signing_public_key]):
                print("[AUTO_REGISTER] Missing required credentials for registration")
                return False
            
            # Build registration payload
            from datetime import datetime, timedelta
            
            valid_from = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000Z')
            valid_until = (datetime.now() + timedelta(days=365)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
            
            payload = {
                "subscriber_id": self.participant_id,
                "country": "IND",
                "city": "std:080",
                "domain": "ONDC:RET12",
                "type": "BPP",
                "signing_public_key": self.signing_public_key,
                "encryption_public_key": self.encryption_public_key or self.signing_public_key,
                "valid_from": valid_from,
                "valid_until": valid_until,
                "unique_key_id": self.uk_id,
                "subscriber_url": f"https://{self.participant_id}",
                "signing_algorithm": "ED25519",
                "encryption_algorithm": "X25519"
            }
            
            print(f"[AUTO_REGISTER] Registering participant: {self.participant_id}")
            print(f"[AUTO_REGISTER] UK ID: {self.uk_id}")
            
            # Get admin token for registration
            token = self.auth_client.get_token()
            if not token:
                print("[AUTO_REGISTER] Failed to get admin token")
                return False
            
            # Send registration request
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            with self.client.post(
                name="AUTO_REGISTER_PARTICIPANT",
                url=f"{self.host}/admin/subscribe",
                json=payload,
                headers=headers,
                catch_response=True
            ) as response:
                
                if response.status_code in [200, 201]:
                    print(f"[AUTO_REGISTER] ✓ Participant registered successfully")
                    response.success()
                    return True
                else:
                    print(f"[AUTO_REGISTER] ✗ Registration failed: {response.status_code}")
                    print(f"[AUTO_REGISTER] Response: {response.text[:500]}")
                    response.failure(f"Registration failed: {response.status_code}")
                    return False
                    
        except Exception as e:
            print(f"[AUTO_REGISTER] Exception during registration: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    # ---------------------------------------------------------------------
    # V1 LOOKUP REQUEST (Simplest form - /lookup endpoint)
    # ---------------------------------------------------------------------

    def _send_v1_lookup_request(
            self,
            step_name,
            payload,
            expected_status=[200]
    ):
        """
        Send V1 lookup request to /lookup endpoint (no version prefix)
        This is the simplest and original lookup API
        
        Args:
            step_name: Name for tracking request
            payload: V1 lookup payload (country + type)
            expected_status: List of acceptable status codes
        
        Returns:
            tuple: (success, data, status_code, response)
        """
        headers = self._generate_public_headers()

        with self.client.post(
                name=step_name,
                url="/lookup",
                json=payload,
                headers=headers,
                catch_response=True
        ) as response:

            if response.status_code not in expected_status:

                response.failure(
                    f"{step_name} Failed: {response.text}"
                )

                return False, None, response.status_code, response

            try:

                data = response.json()
                
                # Mark as success inside the context manager
                response.success()

                return True, data, response.status_code, response

            except Exception as e:

                # If status is expected error code (400, 416), treat as success
                # even if JSON parsing fails (empty body or non-JSON response)
                if response.status_code in [400, 416]:
                    response.success()
                    return True, None, response.status_code, response
                
                response.failure(f"{step_name} Failed: {str(e)}")

                return False, None, response.status_code, response

    def _send_v1_lookup_request_raw(
            self,
            step_name,
            raw_body,
            content_type="application/json",
            expected_status=[400]
    ):
        """
        Send V1 lookup request with raw body (for testing invalid JSON)
        No authentication headers needed for public V1 endpoint
        
        Args:
            step_name: Name for tracking request
            raw_body: Raw string body (potentially malformed JSON)
            content_type: Content-Type header
            expected_status: List of acceptable status codes
        
        Returns:
            tuple: (success, data, status_code, response)
        """
        headers = {
            "Content-Type": content_type
        }

        with self.client.post(
                name=step_name,
                url="/lookup",
                data=raw_body,
                headers=headers,
                catch_response=True
        ) as response:

            if response.status_code not in expected_status:

                response.failure(
                    f"{step_name} Failed: {response.text}"
                )

                return False, None, response.status_code, response

            try:

                data = response.json()
                
                # Mark as success inside the context manager
                response.success()

                return True, data, response.status_code, response

            except Exception as e:

                # For invalid JSON, this is expected - return success with error status
                response.success()
                return True, None, response.status_code, response

    # ---------------------------------------------------------------------
    # V2 LOOKUP REQUEST
    # ---------------------------------------------------------------------

    def _send_v2_lookup_request(
            self,
            step_name,
            payload,
            expected_status=[200],
            auto_mark_success=True,
            expected_error_codes=None
    ):

        # Generate headers with ED25519 signature
        headers = self._generate_v2_headers(payload)

        # Extract pre-serialized body if available (important for signature validation)
        serialized_body = headers.pop('serialized_body', None)
        if not serialized_body:
            # Fallback if signature generation failed
            serialized_body = json.dumps(
                payload,
                separators=(',', ':'),
                ensure_ascii=False
            )

        with self.client.post(
                name=step_name,
                url="/v2.0/lookup",
                data=serialized_body,
                headers=headers,
                catch_response=True
        ) as response:

            # Try to parse JSON response first
            try:
                data = response.json()
            except Exception as e:
                data = None

            # Handle validation when expected_error_codes is provided (for negative tests)
            if not auto_mark_success and expected_error_codes is not None:
                # Check if response has expected error code (works for any HTTP status)
                if isinstance(data, dict) and 'error' in data:
                    error_code = data.get('error', {}).get('code')
                    if error_code in expected_error_codes:
                        response.success()
                        return True, data, response.status_code, response
                    else:
                        response.failure(f"Expected error codes {expected_error_codes}, got {error_code}")
                        return False, data, response.status_code, response
                elif isinstance(data, list):
                    # Valid results list when error was expected
                    response.failure(f"Expected error response, got valid results")
                    return False, data, response.status_code, response
                else:
                    response.failure(f"Unexpected response format: {type(data)}, status: {response.status_code}")
                    return False, data, response.status_code, response
            
            # Original logic for non-error-code validation tests
            if response.status_code not in expected_status:
                response.failure(
                    f"{step_name} Failed: {response.text}"
                )
                return False, data, response.status_code, response

            # Auto-mark success if enabled
            if auto_mark_success:
                response.success()

            return True, data, response.status_code, response

    # ---------------------------------------------------------------------
    # V2 LOOKUP REQUEST FOR BOUNDARY TESTS
    # Accepts specific error codes (15000-19999) as success for boundary tests
    # V2 returns: HTTP 200 (success), HTTP 404 (error 1001), HTTP 416 (error 1050)
    # Updated to accept ONDC Registry error codes (15000-19999 range)
    # ---------------------------------------------------------------------
    def _send_v2_boundary_test_request(
            self,
            step_name,
            payload,
            expected_status=[200],
            acceptable_error_codes=None
    ):
        """
        Send V2 lookup request for boundary testing.
        Calls response.success() for:
        - HTTP 200 with valid list response
        - HTTP 404 with error code 1001 (no matching participant)
        - HTTP 416 with error code 1050 (validation error)
        - Any HTTP status in expected_status
        - Error codes in ONDC Registry range (15000-19999)
        """
        # Default to accepting ONDC Registry error code range
        if acceptable_error_codes is None:
            acceptable_error_codes = []
            # Accept all ONDC Registry error codes (15000-19999)
            for code in range(15000, 20000):
                acceptable_error_codes.append(str(code))
                acceptable_error_codes.append(code)
        
        # Generate headers with ED25519 signature
        headers = self._generate_v2_headers(payload)

        # Extract pre-serialized body
        serialized_body = headers.pop('serialized_body', None)
        if not serialized_body:
            serialized_body = json.dumps(
                payload,
                separators=(',', ':'),
                ensure_ascii=False
            )

        # Variables to return
        success_flag = False
        data = None
        status_code = 0

        with self.client.post(
                name=step_name,
                url="/v2.0/lookup",
                data=serialized_body,
                headers=headers,
                catch_response=True
        ) as response:

            status_code = response.status_code

            # Parse response
            try:
                if response.text:
                    data = response.json()
                else:
                    data = None
            except Exception:
                data = None

            # Decision logic INSIDE the with block
            if status_code == 200:
                # Check if it's a list (valid results)
                if isinstance(data, list):
                    response.success()
                    success_flag = True
                
                # Check if it's an error with acceptable error code
                elif isinstance(data, dict) and 'error' in data:
                    error_code = data.get('error', {}).get('code')
                    if error_code in acceptable_error_codes:
                        response.success()
                        success_flag = True
                    else:
                        response.failure(f"Unexpected error code: {error_code}")
                        success_flag = False
                else:
                    response.failure(f"Unexpected response format: {type(data)}")
                    success_flag = False
            
            elif status_code in [401, 404, 416]:
                # V2 returns 401 for auth/signature errors, 404 for error 1001, 416 for error 1050
                # Accept if error code is in acceptable range (e.g., 15000-19999 for ONDC Registry)
                if isinstance(data, dict) and 'error' in data:
                    error_code = data.get('error', {}).get('code')
                    if error_code in acceptable_error_codes:
                        response.success()
                        success_flag = True
                    else:
                        response.failure(f"Unexpected error code {error_code} with status {status_code}")
                        success_flag = False
                else:
                    response.failure(f"Status {status_code} without error code")
                    success_flag = False
            
            elif status_code in expected_status:
                # Other expected status codes (400, 413, etc.)
                response.success()
                success_flag = True
            else:
                response.failure(f"Unexpected status {status_code}")
                success_flag = False

        # Return AFTER the with block exits
        return success_flag, data, status_code
 

    # ---------------------------------------------------------------------
    # V3 GENERIC LOOKUP REQUEST (for custom headers in negative tests)
    # ---------------------------------------------------------------------

    def _send_v3_lookup_request_custom(
            self,
            step_name,
            payload=None,
            headers=None,
            raw_body=None,
            expected_status=[200]
    ):
        """
        Generic V3 lookup request that accepts custom headers.
        Used primarily for negative testing where custom/invalid headers are needed.
        """
        if headers is None:
            headers = self._generate_v3_headers(payload if payload else {})

        # Determine which body to use
        if raw_body is not None:
            # Use raw body as-is (for malformed JSON tests)
            request_data = raw_body
            content_type = 'data'
        else:
            # Use JSON payload - serialize properly for V3
            if payload:
                serialized_body = json.dumps(
                    payload,
                    separators=(',', ':'),
                    ensure_ascii=False
                )
            else:
                serialized_body = "{}"
            request_data = serialized_body
            content_type = 'data'

        with self.client.post(
                name=step_name,
                url="/v3.0/lookup",
                **{content_type: request_data},
                headers=headers,
                catch_response=True
        ) as response:

            if response.status_code not in expected_status:
                try:
                    error = response.json()
                    response.failure(f"{step_name} Failed: {error}")
                except:
                    response.failure(f"{step_name} Failed: {response.text}")

                return False, None, response.status_code, response

            try:
                data = response.json()
                response.success()
                return True, data, response.status_code, response
            except Exception as e:
                response.failure(str(e))
                return False, None, response.status_code, response


    # ---------------------------------------------------------------------
    # V2 GENERIC LOOKUP REQUEST (for custom headers in negative tests)
    # ---------------------------------------------------------------------

    def _send_v2_lookup_request_custom(
            self,
            step_name,
            payload=None,
            headers=None,
            raw_body=None,
            expected_status=[200],
            auto_mark_success=True
    ):
        """
        Generic V2 lookup request that accepts custom headers.
        Used primarily for negative testing where custom/invalid headers are needed.
        """
        if headers is None:
            # Use payload for header generation if available, otherwise empty dict
            headers = self._generate_v2_headers(payload if payload else {})

        # Determine which body to use
        if raw_body is not None:
            # Use raw body as-is (for malformed JSON tests)
            request_data = raw_body
            content_type = 'data'
        else:
            # Use JSON payload
            request_data = payload if payload else {}
            content_type = 'json'

        with self.client.post(
                name=step_name,
                url="/v2.0/lookup",
                **{content_type: request_data},
                headers=headers,
                catch_response=True
        ) as response:

            if response.status_code not in expected_status:
                try:
                    error = response.json()
                    response.failure(f"{step_name} Failed: {error}")
                except:
                    response.failure(f"{step_name} Failed: {response.text}")

                return False, None, response.status_code, response

            try:
                data = response.json()
                
                # Only auto-mark if caller didn't disable it (for tests that need additional validation)
                if auto_mark_success:
                    response.success()
                    
                return True, data, response.status_code, response
            except Exception as e:
                response.failure(str(e))
                return False, None, response.status_code, response


    # ---------------------------------------------------------------------
    # GENERIC LOOKUP REQUEST (for custom headers in negative tests)
    # ---------------------------------------------------------------------

    def _send_lookup_request(
            self,
            step_name,
            payload=None,
            headers=None,
            raw_body=None,
            expected_status=[200]
    ):
        """
        Generic lookup request that accepts custom headers.
        Used primarily for negative testing where custom/invalid headers are needed.
        """
        if headers is None:
            headers = self._generate_admin_headers()

        # Determine which body to use
        if raw_body is not None:
            # Use raw body as-is (for malformed JSON tests)
            request_data = raw_body
            content_type = 'data'
        else:
            # Use JSON payload
            request_data = payload if payload else {}
            content_type = 'json'

        with self.client.post(
                name=step_name,
                url="/admin/lookup",
                **{content_type: request_data},
                headers=headers,
                catch_response=True
        ) as response:

            if response.status_code not in expected_status:
                try:
                    error = response.json()
                    response.failure(f"{step_name} Failed: {error}")
                except:
                    response.failure(f"{step_name} Failed: {response.text}")

                return False, None, response.status_code, response

            try:
                data = response.json()
                response.success()
                return True, data, response.status_code, response
            except Exception as e:
                response.failure(str(e))
                return False, None, response.status_code, response


    # ---------------------------------------------------------------------
    # NEGATIVE TEST HELPER METHODS (V2/V3 Lookup)
    # ---------------------------------------------------------------------

    def _send_lookup_request_no_auth(self, step_name, payload, version="v3", expected_status=[401]):
        """Send V2/V3 lookup request without Authorization header"""
        headers = {"Content-Type": "application/json"}
        if version == "v2":
            return self._send_v2_lookup_request_custom(step_name, payload, headers, None, expected_status)
        else:
            return self._send_v3_lookup_request_custom(step_name, payload, headers, None, expected_status)

    def _send_lookup_request_invalid_token(self, step_name, payload, version="v3", expected_status=[401]):
        """Send V2/V3 lookup request with invalid Bearer token"""
        headers = {
            "Authorization": "Bearer invalid-token",
            "Content-Type": "application/json"
        }
        if version == "v2":
            return self._send_v2_lookup_request_custom(step_name, payload, headers, None, expected_status)
        else:
            return self._send_v3_lookup_request_custom(step_name, payload, headers, None, expected_status)

    def _send_lookup_request_expired_auth(self, step_name, payload, version="v3", expected_status=[401]):
        """Send V2/V3 lookup request with expired signature"""
        headers = {
            "Authorization": self.config["invalid_auth"]["expired_signature"],
            "Content-Type": "application/json"
        }
        if version == "v2":
            return self._send_v2_lookup_request_custom(step_name, payload, headers, None, expected_status)
        else:
            return self._send_v3_lookup_request_custom(step_name, payload, headers, None, expected_status)

    def _send_lookup_request_invalid_signature(self, step_name, payload, version="v3", expected_status=[401]):
        """Send V2/V3 lookup request with invalid signature"""
        headers = {
            "Authorization": self.config["invalid_auth"]["invalid_signature"],
            "Content-Type": "application/json"
        }
        if version == "v2":
            return self._send_v2_lookup_request_custom(step_name, payload, headers, None, expected_status)
        else:
            return self._send_v3_lookup_request_custom(step_name, payload, headers, None, expected_status)

    def _send_lookup_request_subscriber_not_found(self, step_name, payload, version="v3", expected_status=[401]):
        """Send V2/V3 lookup request with non-existent subscriber"""
        headers = {
            "Authorization": self.config["invalid_auth"]["subscriber_not_found"],
            "Content-Type": "application/json"
        }
        if version == "v2":
            return self._send_v2_lookup_request_custom(step_name, payload, headers, None, expected_status)
        else:
            return self._send_v3_lookup_request_custom(step_name, payload, headers, None, expected_status)

    def _send_lookup_request_invalid_json(self, step_name, raw_body, version="v3", expected_status=[400]):
        """Send V2/V3 lookup request with malformed JSON"""
        # Generate fresh auth headers (to avoid expiry issues)
        # For invalid JSON test, we need valid auth but invalid body
        # Parse the malformed JSON to get what payload would be if fixed
        try:
            payload = json.loads(raw_body + "}")
        except:
            payload = {"country": "IND", "type": "BPP"}
        
        if version == "v2":
            v2_headers = self._generate_v2_headers(payload)
            return self._send_v2_lookup_request_custom(step_name, None, v2_headers, raw_body, expected_status)
        else:
            v3_headers = self._generate_v3_headers(payload)
            return self._send_v3_lookup_request_custom(step_name, None, v3_headers, raw_body, expected_status)

    def _send_lookup_request_wrong_content_type(self, step_name, raw_body, version="v3", expected_status=[415]):
        """Send V2/V3 lookup request with wrong Content-Type header"""
        # For wrong Content-Type test, we send with text/plain
        # Generate auth headers without Content-Type override first
        payload = json.loads(raw_body) if raw_body else {}
        
        if version == "v2":
            v2_headers = self._generate_v2_headers(payload)
            v2_headers["Content-Type"] = "text/plain"
            return self._send_v2_lookup_request_custom(step_name, None, v2_headers, raw_body, expected_status)
        else:
            v3_headers = self._generate_v3_headers(payload)
            # Change Content-Type to wrong value (this may cause signature verification to fail)
            # The server should reject based on Content-Type, not signature
            v3_headers["Content-Type"] = "text/plain"
            # Accept both 415 (Content-Type error) and 401 (signature error due to Content-Type change)
            return self._send_v3_lookup_request_custom(step_name, None, v3_headers, raw_body, expected_status)

    def _send_lookup_request_invalid_algorithm(self, step_name, payload, algorithm_value, version="v3", expected_status=[401]):
        """Send V3 lookup request with invalid algorithm value in Authorization header
        
        Args:
            step_name: Test step name
            payload: Request payload
            algorithm_value: Invalid algorithm value to test (e.g., "banaa", "mango", "banana")
            version: API version (default: "v3")
            expected_status: Expected HTTP status codes (default: [401])
            
        Returns:
            Tuple of (success, data, status, response)
        """
        # Generate valid headers first
        v3_headers = self._generate_v3_headers(payload)
        
        # Modify the algorithm field in the Authorization header
        if "Authorization" in v3_headers:
            original_auth = v3_headers["Authorization"]
            # Replace algorithm="ed25519" with the test value
            modified_auth = re.sub(
                r'algorithm="[^"]*"',
                f'algorithm="{algorithm_value}"',
                original_auth
            )
            v3_headers["Authorization"] = modified_auth
        
        return self._send_v3_lookup_request_custom(step_name, payload, v3_headers, None, expected_status)

    def _send_lookup_request_invalid_headers_field(self, step_name, payload, headers_field_value, version="v3", expected_status=[401]):
        """Send V3 lookup request with invalid 'headers' field value in Authorization header
        
        Args:
            step_name: Test step name
            payload: Request payload
            headers_field_value: Invalid headers field value to test (e.g., "(created) (expires)", "digest (created) (expires)")
            version: API version (default: "v3")
            expected_status: Expected HTTP status codes (default: [401])
            
        Returns:
            Tuple of (success, data, status, response)
        """
        # Generate valid headers first
        v3_headers = self._generate_v3_headers(payload)
        
        # Modify the headers field in the Authorization header
        if "Authorization" in v3_headers:
            original_auth = v3_headers["Authorization"]
            # Replace headers="..." with the test value
            modified_auth = re.sub(
                r'headers="[^"]*"',
                f'headers="{headers_field_value}"',
                original_auth
            )
            v3_headers["Authorization"] = modified_auth
        
        return self._send_v3_lookup_request_custom(step_name, payload, v3_headers, None, expected_status)


    # ---------------------------------------------------------------------
    # HELPER VALIDATION METHODS
    # ---------------------------------------------------------------------

    def _validate_lookup_response(self, response_data):

        if not response_data:

            return False, "Empty response"

        if "subscriber" not in response_data:

            return False, "Missing subscriber field"

        return True, "Valid response"
