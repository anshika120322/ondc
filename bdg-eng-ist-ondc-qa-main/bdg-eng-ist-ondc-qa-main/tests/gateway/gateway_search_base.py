import json
import time
import uuid
import yaml
import os
import logging
from datetime import datetime, timezone
from locust import TaskSet
from common_test_foundation.lib.proxy.proxy_server import ProxyServer
from common_test_foundation.helpers.taskset_handler import RESCHEDULE_TASK, taskset_handler
from tests.utils.ondc_auth_helper import ONDCAuthHelper
from tests.utils.ondc_lookup_helper import ONDCLookupHelper
from tests.utils.ondc_error_catalogue import validate_nack_error

logger = logging.getLogger(__name__)

"""
Base class for ONDC Gateway Search API tests
Contains shared functionality: config loading, auth setup, helper methods
"""

@taskset_handler(RESCHEDULE_TASK)
class GatewaySearchBase(TaskSet):
    """Base class with shared setup and helper methods for Gateway Search tests"""
    
    def on_start(self):
        """Initialize proxy, load config, setup authentication"""
        self.step_name = 'ON_START'
        
        # Disable proxy for performance tests (enable_proxy=False by default for performance)
        # Child classes can override by setting enable_proxy=True
        if getattr(self, 'enable_proxy', False):
            self.proxy = ProxyServer()
            self.proxy.start_capture(trx_id=self.step_name)
            self.client.verify = self.proxy.get_certificate()
            self.client.proxies = self.proxy.get_http_proxy_config()
        else:
            self.proxy = None
        
        # Load configuration - child classes can override config_file_name
        config_file = getattr(self, 'config_file', 'resources/gateway/ondc_gateway_search.yml')
        tenant_name = getattr(self, 'tenant_name', 'ondcGatewaySearch')
        
        config = self._load_config(config_file, tenant_name)
        
        # Setup authentication
        participant_id, uk_id, private_key_seed = self._setup_auth(config)
        
        self.auth_helper = ONDCAuthHelper(
            participant_id=participant_id,
            uk_id=uk_id,
            private_key_seed=private_key_seed
        )
        
        # Store common data
        self.search_domains = config.get('domains', ["ONDC:RET10", "ONDC:RET11", "ONDC:RET12", "ONDC:RET13"])
        self.cities = config.get('cities', ["std:080", "std:022", "std:011", "std:040"])
        self.search_items = config.get('search_items', ["laptop", "mobile", "shirt", "grocery", "electronics"])
        
        # Search-specific config data
        self.fulfillment_types = config.get('fulfillment_types', [])
        self.item_categories = config.get('item_categories', [])
        self.payment_types = config.get('payment_types', [])
        self.domain_tags = config.get('domain_tags', {})
        self.test_locations = config.get('test_locations', [])
        self.multiple_items = config.get('multiple_items', [])

        # Core config — all values loaded from YAML; no environment-specific defaults
        self.core_version = config.get('core_version', '1.2.0')
        self.bap_id = config.get('bap_id')
        self.bap_uri = config.get('bap_uri')
        self.bpp_id = config.get('bpp_id')
        self.bpp_uri = config.get('bpp_uri')

        logger.info(f"ON_START completed successfully for Search tests. wait_time={getattr(self, 'wait_time', 'NOT SET')}")
    
    def _load_config(self, config_file, tenant_name):
        """Load tenant configuration from YAML file"""
        config = {}
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                yaml_content = yaml.safe_load(f)
                if not yaml_content:
                    logger.warning(f"Config file is empty: {config_file}")
                    return config
                config = yaml_content.get(tenant_name, {})
                logger.info(f"Loaded config from {config_file}")
        else:
            logger.warning(f"Config file not found: {config_file}")
        return config
    
    def _setup_auth(self, config):
        """Setup authentication credentials from lookup or config"""
        lookup_url = config.get('lookup_host', '')
        participant_id = None
        uk_id = None
        private_key_seed = None
        
        if lookup_url:
            # Call lookup to discover BPP credentials dynamically
            lookup_helper = ONDCLookupHelper(lookup_url)
            lookup_domain = config.get('lookup_domain', 'ONDC:RET10')
            lookup_city = config.get('lookup_city', 'std:080')
            
            logger.info(f"Calling lookup for BPP in {lookup_domain}, {lookup_city}")
            lookup_result = lookup_helper.lookup(
                domain=lookup_domain,
                participant_type="BPP",
                city=lookup_city
            )
            
            # Extract credentials from lookup response
            bpp_list_found = []
            if lookup_result.get("success") and lookup_result.get("data"):
                bpp_list = lookup_result["data"]
                if isinstance(bpp_list, list) and len(bpp_list) > 0:
                    # Store all found BPPs for reference
                    for bpp in bpp_list:
                        subscriber_id = bpp.get("subscriber_id")
                        keys = bpp.get("keys", [])
                        if keys and len(keys) > 0:
                            bpp_uk_id = keys[0].get("uk_id")
                            pub_key = keys[0].get("signing_public_key", "")[:50]
                            bpp_list_found.append(f"{subscriber_id} (uk_id: {bpp_uk_id})")
                    
                    # Use first BPP by default
                    bpp = bpp_list[0]
                    participant_id = bpp.get("subscriber_id")
                    
                    keys = bpp.get("keys", [])
                    if keys and len(keys) > 0:
                        uk_id = keys[0].get("uk_id")
                        public_key = keys[0].get("signing_public_key")
                        
                logger.info(f"Found {len(bpp_list_found)} BPP(s): {', '.join(bpp_list_found)}")
                logger.info(f"Using BPP: {participant_id}, uk_id: {uk_id}")
                if public_key:
                    logger.debug(f"BPP Public Key (first 80 chars): {public_key[:80]}...")
            else:
                logger.warning("Lookup failed or returned no results")
        else:
            logger.info("Lookup disabled, using credentials from config")
        
        # Use credentials from config (either as fallback or primary source)
        if not participant_id:
            participant_id = config.get('participant_id', 'participant-1.participant.ondc')
            logger.info(f"Using participant_id from config: {participant_id}")
        if not uk_id:
            uk_id = config.get('uk_id', 'buyer-key-001')
            logger.info(f"Using uk_id from config: {uk_id}")
        
        # Private key must come from config
        private_key_hex = config.get('private_key_seed')
        if not private_key_hex:
            raise ValueError("private_key_seed is required in config. Do not use hardcoded keys.")
        
        private_key_seed = None
        if isinstance(private_key_hex, str):
            # Try hex format first (64-char hex string = 32 bytes)
            if len(private_key_hex) == 64:
                try:
                    private_key_seed = bytes.fromhex(private_key_hex)
                    logger.info("Using private key from config (hex format)")
                except ValueError:
                    pass
            
            # If not valid hex, try base64 (NaCl 64-byte or PKCS#8)
            if private_key_seed is None:
                try:
                    import base64
                    decoded_bytes = base64.b64decode(private_key_hex)
                    if len(decoded_bytes) == 64:
                        # NaCl-style 64-byte signing key: seed = first 32 bytes, public key = last 32 bytes
                        private_key_seed = decoded_bytes[:32]
                        logger.info("Using private key from config (base64 NaCl 64-byte format)")
                    elif len(decoded_bytes) >= 32:
                        # PKCS#8 DER format: the 32-byte seed is at the end
                        private_key_seed = decoded_bytes[-32:]
                        logger.info("Using private key from config (base64 PKCS#8 format)")
                except Exception:
                    pass
        
        if private_key_seed is None:
            raise ValueError(
                f"Invalid private_key_seed in config. Expected a 64-char hex string or "
                f"base64-encoded PKCS#8 key, got {len(private_key_hex) if private_key_hex else 0} chars"
            )
        
        return participant_id, uk_id, private_key_seed
    
    def _generate_search_payload(self, domain=None, city=None, item=None, gps=None,
                                    bpp_id=None, bpp_uri=None):
        """Generate a search payload with optional parameters.

        Args:
            domain: ONDC domain code (default: random from config).
            city: City std code (default: random from config).
            item: Item name for item-based search (adds item.descriptor.name to intent).
            gps: Delivery GPS coordinates (default: from config or fallback).
            bpp_id: BPP subscriber ID — when set, produces a SYNC (unicast) request.
                    Leave None for BROADCAST (async) mode.
            bpp_uri: BPP callback URI — required when bpp_id is provided.
        """
        import random

        txn_id = f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = f"msg-{uuid.uuid4().hex[:12]}"

        # Get GPS from config or use provided value
        if not gps:
            if hasattr(self, 'test_locations') and self.test_locations:
                gps = random.choice(self.test_locations).get('gps', '12.9716,77.5946')
            else:
                gps = '12.9716,77.5946'  # Fallback only

        context = {
            "domain": domain or random.choice(self.search_domains),
            "action": "search",
            "country": "IND",
            "city": city or random.choice(self.cities),
            "core_version": self.core_version,
            "bap_id": self.bap_id,
            "bap_uri": self.bap_uri,
            "transaction_id": txn_id,
            "message_id": msg_id,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
            "ttl": "PT5M"
        }

        # Sync (unicast) mode — add bpp_id/bpp_uri for direct BPP routing
        if bpp_id:
            context["bpp_id"] = bpp_id
            context["bpp_uri"] = bpp_uri or self.bpp_uri

        # Build intent — payment buyer_app_finder_fee is REQUIRED per ONDC v1.2
        intent = {
            "fulfillment": {
                "type": "Delivery",
                "end": {
                    "location": {
                        "gps": gps
                    }
                }
            },
            "payment": {
                "@ondc/org/buyer_app_finder_fee_type": "percent",
                "@ondc/org/buyer_app_finder_fee_amount": "3.0"
            },
            "category": {
                "descriptor": {
                    "name": item or random.choice(self.search_items)
                }
            }
        }

        return {
            "context": context,
            "message": {
                "intent": intent
            }
        }
    
    def _generate_on_search_payload(self, transaction_id=None, message_id=None):
        """Generate an on_search callback payload from seller"""
        import random
        
        txn_id = transaction_id or f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-{uuid.uuid4().hex[:12]}"
        
        return {
            "context": {
                "domain": random.choice(self.search_domains),
                "action": "on_search",
                "country": "IND",
                "city": random.choice(self.cities),
                "core_version": self.core_version,
                "bap_id": self.bap_id,
                "bap_uri": self.bap_uri,
                "bpp_id": self.bpp_id,
                "bpp_uri": self.bpp_uri,
                "transaction_id": txn_id,
                "message_id": msg_id,
                "timestamp": datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                "ttl": "PT5M"
            },
            "message": {
                "catalog": {
                    "bpp/descriptor": {
                        "name": "Test Seller Store",
                        "short_desc": "Your local grocery store"
                    },
                    "bpp/providers": [
                        {
                            "id": "IGO_Seller_0001",
                            "descriptor": {
                                "name": "Fresh Groceries",
                                "short_desc": "Fresh produce and groceries"
                            },
                            "locations": [
                                {
                                    "id": "store-location-001",
                                    "gps": "12.9063433,77.5856825",
                                    "address": "123 Market Street, Bangalore"
                                }
                            ],
                            "items": [
                                {
                                    "id": "item-001",
                                    "descriptor": {
                                        "name": "Organic Apples",
                                        "short_desc": "Fresh organic apples - 1kg"
                                    },
                                    "price": {
                                        "currency": "INR",
                                        "value": "150.00"
                                    },
                                    "quantity": {
                                        "available": {"count": 100}
                                    }
                                }
                            ]
                        }
                    ]
                }
            }
        }

    def _setup_linked_transaction(self, tc_name):
        """
        Send a /search request to register a transaction_id with the Gateway,
        then return that transaction_id for use in the corresponding /on_search callback.
        All on_search TCs use this to ensure realistic flow linkage.
        """
        search_payload = self._generate_search_payload()
        txn_id = search_payload['context']['transaction_id']
        self._send_search_request(
            f"{tc_name}_Setup_LinkedSearch", search_payload, expected_status=[200, 202]
        )
        return txn_id
    
    def _send_search_request(self, step_name, payload, headers=None, expected_status=None, test_type='functional', expected_error_code=None):
        """
        Helper method to send search requests with consistent error handling.

        Args:
            step_name: Name for the test step
            payload: Request payload (dict)
            headers: Optional headers (will generate auth if not provided)
            expected_status: List of expected status codes (default: [200, 202])
            test_type: 'functional' (default) or 'negative'.
                - 'functional': HTTP status checked first; then NACK in response body
                  marks the test FAILED even if HTTP status is 200. ACK = PASS.
                - 'negative': NACK in response body = PASS (error details captured);
                  ACK = FAIL (gateway accepted a request it should have rejected);
                  HTTP 4xx/5xx with no ACK/NACK body = PASS (auth-level rejection).

        Returns:
            tuple: (success: bool, response_data: dict, status_code: int)
        """
        if headers is None:
            # ONDC preprod gateway requires BLAKE-512 digest in both the Authorization
            # signing string and as a separate Digest header — keep include_digest=True
            headers = self.auth_helper.generate_headers(payload, include_digest=True)

        if expected_status is None:
            expected_status = [200, 202]

        # CRITICAL: Extract pre-serialized body from headers (generated with sort_keys=False)
        # This ensures the exact same JSON used for signature generation is sent
        serialized_body = headers.pop('serialized_body', None)
        if not serialized_body:
            # Fallback: serialize with same settings as auth_helper (sort_keys=False, ensure_ascii=False)
            serialized_body = json.dumps(payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False)

        with self.client.post(
            name=step_name,
            url="/search",
            data=serialized_body.encode('utf-8'),  # Encode to bytes to support Unicode (Hindi, emoji, etc.)
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
            catch_response=True
        ) as response:

            if test_type == 'negative':
                # --- Negative test validation ---
                # Parse response body when available
                try:
                    data = response.json() if response.content else {}
                except Exception:
                    data = {}

                ack_status = data.get('message', {}).get('ack', {}).get('status')

                if ack_status == 'ACK':
                    # Gateway accepted a request it should have rejected → test FAILS
                    response.failure(f"{step_name} Failed: Expected NACK/rejection but received ACK")
                    return False, data, response.status_code

                if ack_status == 'NACK':
                    # Gateway correctly rejected → validate code and type against catalogue
                    error_info = data.get('error', {})
                    actual_code = str(error_info.get('code', '')) or 'N/A'
                    actual_type = error_info.get('type', '')
                    error_msg = error_info.get('message', 'No error message')
                    ok, note = validate_nack_error(actual_code, actual_type, expected_error_code)
                    if not ok:
                        response.failure(f"{step_name} Failed: NACK received but {note}")
                        return False, data, response.status_code
                    logger.info(f"{step_name} NACK received (expected for negative test): {note} — {error_msg}")
                    response.success()
                    return True, data, response.status_code

                # No ACK/NACK in body (e.g. plain HTTP 401 auth rejection)
                if response.status_code >= 400:
                    if expected_error_code:
                        # Caller expects a structured NACK body — plain rejection is not enough
                        response.failure(
                            f"{step_name} Failed: Expected NACK body with "
                            f"message.ack.status='NACK' and error.code={expected_error_code!r} "
                            f"but response body contains neither (HTTP {response.status_code})"
                        )
                        return False, data, response.status_code
                    response.success()
                    return True, data, response.status_code

                # HTTP 2xx but no NACK — unexpected for a negative test
                response.failure(
                    f"{step_name} Failed: Expected NACK/rejection, got HTTP {response.status_code} with no NACK"
                )
                return False, data, response.status_code

            else:
                # --- Functional test validation (default) ---
                # Check expected HTTP status first
                if response.status_code not in expected_status:
                    response.failure(f"{step_name} Failed: Expected {expected_status}, got {response.status_code}")
                    return False, None, response.status_code

                # Parse response body
                try:
                    data = response.json() if response.content else {}
                except Exception as e:
                    response.failure(f"{step_name} Failed: Error parsing response: {str(e)}")
                    return False, None, response.status_code

                # Check ACK/NACK — NACK means the gateway rejected the payload even
                # though HTTP 200 was returned; this is a functional failure
                ack_status = data.get('message', {}).get('ack', {}).get('status')
                if ack_status == 'NACK':
                    error_info = data.get('error', {})
                    error_code = error_info.get('code', 'N/A')
                    error_type = error_info.get('type', '')
                    error_msg = error_info.get('message', 'No error message')
                    type_note = f", error.type={error_type}" if error_type else ""
                    response.failure(
                        f"{step_name} Failed: NACK received for a valid request — "
                        f"error.code={error_code}{type_note} ({error_msg})"
                    )
                    return False, data, response.status_code

                response.success()
                return True, data, response.status_code
    
    def _send_on_search_request(self, step_name, payload, headers=None, expected_status=None, validate_catalog=True):
        """
        Helper method to send on_search requests with consistent error handling and validation
        
        Args:
            step_name: Name for the test step
            payload: Request payload (dict)
            headers: Optional headers (will generate auth if not provided)
            expected_status: List of expected status codes (default: [200, 202])
            validate_catalog: Whether to validate catalog structure (default: True)
        
        Returns:
            tuple: (success: bool, response_data: dict, status_code: int)
        """
        if headers is None:
            # Gateway requires digest in Authorization header for ALL requests
            headers = self.auth_helper.generate_headers(payload, include_digest=True)

        if expected_status is None:
            expected_status = [200, 202]

        # Extract pre-serialized body from headers
        serialized_body = headers.pop('serialized_body', None)
        if not serialized_body:
            # Fallback: serialize with same settings as auth_helper
            serialized_body = json.dumps(payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False)
        
        with self.client.post(
            name=step_name,
            url="/on_search",
            data=serialized_body.encode('utf-8'),
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
            catch_response=True
        ) as response:
            
            # Check for expected status codes
            if response.status_code not in expected_status:
                response.failure(f"{step_name} Failed: Expected {expected_status}, got {response.status_code}")
                return False, None, response.status_code
            
            # Try to parse response
            try:
                data = response.json() if response.content else {}
            except ValueError:
                # Response is not JSON (e.g., HTML error page)
                response.failure(f"{step_name} Failed: Non-JSON response (HTTP {response.status_code}): {response.text[:200]}")
                return False, None, response.status_code
            except Exception as e:
                response.failure(f"{step_name} Failed: Error parsing response: {str(e)}")
                return False, None, response.status_code
            
            # Validate response structure based on status code
            if response.status_code == 0:
                # Status 0 = Connection dropped/refused (no HTTP response sent)
                # This is valid DoS protection - server drops connection before responding
                # No response body to validate, consider it a success if it's in expected_status
                pass
            elif 200 <= response.status_code < 300:
                # Validate ACK structure for successful responses
                is_valid, error_msg = self._validate_ack_response(data, step_name)
                if not is_valid:
                    response.failure(error_msg)
                    return False, data, response.status_code
                
                # NOTE: Context and catalog validation skipped for /on_search ACK responses
                # In ONDC async flow, /on_search returns immediate ACK to BPP (without context/catalog)
                # The BAP receives the full catalog via separate callback from Gateway
                # Only validate catalog if context is present (indicating full response)
                if data.get('context') and validate_catalog:
                    # Validate context fields (expect 'on_search' action)
                    is_valid, error_msg = self._validate_context_fields(data, step_name, required_action='on_search')
                    if not is_valid:
                        response.failure(error_msg)
                        return False, data, response.status_code
                    
                    # Validate catalog structure
                    is_valid, error_msg = self._validate_on_search_catalog(data, step_name)
                    if not is_valid:
                        response.failure(error_msg)
                        return False, data, response.status_code
            else:
                # Validate error structure for 4xx/5xx responses
                is_valid, error_msg = self._validate_error_response(data, step_name, response.status_code)
                if not is_valid:
                    response.failure(error_msg)
                    return False, data, response.status_code
            
            response.success()
            return True, data, response.status_code
    
    def _validate_ack_response(self, data, test_name="Test"):
        """
        Validate ACK/NACK response from Gateway
        
        Args:
            data: Parsed JSON response
            test_name: Test case name for error messages
        
        Returns:
            tuple: (is_valid: bool, error_message: str or None)
        """
        if not data:
            return False, f"{test_name}: Empty response data"
        
        # Check for message.ack structure
        message = data.get('message')
        if not message:
            return False, f"{test_name}: Missing 'message' field in response"
        
        ack = message.get('ack')
        if not ack:
            return False, f"{test_name}: Missing 'message.ack' field in response"
        
        ack_status = ack.get('status')
        if not ack_status:
            return False, f"{test_name}: Missing 'message.ack.status' field"
        
        # Validate ACK/NACK
        if ack_status == 'NACK':
            error_info = data.get('error', {})
            error_code = error_info.get('code', 'unknown')
            error_msg = error_info.get('message', 'unknown')
            return False, f"{test_name}: Received NACK - Code: {error_code}, Message: {error_msg}"
        elif ack_status != 'ACK':
            return False, f"{test_name}: Invalid ack.status '{ack_status}', expected 'ACK' or 'NACK'"
        
        return True, None
    
    def _validate_on_search_catalog(self, data, test_name="on_search"):
        """
        Validate on_search response catalog structure
        
        Args:
            data: Parsed JSON response
            test_name: Test case name for error messages
        
        Returns:
            tuple: (is_valid: bool, error_message: str or None)
        """
        if not data:
            return False, f"{test_name}: Empty response data"
        
        # First validate it's an ACK
        is_ack, ack_error = self._validate_ack_response(data, test_name)
        if not is_ack:
            return False, ack_error
        
        # Validate catalog structure
        message = data.get('message', {})
        catalog = message.get('catalog')
        
        if not catalog:
            return False, f"{test_name}: Missing 'message.catalog' in on_search response"
        
        # Check for bpp/providers
        providers = catalog.get('bpp/providers')
        if not providers:
            return False, f"{test_name}: Missing 'catalog.bpp/providers' array"
        
        if not isinstance(providers, list):
            return False, f"{test_name}: 'catalog.bpp/providers' must be an array"
        
        if len(providers) == 0:
            return False, f"{test_name}: 'catalog.bpp/providers' array is empty"
        
        # Validate each provider has required fields
        for idx, provider in enumerate(providers):
            if not provider.get('id'):
                return False, f"{test_name}: Provider {idx} missing 'id'"
            
            if not provider.get('descriptor'):
                return False, f"{test_name}: Provider {idx} missing 'descriptor'"
            
            # Validate items array exists
            items = provider.get('items')
            if not items:
                return False, f"{test_name}: Provider {idx} missing 'items' array"
            
            if not isinstance(items, list):
                return False, f"{test_name}: Provider {idx} 'items' must be an array"
            
            # Validate each item
            for item_idx, item in enumerate(items):
                if not item.get('id'):
                    return False, f"{test_name}: Provider {idx}, Item {item_idx} missing 'id'"
                
                if not item.get('descriptor'):
                    return False, f"{test_name}: Provider {idx}, Item {item_idx} missing 'descriptor'"
        
        return True, None
    
    def _validate_context_fields(self, data, test_name="Test", required_action=None):
        """
        Validate context fields in response
        
        Args:
            data: Parsed JSON response
            test_name: Test case name
            required_action: Expected action in context (e.g., 'on_search')
        
        Returns:
            tuple: (is_valid: bool, error_message: str or None)
        """
        context = data.get('context')
        if not context:
            return False, f"{test_name}: Missing 'context' in response"
        
        # Check required context fields
        required_fields = ['domain', 'action', 'country', 'city', 'core_version', 
                          'bap_id', 'transaction_id', 'message_id', 'timestamp']
        
        for field in required_fields:
            if not context.get(field):
                return False, f"{test_name}: Missing required context field '{field}'"
        
        # Validate action if specified
        if required_action and context.get('action') != required_action:
            return False, f"{test_name}: Expected action '{required_action}', got '{context.get('action')}'"
        
        return True, None
    
    def _validate_error_response(self, data, test_name="Test", status_code=None):
        """
        Validate error response structure (4xx, 5xx responses)
        
        Args:
            data: Parsed JSON response
            test_name: Test case name for error messages
            status_code: HTTP status code for context
        
        Returns:
            tuple: (is_valid: bool, error_message: str or None)
        """
        if not data:
            return False, f"{test_name}: Empty error response (HTTP {status_code})"
        
        # Gateway uses different error formats:
        # Format 1 (ONDC spec): {"error": {"code": "...", "message": "..."}}
        # Format 2 (Gateway): {"error": "AUTH-ERROR", "error_code": "40101", "description": "..."}
        
        # Check for ONDC format
        error_info = data.get('error')
        if error_info and isinstance(error_info, dict):
            # ONDC nested format
            if not error_info.get('code'):
                return False, f"{test_name}: Missing 'error.code' in error response (HTTP {status_code})"
            if not error_info.get('message'):
                return False, f"{test_name}: Missing 'error.message' in error response (HTTP {status_code})"
            return True, None
        
        # Check for Gateway flat format
        if data.get('error') and data.get('error_code'):
            # Gateway format is valid
            return True, None
        
        # Check for alternative format with 'message' field
        if data.get('message'):
            # Valid alternative format
            return True, None
        
        # No recognized error format
        return False, f"{test_name}: Unrecognized error response format (HTTP {status_code}): {list(data.keys())}"
    
    def on_stop(self):
        """Cleanup proxy after test ends"""
        if self.proxy:
            self.proxy.stop_capture()
            self.proxy.quit()
