import json
import logging
import os
import uuid
from datetime import datetime, timezone

import yaml
from locust import TaskSet
from common_test_foundation.lib.proxy.proxy_server import ProxyServer
from common_test_foundation.helpers.taskset_handler import RESCHEDULE_TASK, taskset_handler
from tests.utils.ondc_auth_helper import ONDCAuthHelper

logger = logging.getLogger(__name__)

"""
Base class for ONDC Gateway Select API tests
Contains shared functionality: config loading, auth setup, select/on_select payload generation.
Models structure after gateway_init_base.py
"""


@taskset_handler(RESCHEDULE_TASK)
class GatewaySelectBase(TaskSet):
    """Base class with shared setup and helper methods for Gateway Select tests"""

    def on_start(self):
        """Initialize proxy, load config, setup authentication."""
        self.step_name = 'ON_START'

        if getattr(self, 'enable_proxy', False):
            self.proxy = ProxyServer()
            self.proxy.start_capture(trx_id=self.step_name)
            self.client.verify = self.proxy.get_certificate()
            self.client.proxies = self.proxy.get_http_proxy_config()
        else:
            self.proxy = None

        config_file = getattr(self, 'config_file', 'resources/gateway/ondc_gateway_select_functional.yml')
        tenant_name = getattr(self, 'tenant_name', 'ondcGW')
        config = self._load_config(config_file, tenant_name)

        participant_id, uk_id, private_key_seed = self._setup_auth(config)

        self.auth_helper = ONDCAuthHelper(
            participant_id=participant_id,
            uk_id=uk_id,
            private_key_seed=private_key_seed
        )

        # Core config — all values loaded from YAML; no environment-specific defaults
        self.select_domains = config.get('domains', ["ONDC:RET10", "ONDC:RET16"])
        self.cities = config.get('cities', ["std:080"])
        self.core_version = config.get('core_version', '1.2.0')
        self.bap_id = config.get('bap_id')
        self.bap_uri = config.get('bap_uri')
        self.bpp_id = config.get('bpp_id')
        self.bpp_uri = config.get('bpp_uri')

        # Select-specific config data
        self.fulfillment_types = config.get('fulfillment_types', [])
        self.test_providers = config.get('test_providers', [])
        self.test_items = config.get('test_items', [])
        self.test_locations = config.get('test_locations', [])

        logger.info(f"ON_START completed successfully for Select tests. wait_time={getattr(self, 'wait_time', 'NOT SET')}")

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
        """Extract and validate auth credentials from config."""
        participant_id = config.get('participant_id')
        if not participant_id:
            participant_id = config.get('bap_id', 'participant-1.participant.ondc')
            logger.info(f"Using bap_id as participant_id: {participant_id}")

        uk_id = config.get('uk_id', 'buyer-key-001')
        if not uk_id:
            uk_id = config.get('uk_id', 'buyer-key-001')
            logger.info(f"Using uk_id from config: {uk_id}")

        private_key_hex = config.get('private_key_seed')
        if not private_key_hex:
            raise ValueError("private_key_seed is required in config. Do not use hardcoded keys.")

        private_key_seed = None
        if isinstance(private_key_hex, str):
            if len(private_key_hex) == 64:
                try:
                    private_key_seed = bytes.fromhex(private_key_hex)
                    logger.info("Using private key from config (hex format)")
                except ValueError:
                    pass

            if private_key_seed is None:
                try:
                    import base64
                    pkcs8_bytes = base64.b64decode(private_key_hex)
                    if len(pkcs8_bytes) >= 32:
                        private_key_seed = pkcs8_bytes[-32:]
                        logger.info("Using private key from config (base64 PKCS#8 format)")
                except Exception:
                    pass

        if private_key_seed is None:
            raise ValueError(
                f"Invalid private_key_seed in config. Expected a 64-char hex string or "
                f"base64-encoded PKCS#8 key, got {len(private_key_hex) if private_key_hex else 0} chars"
            )

        return participant_id, uk_id, private_key_seed

    def _generate_select_payload(
        self,
        domain=None,
        city=None,
        transaction_id=None,
        message_id=None,
        provider_id=None,
        item_id=None,
        item_quantity=1,
        fulfillment_type=None,
        delivery_gps=None,
        items=None,
    ):
        """
        Generate a /select payload (BAP selects items from search catalog).

        /select sits between /search and /init in the ONDC order flow:
          search → on_search → SELECT → on_select → init → on_init → confirm → on_confirm

        Key schema rules for /select:
        - `bpp_id` and `bpp_uri` are REQUIRED in context (routing the request to BPP)
        - `message.order.provider` with `id` and `locations` is required
        - `message.order.items` with `id` and `quantity.count`
        - `message.order.fulfillments` with delivery destination `end.location.gps`
        - NO billing, payment, or quote at this stage (those come in /init and /on_select)

        Args:
            domain: ONDC domain. Defaults to first in config list.
            city: City std code. Defaults to first in config list.
            transaction_id: Override transaction ID. Auto-generated if None.
            message_id: Override message ID. Auto-generated if None.
            provider_id: Seller/provider ID. Defaults to first test_provider.
            item_id: Single item ID. Ignored if `items` is provided.
            item_quantity: Quantity for the single item. Ignored if `items` is provided.
            fulfillment_type: Fulfillment type string (e.g. 'Delivery'). Not included if None.
            delivery_gps: GPS string for delivery destination. Defaults from config.
            items: List of item dicts [{id, quantity: {count}}]. Overrides item_id/item_quantity.

        Returns:
            dict: Select payload
        """
        import random

        txn_id = transaction_id or f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-{uuid.uuid4().hex[:12]}"

        selected_domain = domain or (random.choice(self.select_domains) if self.select_domains else "ONDC:RET10")
        selected_city = city or (random.choice(self.cities) if self.cities else "std:080")

        # Provider resolution
        if provider_id is None:
            if self.test_providers:
                provider = self.test_providers[0]
                provider_id = provider.get('id', 'IGO_Seller_0001')
                store_location_id = provider.get('location_id', 'store-location-001')
            else:
                provider_id = 'IGO_Seller_0001'
                store_location_id = 'store-location-001'
        else:
            # Find matching provider location from config
            store_location_id = 'store-location-001'
            for p in self.test_providers:
                if p.get('id') == provider_id:
                    store_location_id = p.get('location_id', 'store-location-001')
                    break

        # Item resolution
        if items is None:
            if item_id is None:
                item_id = self.test_items[0].get('id', 'item-001') if self.test_items else 'item-001'
            items = [{"id": item_id, "quantity": {"count": item_quantity}}]

        # GPS for delivery destination
        if delivery_gps is None:
            delivery_gps = self.test_locations[0].get('gps', '12.9492953,77.7019878') if self.test_locations else '12.9492953,77.7019878'

        fulfillment = {
            "id": "F1",
            "end": {
                "location": {
                    "gps": delivery_gps
                }
            }
        }
        if fulfillment_type:
            fulfillment["type"] = fulfillment_type

        return {
            "context": {
                "domain": selected_domain,
                "action": "select",
                "country": "IND",
                "city": selected_city,
                "core_version": self.core_version,
                "bap_id": self.bap_id,
                "bap_uri": self.bap_uri,
                "bpp_id": self.bpp_id,     # REQUIRED for /select
                "bpp_uri": self.bpp_uri,   # REQUIRED for /select
                "transaction_id": txn_id,
                "message_id": msg_id,
                "timestamp": datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                "ttl": "PT30S"
            },
            "message": {
                "order": {
                    "provider": {
                        "id": provider_id,
                        "locations": [{"id": store_location_id}]
                    },
                    "items": items,
                    "fulfillments": [fulfillment]
                }
            }
        }

    def _generate_on_select_payload(self, transaction_id=None, message_id=None):
        """
        Generate an /on_select callback payload (BPP responds with quote for selected items).

        /on_select is the BPP's response to /select — it provides:
        - The confirmed provider and items list
        - A quote with price breakdown (item price + delivery + taxes + discounts)
        - Fulfillment details (type and tracking flag)

        Key schema rules for /on_select:
        - Context: action = "on_select", bap_id/bap_uri identify the BAP to route to
        - `message.order.provider` with id only (no locations needed in response)
        - `message.order.items` with id and quantity
        - `message.order.quote` is REQUIRED with:
          - `price.currency` + `price.value` (total)
          - `breakup` array with @ondc/org/item_id, title, @ondc/org/title_type, price
          - `ttl` (validity duration e.g. "P1D")
        - `message.order.fulfillments` with type and tracking flag

        Args:
            transaction_id: Override transaction ID. Auto-generated if None.
            message_id: Override message ID. Auto-generated if None.

        Returns:
            dict: on_select callback payload
        """
        import random

        txn_id = transaction_id or f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-{uuid.uuid4().hex[:12]}"

        # Provider resolution from config
        provider_id = self.test_providers[0].get('id') if self.test_providers else 'IGO_Seller_0001'

        # Item resolution from config
        item = self.test_items[0] if self.test_items else {}
        item_id = item.get('id', 'item-001')
        item_name = item.get('name', 'Test Item')
        item_price = item.get('price', '450.00')

        # Fulfillment type from config
        fulfillment_type = self.fulfillment_types[0] if self.fulfillment_types else 'Delivery'

        # Compute a simple delivery fee and total
        delivery_charge = "50.00"
        try:
            total_value = f"{float(item_price) + float(delivery_charge):.2f}"
        except (ValueError, TypeError):
            total_value = "500.00"

        return {
            "context": {
                "domain": random.choice(self.select_domains) if self.select_domains else "ONDC:RET10",
                "action": "on_select",
                "country": "IND",
                "city": random.choice(self.cities) if self.cities else "std:080",
                "core_version": self.core_version,
                "bap_id": self.bap_id,
                "bap_uri": self.bap_uri,
                "bpp_id": self.bpp_id,
                "bpp_uri": self.bpp_uri,
                "transaction_id": txn_id,
                "message_id": msg_id,
                "timestamp": datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                "ttl": "PT30S"
            },
            "message": {
                "order": {
                    "provider": {
                        "id": provider_id
                    },
                    "items": [
                        {
                            "id": item_id,
                            "quantity": {"count": 1}
                        }
                    ],
                    "quote": {
                        "price": {
                            "currency": "INR",
                            "value": total_value
                        },
                        "breakup": [
                            {
                                "@ondc/org/item_id": item_id,
                                "@ondc/org/item_quantity": {"count": 1},
                                "title": item_name,
                                "@ondc/org/title_type": "item",
                                "price": {"currency": "INR", "value": item_price},
                                "item": {"price": {"currency": "INR", "value": item_price}}
                            },
                            {
                                "@ondc/org/item_id": item_id,
                                "title": "Delivery charges",
                                "@ondc/org/title_type": "delivery",
                                "price": {"currency": "INR", "value": delivery_charge}
                            }
                        ],
                        "ttl": "P1D"
                    },
                    "fulfillments": [
                        {
                            "id": "F1",
                            "type": fulfillment_type,
                            "tracking": False
                        }
                    ]
                }
            }
        }

    def _send_select_request(self, step_name, payload, headers=None, expected_status=None):
        """
        Helper to send /select requests with consistent auth and error handling.

        Args:
            step_name: Locust step name (appears in reports).
            payload: Request payload dict.
            headers: Optional pre-built headers (auth generated if None).
            expected_status: List of acceptable status codes (default: [200, 202]).

        Returns:
            tuple: (success: bool, response_data: dict, status_code: int)
        """
        if headers is None:
            headers = self.auth_helper.generate_headers(payload)

        if expected_status is None:
            expected_status = [200, 202]

        serialized_body = headers.pop('serialized_body', None)
        if not serialized_body:
            serialized_body = json.dumps(payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False)

        with self.client.post(
            name=step_name,
            url="/select",
            data=serialized_body.encode('utf-8'),
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
            catch_response=True
        ) as response:

            if response.status_code not in expected_status:
                response.failure(f"{step_name} Failed: Expected {expected_status}, got {response.status_code}")
                return False, None, response.status_code

            try:
                data = response.json() if response.content else {}
                response.success()
                return True, data, response.status_code
            except Exception as e:
                response.failure(f"{step_name} Failed: Error parsing response: {str(e)}")
                return False, None, response.status_code

    def _send_on_select_request(self, step_name, payload, headers=None, expected_status=None):
        """
        Helper to send /on_select callback requests with consistent auth and error handling.

        Args:
            step_name: Locust step name.
            payload: on_select callback payload dict.
            headers: Optional pre-built headers (auth generated if None).
            expected_status: List of acceptable status codes (default: [200, 202]).

        Returns:
            tuple: (success: bool, response_data: dict, status_code: int)
        """
        if headers is None:
            headers = self.auth_helper.generate_headers(payload)

        if expected_status is None:
            expected_status = [200, 202]

        serialized_body = headers.pop('serialized_body', None)
        if not serialized_body:
            serialized_body = json.dumps(payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False)

        with self.client.post(
            name=step_name,
            url="/on_select",
            data=serialized_body.encode('utf-8'),
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
            catch_response=True
        ) as response:

            if response.status_code not in expected_status:
                response.failure(f"{step_name} Failed: Expected {expected_status}, got {response.status_code}")
                return False, None, response.status_code

            try:
                data = response.json() if response.content else {}
                response.success()
                return True, data, response.status_code
            except Exception as e:
                response.failure(f"{step_name} Failed: Error parsing response: {str(e)}")
                return False, None, response.status_code

    def _validate_ack_response(self, response_obj, data, test_name):
        """
        Validate ACK/NACK response from Gateway.

        Args:
            response_obj: Locust response object.
            data: Parsed JSON response.
            test_name: Test case name for error messages.

        Returns:
            bool: True if valid ACK, False otherwise.
        """
        ack_status = data.get('message', {}).get('ack', {}).get('status')

        if ack_status == 'NACK':
            error_msg = data.get('error', {}).get('message', 'unknown')
            response_obj.failure(f"{test_name} Failed: Received NACK - {error_msg}")
            return False
        elif ack_status != 'ACK':
            response_obj.failure(f"{test_name} Failed: Expected ACK, got {data}")
            return False

        return True

    def on_stop(self):
        """Cleanup proxy after test ends."""
        if self.proxy:
            self.proxy.stop_capture()
