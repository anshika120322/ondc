#!/usr/bin/env python3
"""
Generate a fresh ONDC ed25519 signature for a /confirm request.

Usage:
    python func_test_scripts/gen_confirm_signature.py           # print headers only
    python func_test_scripts/gen_confirm_signature.py --send    # print headers + send request
    python func_test_scripts/gen_confirm_signature.py --config resources/gateway/ondc_gateway_confirm_functional.yml
"""
import sys
import os
import time
import uuid
import base64
import json
import argparse
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml
from tests.utils.ondc_auth_helper import ONDCAuthHelper


def _load_private_key_seed(raw: str) -> bytes:
    """Parse private_key_seed from config — accepts hex (64 chars) or base64 PKCS#8."""
    if len(raw) == 64:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    # Treat as base64-encoded PKCS#8 DER; last 32 bytes are the ed25519 seed
    pkcs8 = base64.b64decode(raw)
    if len(pkcs8) < 32:
        raise ValueError(f"Decoded key too short: {len(pkcs8)} bytes")
    return pkcs8[-32:]


def _build_confirm_payload(cfg: dict) -> dict:
    """Build a minimal but valid /confirm payload from config values."""
    now_ts = datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    txn_id = f"txn-{uuid.uuid4().hex[:12]}"
    msg_id = f"msg-{uuid.uuid4().hex[:12]}"
    order_id = f"order-{uuid.uuid4().hex[:8]}"

    participant_id = cfg['participant_id']
    bap_id  = cfg.get('bap_id', participant_id)
    bap_uri = cfg.get('bap_uri', '')
    bpp_id  = cfg.get('bpp_id', 'seller-1.bpp.ondc')
    bpp_uri = cfg.get('bpp_uri', '')

    domains = cfg.get('domains', ['ONDC:RET10'])
    domain  = domains[0] if domains else 'ONDC:RET10'

    cities = cfg.get('cities', ['std:080'])
    city   = cities[0] if cities else 'std:080'

    providers  = cfg.get('test_providers', [{'id': 'IGO_Seller_0001', 'location_id': 'store-location-001'}])
    provider   = providers[0]
    provider_id    = provider.get('id', 'IGO_Seller_0001')
    location_id    = provider.get('location_id', 'store-location-001')

    items       = cfg.get('test_items', [{'id': 'item-001', 'price': '450.00', 'name': 'Test Item'}])
    item        = items[0]
    item_id     = item.get('id', 'item-001')
    item_price  = item.get('price', '450.00')

    payment_types = cfg.get('payment_types', [{'type': 'ON-ORDER', 'status': 'PAID', 'collected_by': 'BAP'}])
    pmt = payment_types[0]

    locations = cfg.get('test_locations', [{'city': city, 'gps': '12.9492953,77.7019878', 'area_code': '560001'}])
    loc = locations[0]

    return {
        "context": {
            "domain": domain,
            "action": "confirm",
            "country": "IND",
            "city": city,
            "core_version": str(cfg.get('core_version', '1.2.0')),
            "bap_id": bap_id,
            "bap_uri": bap_uri,
            "bpp_id": bpp_id,
            "bpp_uri": bpp_uri,
            "transaction_id": txn_id,
            "message_id": msg_id,
            "timestamp": now_ts,
            "ttl": "PT30S"
        },
        "message": {
            "order": {
                "id": order_id,
                "state": "Created",
                "provider": {
                    "id": provider_id,
                    "locations": [{"id": location_id}]
                },
                "items": [
                    {
                        "id": item_id,
                        "quantity": {"count": 1}
                    }
                ],
                "billing": {
                    "name": "Test Buyer",
                    "address": {
                        "door": "1A",
                        "name": "Test Street",
                        "locality": "Koramangala",
                        "city": "Bengaluru",
                        "state": "Karnataka",
                        "country": "IND",
                        "area_code": loc.get('area_code', '560001')
                    },
                    "email": "test.buyer@example.com",
                    "phone": "+91-9876543210",
                    "created_at": now_ts,
                    "updated_at": now_ts
                },
                "fulfillments": [
                    {
                        "id": "1",
                        "type": "Delivery",
                        "end": {
                            "location": {
                                "gps": loc.get('gps', '12.9492953,77.7019878'),
                                "address": {
                                    "door": "1A",
                                    "name": "Test Street",
                                    "locality": "Koramangala",
                                    "city": "Bengaluru",
                                    "state": "Karnataka",
                                    "country": "IND",
                                    "area_code": loc.get('area_code', '560001')
                                }
                            },
                            "contact": {
                                "phone": "+91-9876543210",
                                "email": "test.buyer@example.com"
                            }
                        }
                    }
                ],
                "quote": {
                    "price": {"currency": "INR", "value": item_price},
                    "breakup": [
                        {
                            "title": item.get('name', 'Test Item'),
                            "price": {"currency": "INR", "value": item_price},
                            "@ondc/org/item_id": item_id,
                            "@ondc/org/item_quantity": {"count": 1},
                            "@ondc/org/title_type": "item"
                        }
                    ],
                    "ttl": "P1D"
                },
                "payment": {
                    "uri": "",
                    "tl_method": "http/get",
                    "params": {
                        "currency": "INR",
                        "transaction_id": f"payment-txn-{uuid.uuid4().hex[:8]}",
                        "amount": item_price
                    },
                    "status": pmt.get('status', 'PAID'),
                    "type": pmt.get('type', 'ON-ORDER'),
                    "collected_by": pmt.get('collected_by', 'BAP'),
                    "@ondc/org/buyer_app_finder_fee_type": "percent",
                    "@ondc/org/buyer_app_finder_fee_amount": "3.0",
                    "@ondc/org/settlement_details": []
                }
            }
        }
    }


def main():
    parser = argparse.ArgumentParser(description='Generate fresh ONDC /confirm signature')
    parser.add_argument('--config', default='resources/gateway/ondc_gateway_confirm_functional.yml',
                        help='Path to gateway config YAML (default: confirm functional config)')
    parser.add_argument('--send', action='store_true',
                        help='Send the request to the gateway after generating headers')
    args = parser.parse_args()

    config_path = args.config
    if not os.path.isabs(config_path):
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), config_path)

    print('=' * 80)
    print('ONDC /confirm — FRESH SIGNATURE GENERATOR')
    print('=' * 80)
    print(f'Config: {config_path}')

    with open(config_path, 'r') as f:
        raw_yaml = yaml.safe_load(f)

    # Determine YAML root key
    cfg_key = next(iter(raw_yaml))
    cfg = raw_yaml[cfg_key]
    print(f'Config key: {cfg_key}')

    host = cfg['host'].rstrip('/')
    participant_id = cfg['participant_id']
    uk_id          = cfg['uk_id']
    private_key_seed = _load_private_key_seed(cfg['private_key_seed'])

    print(f'Gateway: {host}')
    print(f'Participant ID: {participant_id}')
    print(f'UK ID: {uk_id}')
    print(f'Key seed (first 8 bytes hex): {private_key_seed[:8].hex()}...')
    print()

    # Create auth helper
    auth = ONDCAuthHelper(participant_id, uk_id, private_key_seed)
    print(f'[OK] Auth helper created | Public key: {auth.get_public_key_base64()[:40]}...')

    # Build payload
    payload = _build_confirm_payload(cfg)
    print(f'[OK] Payload built | txn_id={payload["context"]["transaction_id"]}')
    print()

    # Generate headers
    headers = auth.generate_headers(payload)

    print('=' * 80)
    print('GENERATED HEADERS')
    print('=' * 80)
    print(f'Authorization:\n  {headers["Authorization"]}')
    print()
    print(f'Digest: {headers["Digest"]}')
    print(f'Content-Type: {headers["Content-Type"]}')
    print()

    serialized_body = headers.pop('serialized_body')

    print('=' * 80)
    print('SERIALIZED PAYLOAD (use this exact body when sending manually)')
    print('=' * 80)
    print(serialized_body)
    print()

    if args.send:
        import requests as req
        url = f'{host}/confirm'
        print('=' * 80)
        print(f'SENDING POST {url}')
        print('=' * 80)
        try:
            response = req.post(url, data=serialized_body, headers=headers, timeout=30)
            print(f'Status: {response.status_code}')
            print('Response Headers:')
            for k, v in response.headers.items():
                print(f'  {k}: {v}')
            print()
            print('Response Body:')
            try:
                print(json.dumps(response.json(), indent=2))
            except Exception:
                print(response.text[:1000])
        except Exception as exc:
            print(f'[ERROR] Request failed: {exc}')
            return 1

    print()
    print('Done.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
