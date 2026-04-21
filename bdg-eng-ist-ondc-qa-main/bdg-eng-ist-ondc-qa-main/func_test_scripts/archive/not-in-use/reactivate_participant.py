#!/usr/bin/env python3
"""Reactivate test participant by updating to SUBSCRIBED status"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import requests
import yaml
import json
from tests.utils.registry_auth_client import RegistryAuthClient

# Load config
with open('resources/registry/lookup/v3/test_lookup_functional.yml', 'r') as f:
    config = yaml.safe_load(f)['ondcRegistry']

participant_id = config['participant_id']
uk_id = config['uk_id']
subscribe_host = 'http://34.14.152.92'
admin_username = config['admin_username']
admin_password = config['admin_password']

print(f"\n{'='*70}")
print(f"Reactivating Participant")
print(f"{'='*70}")
print(f"Participant: {participant_id}")
print(f"UK ID: {uk_id}")
print(f"Server: {subscribe_host}")
print(f"{'='*70}\n")

# Get token
print("[1/2] Getting admin token...")
auth = RegistryAuthClient(subscribe_host, admin_username, admin_password)
token = auth.get_token()
print(f"✅ Token obtained\n")

# Try to PATCH to SUBSCRIBED status
print("[2/2] Updating participant to SUBSCRIBED status...")

payload = {
    "participant_id": participant_id,
    "action": "SUBSCRIBED"
}

headers = {
    'Authorization': f'Bearer {token}',
    'Content-Type': 'application/json'
}

response = requests.patch(
    f"{subscribe_host}/admin/subscribe",
    json=payload,
    headers=headers,
    timeout=30
)

print(f"Response Status: {response.status_code}")
print(f"Response Body: {response.text}\n")

if response.status_code in [200, 201]:
    print("✅ SUCCESS: Participant updated to SUBSCRIBED")
    print(f"\n📝 Next steps:")
    print(f"   1. Wait 5-10 seconds for cache/DB sync")
    print(f"   2. Verify with: python func_test_scripts/ensure_test_participant.py --check-only")
    print(f"   3. Run negative tests")
    print(f"{'='*70}\n")
    sys.exit(0)
else:
    print(f"❌ FAILED: Could not update participant")
    print(f"\nTrying alternative: Complete re-create with new configs...\n")
    
    # Try updating with full payload
    full_payload = {
        "participant_id": participant_id,
        "action": "SUBSCRIBED",
        "key": {
            "uk_id": uk_id,
            "signing_public_key": config.get('signing_public_key'),
            "encryption_public_key": config.get('encryption_public_key'),
            "signed_algorithm": "ED25519",
            "encryption_algorithm": "X25519"
        },
        "location": {
            "country": "IND",
            "city": ["std:080"]
        },
        "configs": [{
            "domain": "ONDC:RET10",
            "np_type": "BPP"
        }]
    }
    
    response2 = requests.patch(
        f"{subscribe_host}/admin/subscribe",
        json=full_payload,
        headers=headers,
        timeout=30
    )
    
    print(f"Response Status: {response2.status_code}")
    print(f"Response Body: {response2.text}\n")
    
    if response2.status_code in [200, 201]:
        print("✅ SUCCESS: Participant fully updated")
        sys.exit(0)
    else:
        print("❌ FAILED: Could not update participant")
        sys.exit(1)
