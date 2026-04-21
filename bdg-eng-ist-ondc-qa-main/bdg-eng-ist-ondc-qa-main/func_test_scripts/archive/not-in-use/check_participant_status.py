#!/usr/bin/env python3
"""Check participant registration status"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import requests
import json
import yaml
from tests.utils.registry_auth_client import RegistryAuthClient

# Load config
with open('resources/registry/ondc_reg_lookup_functional.yml', 'r') as f:
    config = yaml.safe_load(f)['ondcRegistry']

participant_id = config['participant_id']
subscribe_host = 'http://34.14.152.92'
admin_username = config['admin_username']
admin_password = config['admin_password']

print(f"\n🔍 Checking participant: {participant_id}")
print(f"   Server: {subscribe_host}")
print("="*70)

# Get token
auth = RegistryAuthClient(subscribe_host, admin_username, admin_password)
token = auth.get_token()

# Query admin lookup endpoint
response = requests.get(
    f'{subscribe_host}/admin/lookup',
    params={'participant_id': participant_id},
    headers={'Authorization': f'Bearer {token}'},
    timeout=10
)

print(f"\nQuery: GET /admin/lookup?participant_id={participant_id}")
print(f"Status: {response.status_code}\n")

if response.status_code == 200:
    data = response.json()
    if isinstance(data, list) and len(data) > 0:
        for idx, participant in enumerate(data):
            print(f"📋 Result #{idx+1}:")
            print(f"   Participant ID: {participant.get('participant_id')}")
            print(f"   Status: {participant.get('status')} ✅" if participant.get('status') == 'SUBSCRIBED' else f"   Status: {participant.get('status')}")
            print(f"   Type: {participant.get('np_type')}")
            print(f"   Domain: {participant.get('domain')}")
            
            key_data = participant.get('key') or participant.get('keys', [{}])[0] if isinstance(participant.get('keys'), list) else {}
            print(f"   UK ID: {key_data.get('uk_id', 'N/A')}")
            print(f"   Created: {participant.get('created_at', 'N/A')}")
            print()
    else:
        print(f"❌ No participant found")
        print(json.dumps(data, indent=2))
else:
    print(f"❌ Error: {response.status_code}")
    print(response.text)
