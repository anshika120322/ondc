#!/usr/bin/env python3
"""
Re-register the existing test participant ctf-admin-c86cad.participant.ondc
"""

import json
import requests
import urllib3
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64
import uuid

urllib3.disable_warnings()

# Load existing credentials
with open('/shared/test-credentials.json', 'r') as f:
    creds = json.load(f)['uat']

subscriber_id = creds['subscriber_id']
uk_id = creds['unique_key_id']
private_key_hex = creds['private_key_seed_hex']

# Reconstruct keys from seed
private_key_bytes = bytes.fromhex(private_key_hex)
private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
public_key_raw = private_key.public_key().public_bytes_raw()

# Encode public key in DER/SPKI format (as required by ONDC)
public_key_der = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
public_key_b64 = base64.b64encode(public_key_der).decode('utf-8')

print("=" * 80)
print("RE-REGISTERING EXISTING PARTICIPANT")
print("=" * 80)
print(f"\nParticipant Details:")
print(f"  Subscriber ID: {subscriber_id}")
print(f"  UK ID: {uk_id}")
print(f"  Public Key (DER/b64): {public_key_b64}")

# Step 1: Get admin token
print(f"\n[STEP 1] Getting admin token...")
try:
    auth_response = requests.post(
        "https://admin-auth-uat.kynondc.net/api/auth/login",
        json={"email": "admin@ondc.org", "password": "Admin@123"},
        timeout=10
    )
    
    if auth_response.status_code != 200:
        print(f"❌ Admin auth failed: {auth_response.status_code}")
        print(f"Response: {auth_response.text}")
        exit(1)
    
    admin_token = auth_response.json().get('accessToken')
    print(f"✅ Admin token obtained")
except Exception as e:
    print(f"❌ Error getting admin token: {e}")
    exit(1)

# Step 2: Register participant with the admin/subscribe endpoint
register_payload = {
    "participant_id": subscriber_id,
    "action": "WHITELISTED",
    "configs": [{
        "np_type": "MSN",
        "subscriber_id": subscriber_id,
        "domain": "ONDC:RET10"
    }],
    "credentials": [{
        "cred_id": f"CRED-{uuid.uuid4().hex[:8]}",
        "type": "SIGNING",
        "cred_data": {
            "uk_id": uk_id,
            "signing_public_key": public_key_b64,
            "encryption_public_key": public_key_b64,
            "signed_algorithm": "ed25519",
            "encryption_algorithm": "x25519",
            "valid_from": datetime.now(timezone.utc).isoformat(),
            "valid_until": "2027-12-31T23:59:59.000Z"
        }
    }],
    "contacts": [{
        "contact_id": f"CONT-{uuid.uuid4().hex[:8]}",
        "type": "TECHNICAL",
        "name": "Admin User",
        "email": "admin@ctf-admin-c86cad.ondc",
        "phone": "+919876543210"
    }],
    "location": {
        "location_id": "LOC001",
        "type": "PRIMARY",
        "city": ["std:080"],
        "country": "IND"
    },
    "uri": {
        "uri_id": f"URI-{uuid.uuid4().hex[:8]}",
        "type": "CALLBACK",
        "url": f"https://{subscriber_id}"
    },
    "key": {
        "uk_id": uk_id,
        "signing_public_key": public_key_b64,
        "encryption_public_key": public_key_b64,
        "signed_algorithm": "ed25519",
        "encryption_algorithm": "x25519",
        "valid_from": datetime.now(timezone.utc).isoformat(),
        "valid_until": "2027-12-31T23:59:59.000Z"
    }
}

print(f"\n[STEP 2] Re-registering participant via admin endpoint...")
print(f"Endpoint: https://registry-uat.kynondc.net/admin/subscribe")

try:
    register_response = requests.post(
        "https://registry-uat.kynondc.net/admin/subscribe",
        json=register_payload,
        headers={
            'Authorization': f'Bearer {admin_token}',
            'Content-Type': 'application/json'
        },
        timeout=30
    )
    
    print(f"\nResponse Status: {register_response.status_code}")
    try:
        response_data = register_response.json()
        print(json.dumps(response_data, indent=2))
    except:
        print(register_response.text)
    
    if register_response.status_code in [200, 201]:
        print(f"\n✅ SUCCESS! Participant re-registered")
        
        # Verify with lookup
        print(f"\n[STEP 3] Verifying registration with lookup...")
        lookup_response = requests.post(
            "https://registry-uat.kynondc.net/v3.0/lookup",
            json={
                "subscriber_id": subscriber_id,
                "domain": "ONDC:RET10"
            },
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        print(f"Lookup Status: {lookup_response.status_code}")
        if lookup_response.status_code == 200:
            print(f"✅ Participant found in registry!")
            try:
                lookup_data = lookup_response.json()
                print(f"Participant info: {json.dumps(lookup_data[0] if isinstance(lookup_data, list) else lookup_data, indent=2)[:500]}")
            except:
                print(lookup_response.text[:500])
        else:
            print(f"⚠️  Lookup returned {lookup_response.status_code}: {lookup_response.text[:200]}")
    else:
        print(f"\n❌ Registration failed with status {register_response.status_code}")
        
except Exception as e:
    print(f"❌ Error during registration: {e}")
    import traceback
    traceback.print_exc()
    exit(1)

print("\n" + "=" * 80)
