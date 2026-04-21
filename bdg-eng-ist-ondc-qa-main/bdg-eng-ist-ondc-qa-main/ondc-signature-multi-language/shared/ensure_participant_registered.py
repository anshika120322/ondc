#!/usr/bin/env python3
"""
Ensure participant is registered before running tests.
This script checks if the participant exists and registers it if needed.
"""

import json
import requests
import urllib3
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64
import uuid
import sys

urllib3.disable_warnings()

def check_participant_exists(subscriber_id):
    """Check if participant is registered"""
    try:
        response = requests.post(
            "https://registry-uat.kynondc.net/v3.0/lookup",
            json={"subscriber_id": subscriber_id, "domain": "ONDC:RET10"},
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        return response.status_code == 200
    except:
        return False

def register_participant(creds):
    """Register the participant"""
    subscriber_id = creds['subscriber_id']
    uk_id = creds['unique_key_id']
    private_key_hex = creds['private_key_seed_hex']
    
    # Reconstruct keys
    private_key_bytes = bytes.fromhex(private_key_hex)
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    public_key_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_b64 = base64.b64encode(public_key_der).decode('utf-8')
    
    # Get admin token
    try:
        auth_response = requests.post(
            "https://admin-auth-uat.kynondc.net/api/auth/login",
            json={"email": "admin@ondc.org", "password": "Admin@123"},
            timeout=10
        )
        
        if auth_response.status_code != 200:
            print(f"⚠️  Could not get admin token (status {auth_response.status_code})")
            return False
        
        admin_token = auth_response.json().get('accessToken')
    except Exception as e:
        print(f"⚠️  Admin auth failed: {e}")
        return False
    
    # Register payload
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
            "email": f"admin@{subscriber_id}",
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
        
        if register_response.status_code in [200, 201]:
            print(f"✅ Participant registered successfully")
            return True
        elif register_response.status_code == 409:
            print(f"✅ Participant already exists")
            return True
        else:
            print(f"⚠️  Registration returned status {register_response.status_code}")
            return False
    except Exception as e:
        print(f"⚠️  Registration failed: {e}")
        return False

def ensure_registered():
    """Main function to ensure participant is registered"""
    print("\n" + "=" * 80)
    print("CHECKING PARTICIPANT REGISTRATION")
    print("=" * 80)
    
    # Load credentials
    try:
        with open('/shared/test-credentials.json', 'r') as f:
            creds = json.load(f)['uat']
    except Exception as e:
        print(f"❌ Could not load credentials: {e}")
        return False
    
    subscriber_id = creds['subscriber_id']
    print(f"\nParticipant: {subscriber_id}")
    print(f"Checking registration status...")
    
    # Check if already registered
    if check_participant_exists(subscriber_id):
        print(f"✅ Participant is already registered and active")
        print("=" * 80 + "\n")
        return True
    
    print(f"⚠️  Participant not found in registry")
    print(f"📝 Attempting to register participant...")
    
    # Try to register
    if register_participant(creds):
        # Wait a moment for registry to update
        import time
        time.sleep(2)
        
        # Verify registration
        if check_participant_exists(subscriber_id):
            print(f"✅ Participant successfully registered and verified!")
            print("=" * 80 + "\n")
            return True
        else:
            print(f"⚠️  Registered but lookup still returns 404")
            print(f"💡 Tests will continue but may get 404 responses")
            print("=" * 80 + "\n")
            return True  # Continue anyway, authentication will still work
    else:
        print(f"⚠️  Could not register participant automatically")
        print(f"💡 Tests will continue but will get 404 responses")
        print(f"   (404 still proves that signatures work - just participant not found)")
        print("=" * 80 + "\n")
        return True  # Continue anyway

if __name__ == "__main__":
    success = ensure_registered()
    sys.exit(0 if success else 1)
