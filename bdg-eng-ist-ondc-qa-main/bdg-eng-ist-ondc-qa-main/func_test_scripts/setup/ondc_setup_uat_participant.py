#!/usr/bin/env python3
"""
Register test participant in UAT environment
UAT Lookup Server: http://35.200.145.160:8080
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import requests
import yaml
from tests.utils.registry_auth_client import RegistryAuthClient

def register_participant():
    """Register test participant via UAT admin API"""
    
    # Load config
    config_file = 'resources/registry/lookup/v3/test_lookup_functional.yml'
    with open(config_file, 'r') as f:
        config_data = yaml.safe_load(f)
        config = config_data.get('ondcRegistry', {})
    
    # UAT servers
    UAT_ADMIN_SERVER = "http://34.93.208.52"
    UAT_LOOKUP_SERVER = "http://35.200.145.160:8080"
    
    # Get credentials from config
    participant_id = config.get('participant_id')
    uk_id = config.get('uk_id')
    signing_public_key = config.get('signing_public_key')
    encryption_public_key = config.get('encryption_public_key')
    admin_username = config.get('admin_username', 'admin')
    admin_password = config.get('admin_password', 'admin')
    admin_token = config.get('admin_token')  # Static JWT token
    
    print(f"\n{'='*70}")
    print(f"  REGISTERING TEST PARTICIPANT IN UAT ENVIRONMENT")
    print(f"{'='*70}")
    print(f"  Participant ID: {participant_id}")
    print(f"  UK ID: {uk_id}")
    print(f"  UAT Admin Server: {UAT_ADMIN_SERVER}")
    print(f"  UAT Lookup Server: {UAT_LOOKUP_SERVER}")
    if admin_token:
        print(f"  Auth Method: Static JWT Token")
    else:
        print(f"  Auth Method: Username/Password")
    print(f"{'='*70}\n")
    
    # Step 1: Get admin token
    if admin_token:
        print("[1/3] Using static JWT token from config...")
        print(f"      ✅ Token available (expires: 2026-04-10)")
        token = admin_token
    else:
        print("[1/3] Authenticating with UAT admin API...")
        auth_client = RegistryAuthClient(UAT_ADMIN_SERVER, admin_username, admin_password)
    
        try:
            token = auth_client.get_token()
            print(f"      ✅ Token obtained: {token[:30]}...")
        except Exception as e:
            print(f"      ❌ Failed to get token: {e}")
            print(f"\n      Possible issues:")
            print(f"         • Admin credentials incorrect (check username/password)")
            print(f"         • UAT admin API not accessible at {UAT_ADMIN_SERVER}")
            print(f"         • Need to verify UAT admin endpoint URL")
            return False
    
    # Step 2: Register participant
    print(f"\n[2/3] Registering participant via admin/subscribe endpoint...")
    
    # Generate resource IDs
    key_id = uk_id
    location_id = f"loc_{uk_id[:8]}"
    uri_id = f"uri_{uk_id[:8]}"
    cred_gst_id = f"cred_{uk_id[:8]}_gst"
    cred_pan_id = f"cred_{uk_id[:8]}_pan"
    contact_tech_id = f"contact_{uk_id[:8]}_tech"
    contact_auth_id = f"contact_{uk_id[:8]}_auth"
    contact_biz_id = f"contact_{uk_id[:8]}_biz"
    
    # Admin API V3 payload
    payload = {
        "participant_id": participant_id,
        "action": "SUBSCRIBED",
        "credentials": [
            {
                "cred_id": cred_gst_id,
                "type": "GST",
                "cred_data": {
                    "pan": "ABCDE1234F",
                    "gstin": "22ABCDE1234F1Z5",
                    "business_name": "Test Lookup UAT Participant"
                }
            },
            {
                "cred_id": cred_pan_id,
                "type": "PAN",
                "cred_data": {
                    "pan": "ABCDE1234F",
                    "name": "UAT Test Owner"
                }
            }
        ],
        "contacts": [
            {
                "contact_id": contact_tech_id,
                "type": "TECHNICAL",
                "name": "UAT Tech Admin",
                "email": "tech@uat-test.example.com",
                "phone": "+919876543210",
                "address": "123 Tech Street, Bangalore",
                "designation": "Technical Lead",
                "is_primary": True
            },
            {
                "contact_id": contact_auth_id,
                "type": "AUTHORISED_SIGNATORY",
                "name": "Authorized Signatory",
                "email": "auth@uat-test.example.com",
                "phone": "+919876543211",
                "designation": "Authorized Signatory",
                "is_primary": False
            },
            {
                "contact_id": contact_biz_id,
                "type": "BUSINESS",
                "name": "Business Manager",
                "email": "business@uat-test.example.com",
                "phone": "+919876543212",
                "designation": "Business Head",
                "is_primary": False
            }
        ],
        "key": {
            "uk_id": key_id,
            "signing_public_key": signing_public_key,
            "encryption_public_key": encryption_public_key,
            "signed_algorithm": "ED25519",
            "encryption_algorithm": "X25519",
            "valid_from": "2026-02-01T00:00:00.000Z",
            "valid_until": "2030-12-31T23:59:59.000Z"
        },
        "location": {
            "location_id": location_id,
            "country": "IND",
            "city": ["std:080"],
            "type": "SERVICEABLE"
        },
        "uri": {
            "uri_id": uri_id,
            "type": "CALLBACK",
            "url": "https://httpbin.org/anything"  # Publicly accessible URL for UAT validation
        },
        "configs": [
            {
                "domain": "ONDC:RET10",
                "np_type": "BPP",
                "subscriber_id": participant_id,
                "location_id": location_id,
                "uri_id": uri_id,
                "key_id": key_id
            }
        ]
    }
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.post(
            f"{UAT_ADMIN_SERVER}/admin/subscribe",
            json=payload,
            headers=headers,
            timeout=30
        )
        
        print(f"      Status: {response.status_code}")
        
        if response.status_code in [200, 201]:
            print(f"      ✅ SUCCESS - Participant registered in UAT")
            print(f"\n      Response: {response.text[:200]}")
            return True
            
        elif response.status_code == 400:
            try:
                error = response.json()
                if "already exists" in str(error).lower():
                    print(f"      ✅ ALREADY EXISTS - Participant already in UAT")
                    print(f"         You can proceed with V3 lookup tests")
                    return True
                else:
                    print(f"      ⚠️  Registration failed: {error}")
                    return False
            except:
                print(f"      ⚠️  Registration failed (400): {response.text}")
                return False
                
        else:
            print(f"      ❌ Unexpected status {response.status_code}")
            print(f"      Response: {response.text}")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"      ❌ Connection failed to {UAT_ADMIN_SERVER}")
        print(f"\n      Troubleshooting:")
        print(f"         • Verify UAT admin server is accessible")
        print(f"         • Check if admin API requires different endpoint")
        print(f"         • May need VPN or network access")
        return False
        
    except Exception as e:
        print(f"      ❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

    # Step 3: Verify registration
    print(f"\n[3/3] Verifying participant is queryable via lookup...")
    
    try:
        verify_payload = {
            "country": "IND",
            "type": "BPP"
        }
        
        verify_response = requests.post(
            f"{UAT_LOOKUP_SERVER}/lookup",
            json=verify_payload,
            timeout=30
        )
        
        if verify_response.status_code == 200:
            participants = verify_response.json()
            if any(p.get('subscriber_id') == participant_id for p in participants):
                print(f"      ✅ Participant found in lookup results")
                print(f"\n{'='*70}")
                print(f"  ✅ REGISTRATION COMPLETE")
                print(f"{'='*70}")
                print(f"\n  Next steps:")
                print(f"     1. Run V3 functional tests:")
                print(f"        python driver.py --test ondc_reg_v3_lookup_functional \\")
                print(f"          --env ondcRegistry --iterations 1 --users 1 \\")
                print(f"          --autostart --autoquit 1")
                print(f"\n     2. Or run all UAT lookup tests:")
                print(f"        bash func_test_scripts/run_all_lookup_tests_uat.sh")
                print(f"\n{'='*70}\n")
                return True
            else:
                print(f"      ⚠️  Participant registered but not yet in lookup")
                print(f"          Database sync may take a moment")
                return True
        else:
            print(f"      ⚠️  Could not verify (status {verify_response.status_code})")
            print(f"          Participant may still be registered")
            return True
            
    except Exception as e:
        print(f"      ⚠️  Verification failed: {e}")
        print(f"          Participant may still be registered successfully")
        return True

if __name__ == '__main__':
    print("\n" + "="*70)
    print("  UAT PARTICIPANT REGISTRATION SCRIPT")
    print("="*70)
    print("  This script registers the test participant from")
    print("  resources/registry/lookup/v3/test_lookup_functional.yml")
    print("  in the UAT environment (http://35.200.145.160:8080)")
    print("="*70 + "\n")
    
    success = register_participant()
    sys.exit(0 if success else 1)
