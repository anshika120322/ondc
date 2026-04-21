#!/usr/bin/env python3
"""
Test DNS Validation and Existing Participant Operations in UAT
Helps understand what operations work with/without DNS TXT records
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import requests
import json
import yaml
from tests.utils.ondc_auth_helper import ONDCAuthHelper

# UAT Configuration
UAT_ADMIN_SERVER = "http://34.93.208.52"
EXISTING_PARTICIPANT = "test-qa-0d4b8d2a.participant.ondc"

def load_config():
    """Load credentials from config"""
    config_file = 'resources/registry/subscribe/test_subscribe_functional.yml'
    with open(config_file, 'r') as f:
        config_data = yaml.safe_load(f)
        return config_data.get('ondcRegistry', {})

def test_v3_patch_existing_participant(config):
    """Test V3 PATCH on existing participant (should work without DNS issues)"""
    print("\n" + "="*80)
    print("TEST 1: V3 PATCH - Update Existing Participant")
    print("="*80)
    print("Hypothesis: PATCH operations should work even with DNS validation")
    print("           because participant already exists and was validated\n")
    
    # Build PATCH payload to update contacts
    payload = {
        "request_id": "test-dns-patch-001",
        "participant_id": config['participant_id'],
        "uk_id": config['uk_id'],
        "contacts": [
            {
                "contact_id": "contact_test_001",
                "type": "TECHNICAL",
                "name": "Updated Technical Contact",
                "email": "tech-updated@test.com",
                "phone": "+919999999999",
                "designation": "Tech Lead",
                "is_primary": True
            }
        ]
    }
    
    # Generate V3 signature
    private_key_bytes = bytes.fromhex(config['private_key_seed'])
    auth_helper = ONDCAuthHelper(
        participant_id=config['participant_id'],
        uk_id=config['uk_id'],
        private_key_seed=private_key_bytes
    )
    
    headers = auth_helper.generate_headers(payload)
    
    # Send PATCH request
    url = f"{UAT_ADMIN_SERVER}/api/v3/subscribe"
    print(f"PATCH {url}")
    print(f"Payload: {json.dumps(payload, indent=2)[:200]}...")
    
    try:
        response = requests.patch(url, json=payload, headers=headers, timeout=30)
        print(f"\nResponse Status: {response.status_code}")
        print(f"Response Body:")
        print(json.dumps(response.json(), indent=2))
        
        if response.status_code == 200:
            print("\n✅ RESULT: V3 PATCH works on existing participant!")
            print("   This means we can test UPDATE operations even with DNS validation")
            return True
        elif "DNS validation" in response.text:
            print("\n❌ RESULT: DNS validation blocks even PATCH operations")
            print("   Dev team needs to disable DNS validation for test participants")
            return False
        else:
            print(f"\n⚠️  RESULT: PATCH failed for other reason: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        return False

def test_admin_patch_deactivate(config):
    """Test admin PATCH to change status"""
    print("\n" + "="*80)
    print("TEST 2: Admin PATCH - Change Participant Status")
    print("="*80)
    print("Hypothesis: Admin API can deactivate/reactivate participant")
    print("           allowing us to test lifecycle transitions\n")
    
    payload = {
        "participant_id": config['participant_id'],
        "action": "INACTIVE"  # Try to deactivate
    }
    
    admin_token = config['admin_token']
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }
    
    url = f"{UAT_ADMIN_SERVER}/admin/subscribe"
    print(f"PATCH {url}")
    print(f"Action: Change status to INACTIVE")
    
    try:
        response = requests.patch(url, json=payload, headers=headers, timeout=30)
        print(f"\nResponse Status: {response.status_code}")
        print(f"Response Body:")
        print(json.dumps(response.json(), indent=2))
        
        if response.status_code == 200:
            print("\n✅ RESULT: Admin PATCH works! Can change status")
            print("   We can test: WHITELISTED ↔ SUBSCRIBED ↔ INACTIVE transitions")
            return True
        else:
            print(f"\n⚠️  RESULT: Admin PATCH failed: {response.status_code}")
            print("   May need different action or endpoint")
            return False
            
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        return False

def test_dns_validation_new_participant(config):
    """Test DNS validation with a new random participant"""
    print("\n" + "="*80)
    print("TEST 3: DNS Validation - Try Creating New Participant")
    print("="*80)
    print("Hypothesis: UAT blocks new participants without DNS TXT records\n")
    
    import uuid
    from nacl.signing import SigningKey
    from nacl.encoding import Base64Encoder
    import base64
    
    # Generate fresh keys for new participant
    signing_key = SigningKey.generate()
    signing_key_bytes = bytes(signing_key)
    
    new_participant_id = f"test-dns-check-{str(uuid.uuid4())[:6]}.participant.ondc"
    new_uk_id = str(uuid.uuid4())
    
    test_payload = {
        "request_id": str(uuid.uuid4()),
        "participant_id": new_participant_id,
        "uk_id": new_uk_id,
        "key": {
            "uk_id": new_uk_id,
            "signing_public_key": signing_key.verify_key.encode(encoder=Base64Encoder).decode('utf-8'),
            "encryption_public_key": base64.b64encode(os.urandom(32)).decode('utf-8'),
            "signed_algorithm": "ED25519",
            "encryption_algorithm": "X25519",
            "valid_from": "2026-03-11T00:00:00.000Z",
            "valid_until": "2027-03-11T23:59:59.000Z"
        }
    }
    
    # Generate signature
    auth_helper = ONDCAuthHelper(
        participant_id=new_participant_id,
        uk_id=new_uk_id,
        private_key_seed=signing_key_bytes
    )
    
    headers = auth_helper.generate_headers(test_payload)
    
    url = f"{UAT_ADMIN_SERVER}/api/v3/subscribe"
    print(f"POST {url}")
    print(f"New Participant: {new_participant_id}")
    
    try:
        response = requests.post(url, json=test_payload, headers=headers, timeout=30)
        print(f"\nResponse Status: {response.status_code}")
        response_body = response.json()
        print(f"Response Body:")
        print(json.dumps(response_body, indent=2))
        
        error_msg = response_body.get('error', {}).get('message', '')
        
        if "DNS validation failed" in error_msg or "ondc-signature" in error_msg:
            print("\n✅ CONFIRMED: UAT enforces DNS validation for new participants")
            print("\n📋 REQUIREMENTS FOR DEV TEAM:")
            print("   1. DNS TXT records needed for test participants:")
            print(f"      {new_participant_id} TXT \"ondc-signature=<base64_signature>\"")
            print("   2. OR: Disable DNS validation for test participant domains:")
            print("      *.participant.ondc (test domains)")
            print("   3. OR: Provide a test DNS zone where we can add TXT records")
            return False
        elif response.status_code == 200:
            print("\n⚠️  UNEXPECTED: Subscribe succeeded without DNS validation!")
            print("   DNS validation might be disabled or not working")
            return True
        else:
            print(f"\n⚠️  Different error: {error_msg}")
            return False
            
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        return False

def generate_dev_team_report(results):
    """Generate recommendations for dev team"""
    print("\n" + "="*80)
    print("RECOMMENDATIONS FOR DEV TEAM")
    print("="*80)
    
    if results.get('patch_works'):
        print("\n✅ GOOD NEWS: V3 PATCH operations work on existing participants")
        print("   We can test: Update contacts, credentials, locations")
    
    if results.get('dns_blocks'):
        print("\n⚠️  DNS VALIDATION ISSUE:")
        print("   UAT blocks new participant creation without DNS TXT records")
        print("\n   SOLUTIONS:")
        print("   Option 1: Provide DNS zone access for test participants")
        print("             - Create zone: test.participant.ondc")
        print("             - Allow QA to add TXT records")
        print("   ")
        print("   Option 2: Configure UAT to skip DNS validation for test domains")
        print("             - Whitelist pattern: test-*.participant.ondc")
        print("             - Or disable DNS validation entirely for UAT")
        print("   ")
        print("   Option 3: Pre-register pool of test participants")
        print("             - Create: test-participant-001 through test-participant-100")
        print("             - QA can rotate through these for testing")
    
    if not results.get('admin_patch_works'):
        print("\n⚠️  ADMIN STATUS CHANGES:")
        print("   Need to verify admin API can change participant status")
        print("   Required for testing: WHITELISTED ↔ SUBSCRIBED ↔ INACTIVE")
    
    print("\n" + "="*80)
    print("RECOMMENDED TESTING APPROACH")
    print("="*80)
    print("\nUNTIL DNS ISSUE RESOLVED:")
    print("  1. Use QA environment for create/delete lifecycle tests")
    print("  2. Use UAT only for:")
    print("     - V3 PATCH operations (update existing participant)")
    print("     - V3 Lookup tests (already working)")
    print("     - Admin API operations on existing participants")
    print("\nONCE DNS ISSUE RESOLVED:")
    print("  1. Full V3 subscribe tests in UAT (all 26 test cases)")
    print("  2. End-to-end lifecycle testing")
    print("  3. Production readiness validation")
    

def main():
    """Run all DNS validation tests"""
    print("\n" + "="*80)
    print("UAT DNS VALIDATION & EXISTING PARTICIPANT TEST SUITE")
    print("="*80)
    print("Purpose: Understand DNS validation requirements in UAT")
    print("         and identify what operations are possible")
    print("="*80)
    
    # Load config
    config = load_config()
    
    results = {}
    
    # Test 1: V3 PATCH on existing participant
    results['patch_works'] = test_v3_patch_existing_participant(config)
    
    # Test 2: Admin PATCH to change status
    results['admin_patch_works'] = test_admin_patch_deactivate(config)
    
    # Test 3: DNS validation with new participant
    results['dns_blocks'] = not test_dns_validation_new_participant(config)
    
    # Generate report
    generate_dev_team_report(results)
    
    print("\n" + "="*80)
    print("TEST SUITE COMPLETE")
    print("="*80)
    print(f"\nResults:")
    print(f"  V3 PATCH works:       {'✅ Yes' if results['patch_works'] else '❌ No'}")
    print(f"  Admin PATCH works:    {'✅ Yes' if results['admin_patch_works'] else '❌ No'}")
    print(f"  DNS validation active: {'✅ Yes' if results['dns_blocks'] else '❌ No'}")
    print("\n")

if __name__ == "__main__":
    main()
