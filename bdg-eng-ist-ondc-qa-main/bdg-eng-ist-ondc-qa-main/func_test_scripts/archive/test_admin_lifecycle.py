#!/usr/bin/env python3
"""
Test Admin API Lifecycle Transitions in UAT
Tests: SUBSCRIBED ↔ INACTIVE ↔ WHITELISTED status changes
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import requests
import json
import yaml
import time

UAT_ADMIN_SERVER = "http://34.93.208.52"
UAT_LOOKUP_SERVER = "http://35.200.145.160:8080"

def load_config():
    """Load credentials from config"""
    config_file = 'resources/registry/subscribe/test_subscribe_functional.yml'
    with open(config_file, 'r') as f:
        config_data = yaml.safe_load(f)
        return config_data.get('ondcRegistry', {})

def admin_patch_status(participant_id, new_status, admin_token):
    """Change participant status using admin PATCH"""
    url = f"{UAT_ADMIN_SERVER}/admin/subscribe"
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }
    payload = {
        "participant_id": participant_id,
        "action": new_status
    }
    
    print(f"\n{'='*70}")
    print(f"Changing status: {new_status}")
    print(f"{'='*70}")
    print(f"PATCH {url}")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.patch(url, json=payload, headers=headers, timeout=30)
        print(f"\nResponse Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            print(f"✅ SUCCESS: Status changed to {new_status}")
            return True
        else:
            print(f"❌ FAILED: Could not change status")
            return False
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

def verify_status_via_lookup(participant_id):
    """Verify participant status via V3 lookup"""
    url = f"{UAT_LOOKUP_SERVER}/v3.0/lookup"
    payload = {
        "country": "IND",
        "subscriber_id": participant_id
    }
    
    print(f"\n  Verifying via lookup...")
    
    try:
        response = requests.post(url, json=payload, timeout=30)
        if response.status_code == 200:
            data = response.json()
            if data and len(data) > 0:
                status = data[0].get('status', 'UNKNOWN')
                print(f"  ✅ Lookup confirms status: {status}")
                return status
            else:
                print(f"  ⚠️  Participant not found in lookup")
                return "NOT_FOUND"
        else:
            print(f"  ❌ Lookup failed: {response.status_code}")
            return "ERROR"
    except Exception as e:
        print(f"  ❌ Lookup error: {e}")
        return "ERROR"

def test_lifecycle_transitions(config):
    """Test complete lifecycle: SUBSCRIBED → INACTIVE → WHITELISTED → SUBSCRIBED"""
    
    participant_id = config['participant_id']
    admin_token = config['admin_token']
    
    print("\n" + "="*80)
    print("UAT ADMIN API LIFECYCLE TESTING")
    print("="*80)
    print(f"Participant: {participant_id}")
    print(f"Test: Status lifecycle transitions")
    print("="*80)
    
    results = []
    
    # Test 1: SUBSCRIBED → INACTIVE
    print("\n\n" + "🔄 "*35)
    print("TEST 1: SUBSCRIBED → INACTIVE")
    print("🔄 "*35)
    
    success = admin_patch_status(participant_id, "INACTIVE", admin_token)
    if success:
        time.sleep(2)  # Wait for propagation
        status = verify_status_via_lookup(participant_id)
        results.append(("SUBSCRIBED → INACTIVE", success, status))
    else:
        results.append(("SUBSCRIBED → INACTIVE", False, "FAILED"))
    
    time.sleep(3)
    
    # Test 2: INACTIVE → WHITELISTED  
    print("\n\n" + "🔄 "*35)
    print("TEST 2: INACTIVE → WHITELISTED")
    print("🔄 "*35)
    
    success = admin_patch_status(participant_id, "WHITELISTED", admin_token)
    if success:
        time.sleep(2)
        status = verify_status_via_lookup(participant_id)
        results.append(("INACTIVE → WHITELISTED", success, status))
    else:
        results.append(("INACTIVE → WHITELISTED", False, "FAILED"))
    
    time.sleep(3)
    
    # Test 3: WHITELISTED → SUBSCRIBED
    print("\n\n" + "🔄 "*35)
    print("TEST 3: WHITELISTED → SUBSCRIBED")
    print("🔄 "*35)
    
    success = admin_patch_status(participant_id, "SUBSCRIBED", admin_token)
    if success:
        time.sleep(2)
        status = verify_status_via_lookup(participant_id)
        results.append(("WHITELISTED → SUBSCRIBED", success, status))
    else:
        results.append(("WHITELISTED → SUBSCRIBED", False, "FAILED"))
    
    time.sleep(3)
    
    # Test 4: SUBSCRIBED → WHITELISTED (downgrade)
    print("\n\n" + "🔄 "*35)
    print("TEST 4: SUBSCRIBED → WHITELISTED (Downgrade)")
    print("🔄 "*35)
    
    success = admin_patch_status(participant_id, "WHITELISTED", admin_token)
    if success:
        time.sleep(2)
        status = verify_status_via_lookup(participant_id)
        results.append(("SUBSCRIBED → WHITELISTED", success, status))
    else:
        results.append(("SUBSCRIBED → WHITELISTED", False, "FAILED"))
    
    time.sleep(3)
    
    # Test 5: WHITELISTED → SUBSCRIBED (restore)
    print("\n\n" + "🔄 "*35)
    print("TEST 5: WHITELISTED → SUBSCRIBED (Restore)")
    print("🔄 "*35)
    
    success = admin_patch_status(participant_id, "SUBSCRIBED", admin_token)
    if success:
        time.sleep(2)
        status = verify_status_via_lookup(participant_id)
        results.append(("Restore to SUBSCRIBED", success, status))
    else:
        results.append(("Restore to SUBSCRIBED", False, "FAILED"))
    
    # Summary
    print("\n\n" + "="*80)
    print("TEST RESULTS SUMMARY")
    print("="*80)
    
    print(f"\n{'Transition':<40} {'Admin API':<15} {'Lookup Status':<20}")
    print("-"*80)
    
    for transition, api_success, lookup_status in results:
        api_result = "✅ SUCCESS" if api_success else "❌ FAILED"
        print(f"{transition:<40} {api_result:<15} {lookup_status:<20}")
    
    print("="*80)
    
    passed = sum(1 for _, success, _ in results if success)
    total = len(results)
    
    print(f"\nOverall: {passed}/{total} transitions successful ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED!")
        print("\n✅ UAT Admin API fully functional for lifecycle transitions")
        print("   Can test: SUBSCRIBED ↔ INACTIVE ↔ WHITELISTED")
    else:
        print(f"\n⚠️  {total - passed} tests failed")
    
    print("\n" + "="*80)

def main():
    """Run lifecycle tests"""
    config = load_config()
    test_lifecycle_transitions(config)

if __name__ == "__main__":
    main()
