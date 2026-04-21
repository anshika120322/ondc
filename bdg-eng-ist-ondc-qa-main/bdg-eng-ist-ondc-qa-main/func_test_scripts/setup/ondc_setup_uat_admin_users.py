#!/usr/bin/env python3
"""
Create Admin Test Users in UAT Environment
Creates domain admin, subscriber admin, and verifies ONDC admin users for testing
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import requests
import yaml
import json
from datetime import datetime

# UAT Admin Service URLs
UAT_AUTH_SERVICE = "https://admin-auth-uat.kynondc.net/api"
UAT_ADMIN_SERVICE = "https://admin-service-uat.kynondc.net/api/v1"

# Pre-configured admin token (SUPER_ADMIN, valid until April 10, 2026)
ADMIN_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2MjFlZTZiYi0zMDc1LTQ2MTQtODMyNC1lMzJjZTUxYjZjMzkiLCJlbWFpbCI6InVhdC1hZG1pbkBvbmRjLnRlc3QiLCJyb2xlIjoiU1VQRVJfQURNSU4iLCJyb2xlSWQiOiJkYjJlNDYxOS0wNDQ2LTQ0YzItOTNlNi1mYWJkNGIxOTlmNDciLCJpYXQiOjE3NzMxOTc5OTgsImV4cCI6MTc3NTc4OTk5OH0.7I314fWUstN_xFdBGeI79CDpv3OOhHFXn723O2Tjl8E"

def test_admin_token():
    """Test if the admin token works"""
    print("\n[Step 1/4] Testing admin token...")
    
    try:
        # Try to access a protected endpoint
        response = requests.get(
            f"{UAT_ADMIN_SERVICE}/users",
            headers={
                "Authorization": f"Bearer {ADMIN_TOKEN}",
                "Content-Type": "application/json"
            },
            timeout=10
        )
        
        if response.status_code == 200:
            print(f"   ✅ Admin token is valid")
            return True
        elif response.status_code == 401:
            print(f"   ❌ Admin token expired or invalid")
            print(f"   Response: {response.text[:200]}")
            return False
        else:
            print(f"   ⚠️  Unexpected status: {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Request failed: {e}")
        return False

def create_user(email, password, first_name, last_name, role):
    """Create a user via admin API"""
    
    payload = {
        "email": email,
        "password": password,
        "firstName": first_name,
        "lastName": last_name,
        "role": role
    }
    
    try:
        response = requests.post(
            f"{UAT_ADMIN_SERVICE}/users",
            headers={
                "Authorization": f"Bearer {ADMIN_TOKEN}",
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=10
        )
        
        if response.status_code == 201:
            data = response.json()
            user_id = data.get('id', 'N/A')
            print(f"   ✅ Created: {email} (ID: {user_id}, Role: {role})")
            return True, user_id
        elif response.status_code == 409 or response.status_code == 400:
            # User might already exist
            try:
                error_data = response.json()
                error_msg = error_data.get('message', response.text)
                if 'already exists' in error_msg.lower() or 'duplicate' in error_msg.lower():
                    print(f"   ℹ️  User already exists: {email}")
                    return True, None
                else:
                    print(f"   ⚠️  Creation failed: {error_msg[:150]}")
                    return False, None
            except:
                print(f"   ⚠️  Status {response.status_code}: {response.text[:150]}")
                return False, None
        else:
            print(f"   ❌ Failed to create {email}: {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            return False, None
            
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Request failed for {email}: {e}")
        return False, None

def verify_user_login(email, password):
    """Verify that a user can login successfully"""
    
    try:
        response = requests.post(
            f"{UAT_AUTH_SERVICE}/auth/login",
            json={
                "email": email,
                "password": password
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            # Check for token in response or cookies
            has_token = (
                data.get('access_token') or 
                data.get('accessToken') or 
                'accessToken' in response.cookies
            )
            if has_token:
                print(f"   ✅ Login successful: {email}")
                return True
            else:
                print(f"   ⚠️  Login returned 200 but no token found")
                return False
        elif response.status_code == 401:
            error_data = response.json() if response.text else {}
            error_msg = error_data.get('message', 'Invalid credentials')
            print(f"   ❌ Login failed: {email} - {error_msg}")
            return False
        else:
            print(f"   ⚠️  Unexpected status {response.status_code} for {email}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Login request failed for {email}: {e}")
        return False

def main():
    print(f"\n{'='*80}")
    print(f"  CREATE ADMIN TEST USERS IN UAT ENVIRONMENT")
    print(f"{'='*80}")
    print(f"  Auth Service: {UAT_AUTH_SERVICE}")
    print(f"  Admin Service: {UAT_ADMIN_SERVICE}")
    print(f"  Token: {ADMIN_TOKEN[:30]}... (expires: 2026-04-10)")
    print(f"{'='*80}\n")
    
    # Step 1: Test admin token
    if not test_admin_token():
        print("\n❌ Admin token test failed. Cannot proceed.")
        print("   Please check if:")
        print("   1. Token has not expired (should be valid until April 10, 2026)")
        print("   2. Admin service is accessible at", UAT_ADMIN_SERVICE)
        return False
    
    # Step 2: Create test users
    print("\n[Step 2/4] Creating test users...")
    
    users_to_create = [
        {
            "email": "domain-admin@ondc.test",
            "password": "DomainAdmin@123",
            "firstName": "Domain",
            "lastName": "Admin",
            "role": "ADMIN",  # Using ADMIN role (actual DOMAIN_ADMIN might not exist)
            "description": "Domain Admin (ADMIN role)"
        },
        {
            "email": "subscriber-admin@ondc.test",
            "password": "SubscriberAdmin@123",
            "firstName": "Subscriber",
            "lastName": "Admin",
            "role": "ADMIN",  # Using ADMIN role (actual SUBSCRIBER_ADMIN might not exist)
            "description": "Subscriber Admin (ADMIN role)"
        },
        {
            "email": "test-operator@ondc.test",
            "password": "Operator@123",
            "firstName": "Test",
            "lastName": "Operator",
            "role": "OPERATOR",
            "description": "Test Operator"
        }
    ]
    
    created_users = []
    failed_users = []
    
    for user in users_to_create:
        success, user_id = create_user(
            user["email"],
            user["password"],
            user["firstName"],
            user["lastName"],
            user["role"]
        )
        
        if success:
            created_users.append(user)
        else:
            failed_users.append(user)
    
    # Step 3: Verify user logins
    print("\n[Step 3/4] Verifying user logins...")
    
    login_results = []
    for user in created_users:
        success = verify_user_login(user["email"], user["password"])
        login_results.append({
            "email": user["email"],
            "password": user["password"],
            "role": user["role"],
            "login_success": success
        })
    
    # Step 4: Summary and config update
    print(f"\n[Step 4/4] Summary and Configuration")
    print(f"{'='*80}")
    print(f"\n✅ Successfully created/verified {len(created_users)} users:")
    for i, user in enumerate(created_users, 1):
        status = "✅" if any(r["email"] == user["email"] and r["login_success"] for r in login_results) else "⚠️"
        print(f"   {i}. {status} {user['email']} ({user['role']})")
    
    if failed_users:
        print(f"\n❌ Failed to create {len(failed_users)} users:")
        for user in failed_users:
            print(f"   • {user['email']} ({user['role']})")
    
    # Print config for resources/admin/ondc_admin_auth.yml
    print(f"\n{'='*80}")
    print(f"UPDATE CONFIG: resources/admin/ondc_admin_auth.yml")
    print(f"{'='*80}")
    print(f"\nondcAdminAuth:")
    print(f"  host: \"{UAT_AUTH_SERVICE}\"")
    print(f"  admin_service: \"{UAT_ADMIN_SERVICE.replace('/api/v1', '')}\"")
    print(f"  admin_token: \"{ADMIN_TOKEN}\"")
    print(f"  ")
    print(f"  users:")
    print(f"    ondc_admin:")
    print(f"      email: \"uat-admin@ondc.test\"")
    print(f"      password: \"<redacted>\"  # Existing SUPER_ADMIN password not logged for security")
    print(f"      role: \"SUPER_ADMIN\"")
    
    for user in created_users:
        role_key = user["email"].split("@")[0].replace("-", "_")
        print(f"    ")
        print(f"    {role_key}:")
        print(f"      email: \"{user['email']}\"")
        print(f"      password: \"<redacted>\"  # Password generated; not logged for security")
        print(f"      role: \"{user['role']}\"")
    
    print(f"\n{'='*80}")
    print(f"✅ User creation complete!")
    print(f"{'='*80}")
    print(f"\nNext steps:")
    print(f"  1. Update resources/admin/ondc_admin_auth.yml with the config above")
    print(f"  2. Run the comprehensive test suite:")
    print(f"     python driver.py --test ondc_admin_auth_rbac_comprehensive \\")
    print(f"       --environment ondcAdminAuth --users 1 --headless --autostart --autoquit 10 \\")
    print(f"       --html results/admin_auth_rbac_comprehensive_uat_test_results.html")
    print(f"\n")
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
