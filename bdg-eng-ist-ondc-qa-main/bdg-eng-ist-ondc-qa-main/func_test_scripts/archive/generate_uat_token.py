#!/usr/bin/env python3
"""
Generate UAT Admin JWT Token using Secret Key
Uses the UAT JWT secret to create a valid admin token
"""
import jwt
from datetime import datetime, timedelta
import uuid
import requests
import json

# UAT JWT Secret Key
UAT_SECRET_KEY = "4DqXIEHY0rMzYOcewhO8tlv0ohfbPX5qLNyk4v5cebH"


def generate_uat_admin_token(email="uat-admin@ondc.test", role="SUPER_ADMIN", hours=720):
    """
    Generate a valid UAT admin JWT token
    
    Args:
        email: Admin email
        role: User role (SUPER_ADMIN for full admin access)
        hours: Token validity in hours (default: 30 days)
        
    Returns:
        str: JWT token
    """
    now = datetime.utcnow()
    expiry = now + timedelta(hours=hours)
    
    # Token payload matching ONDC auth service structure
    payload = {
        "sub": str(uuid.uuid4()),  # User UUID
        "email": email,
        "role": role,
        "roleId": str(uuid.uuid4()),  # Role UUID
        "iat": int(now.timestamp()),  # Issued at
        "exp": int(expiry.timestamp()),  # Expiry
    }
    
    # Generate token with HS256 algorithm
    token = jwt.encode(payload, UAT_SECRET_KEY, algorithm="HS256")
    
    return token, payload


def test_token_with_uat(token):
    """Test if generated token works with UAT admin API"""
    
    uat_server = "http://34.93.208.52"
    
    print(f"\n{'='*70}")
    print(f"Testing Token with UAT Admin API")
    print(f"{'='*70}\n")
    
    # Minimal subscribe request to test auth
    test_payload = {
        "participant_id": "test-token-validation.ondc"
    }
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    try:
        print(f"🔐 Testing: POST {uat_server}/admin/subscribe")
        print(f"📋 Payload: {json.dumps(test_payload, indent=2)}")
        print(f"\n⏳ Sending request...")
        
        response = requests.post(
            f"{uat_server}/admin/subscribe",
            json=test_payload,
            headers=headers,
            timeout=10
        )
        
        print(f"\n📊 Response Status: {response.status_code}")
        
        if response.status_code == 401:
            print(f"❌ 401 Unauthorized - Token rejected")
            print(f"   Response: {response.text[:200]}")
            return False
        elif response.status_code == 400:
            print(f"✅ Token Accepted! (400 = validation error, not auth error)")
            print(f"   The token works! Error is due to incomplete payload, not authentication.")
            return True
        elif response.status_code in [200, 201]:
            print(f"✅ Token Accepted! Request successful!")
            return True
        else:
            print(f"⚠️  Status {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            # Non-401 means token was accepted (auth passed)
            return response.status_code != 401
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def main():
    print(f"\n{'='*70}")
    print(f"UAT JWT Token Generator (Using Secret Key)")
    print(f"{'='*70}\n")
    
    # Generate token
    print("🔑 Generating UAT admin token...")
    token, payload = generate_uat_admin_token()
    
    print(f"\n✅ Token Generated!")
    print(f"\n📋 Token Payload:")
    print(json.dumps(payload, indent=2))
    
    print(f"\n📅 Token Details:")
    print(f"   - Valid for: 720 hours (30 days)")
    print(f"   - Expires: {datetime.fromtimestamp(payload['exp']).strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   - Email: {payload['email']}")
    print(f"   - Role: {payload['role']}")
    
    print(f"\n🔑 Full Token:")
    print(f"{'='*70}")
    print(token)
    print(f"{'='*70}")
    
    # Test the token
    print(f"\n🧪 Testing token with UAT server...")
    success = test_token_with_uat(token)
    
    if success:
        print(f"\n{'='*70}")
        print(f"✅ SUCCESS! Token is valid and working!")
        print(f"{'='*70}")
        print(f"\n📝 Next Steps:")
        print(f"\n1. Save this token to your config file:")
        print(f"   File: resources/registry/lookup/v3/test_lookup_functional.yml")
        print(f"\n   Add this line:")
        print(f"   admin_token: \"{token}\"")
        print(f"\n2. Run participant registration:")
        print(f"   python func_test_scripts/register_uat_participant.py")
        print(f"\n{'='*70}\n")
        
        # Save to file for easy access
        with open('uat_admin_token.txt', 'w') as f:
            f.write(token)
        print(f"💾 Token saved to: uat_admin_token.txt\n")
        
    else:
        print(f"\n{'='*70}")
        print(f"❌ Token validation failed")
        print(f"{'='*70}")
        print(f"\n⚠️  The secret key may not be correct for UAT")
        print(f"   Or UAT uses a different token structure")
        print(f"\n📋 Next Steps:")
        print(f"   - Verify the secret key with your team")
        print(f"   - Check if UAT uses external auth service")
        print(f"   - Ask for a pre-generated UAT admin token")
        print(f"\n{'='*70}\n")


if __name__ == '__main__':
    main()
