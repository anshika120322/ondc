#!/usr/bin/env python3
"""
Get JWT Token for UAT Environment
This script helps obtain a JWT token for UAT admin API authentication.
"""
import requests
import argparse
import json
import sys
from datetime import datetime, timedelta


def test_auth_endpoints(base_url, email, password):
    """Test different auth endpoint possibilities"""
    
    print(f"\n{'='*70}")
    print(f"Testing UAT Authentication Endpoints")
    print(f"{'='*70}\n")
    
    # Possible auth endpoints
    endpoints = [
        f"{base_url}/admin/auth/login",
        f"{base_url}/auth/login",
        f"{base_url}/api/admin/auth/login",
        f"{base_url}/api/auth/login",
        "https://authservice.kynondc.net/api/auth/login",  # External auth service
    ]
    
    for endpoint in endpoints:
        print(f"Testing: {endpoint}")
        try:
            # Try username/password first
            response = requests.post(
                endpoint,
                json={"username": email, "password": password},
                timeout=5
            )
            
            if response.status_code != 404:
                print(f"  ✅ Endpoint exists! Status: {response.status_code}")
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if "access_token" in data or "token" in data:
                            print(f"  🎉 SUCCESS! Token found!")
                            return endpoint, data
                    except:
                        pass
                elif response.status_code == 401:
                    print(f"  ⚠️  401 Unauthorized - endpoint correct, credentials may be wrong")
                    
                    # Try with email field
                    response2 = requests.post(
                        endpoint,
                        json={"email": email, "password": password},
                        timeout=5
                    )
                    if response2.status_code == 200:
                        data = response2.json()
                        if "access_token" in data or "token" in data:
                            print(f"  🎉 SUCCESS with 'email' field!")
                            return endpoint, data
                            
                print(f"  Response: {response.text[:100]}")
            else:
                print(f"  ❌ 404 Not Found")
                
        except requests.exceptions.Timeout:
            print(f"  ⏱️  Timeout")
        except requests.exceptions.ConnectionError:
            print(f"  🔌 Connection failed")
        except Exception as e:
            print(f"  ❌ Error: {str(e)[:50]}")
    
    return None, None


def get_uat_token(auth_url=None, email=None, password=None):
    """
    Get JWT token for UAT environment
    
    Args:
        auth_url: Auth service URL (if known)
        email: User email/username
        password: User password
    """
    
    print(f"\n{'='*70}")
    print(f"UAT JWT Token Generator")
    print(f"{'='*70}\n")
    
    # If no auth URL provided, discover it
    if not auth_url:
        print("⚠️  Auth URL not provided. Testing common endpoints...\n")
        uat_admin_server = "http://34.93.208.52"
        
        if not email or not password:
            print("❌ Email and password required for endpoint discovery\n")
            print("Please run with credentials:")
            print(f"  python func_test_scripts/get_uat_token.py --email YOUR_EMAIL --password YOUR_PASSWORD\n")
            return None
            
        auth_url, token_data = test_auth_endpoints(uat_admin_server, email, password)
        
        if token_data:
            token = token_data.get("access_token") or token_data.get("token")
            print(f"\n{'='*70}")
            print(f"✅ TOKEN OBTAINED")
            print(f"{'='*70}")
            print(f"\nAuth URL: {auth_url}")
            print(f"Token: {token}")
            print(f"\n{'='*70}")
            print(f"\n💾 Save this token to your config:")
            print(f"\nresources/registry/lookup/v3/test_lookup_functional.yml:")
            print(f"\nondcRegistry:")
            print(f"  admin_token: \"{token}\"")
            print(f"\n{'='*70}\n")
            return token
        else:
            print(f"\n❌ No working auth endpoint found")
            print(f"\n📋 Next Steps:")
            print(f"  1. Contact your team for UAT auth service URL")
            print(f"  2. Or ask for a pre-generated UAT JWT token")
            print(f"  3. Or verify credentials are correct for UAT\n")
            return None
    
    # If auth URL provided, use it directly
    try:
        print(f"🔐 Authenticating with: {auth_url}")
        print(f"📧 Email: {email}\n")
        
        # Try both username and email field
        for field in ["email", "username"]:
            payload = {field: email, "password": password}
            
            response = requests.post(auth_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                token = data.get("access_token") or data.get("token")
                
                if token:
                    expires_in = data.get("expires_in", 86400)
                    expiry_time = datetime.now() + timedelta(seconds=expires_in)
                    
                    print(f"✅ Success! Token obtained")
                    print(f"⏰ Expires in: {expires_in} seconds ({expires_in//3600} hours)")
                    print(f"📅 Expires at: {expiry_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"\n🔑 Token:\n{token}")
                    
                    return token
        
        print(f"❌ Authentication failed")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
    
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Get JWT token for UAT environment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-discover auth endpoint (tries common URLs)
  python func_test_scripts/get_uat_token.py --email admin@example.com --password secret123
  
  # Use specific auth URL
  python func_test_scripts/get_uat_token.py --auth-url https://uat-auth.kynondc.net/api/auth/login \\
      --email admin@example.com --password secret123
  
  # Get help finding auth service
  python func_test_scripts/get_uat_token.py --help
        """
    )
    
    parser.add_argument(
        '--auth-url',
        help='UAT Auth service URL (optional - will try to discover if not provided)'
    )
    parser.add_argument(
        '--email',
        help='User email/username for authentication'
    )
    parser.add_argument(
        '--password',
        help='User password'
    )
    
    args = parser.parse_args()
    
    # Show help if no credentials provided
    if not args.email and not args.password:
        print(f"\n{'='*70}")
        print(f"UAT JWT Token Generator - Help")
        print(f"{'='*70}\n")
        print("To get a UAT JWT token, you need:")
        print("\n1. **UAT Credentials** (email/username + password)")
        print("   - Ask your team for UAT admin credentials")
        print("   - Or check your credential store/vault")
        print("\n2. **Auth Service URL** (optional)")
        print("   - Script will try to auto-discover if not provided")
        print("   - Common possibilities:")
        print("     • https://authservice.kynondc.net/api/auth/login (external)")
        print("     • http://34.93.208.52/auth/login (local)")
        print("     • Ask your team for the correct URL")
        print("\n3. **Or Get Pre-generated Token**")
        print("   - Ask your team if they have a static UAT admin token")
        print("   - Add it directly to config file:")
        print("     resources/registry/lookup/v3/test_lookup_functional.yml")
        print("\nExamples:")
        print("  # Auto-discover (recommended)")
        print("  python func_test_scripts/get_uat_token.py --email YOUR_EMAIL --password YOUR_PASSWORD")
        print("\n  # With specific auth URL")
        print("  python func_test_scripts/get_uat_token.py \\")
        print("    --auth-url https://uat-auth.example.com/login \\")
        print("    --email YOUR_EMAIL --password YOUR_PASSWORD")
        print(f"\n{'='*70}\n")
        sys.exit(0)
    
    token = get_uat_token(args.auth_url, args.email, args.password)
    
    if token:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
