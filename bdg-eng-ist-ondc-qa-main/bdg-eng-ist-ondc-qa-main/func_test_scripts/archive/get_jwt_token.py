#!/usr/bin/env python3
"""
Get JWT Token from ONDC Auth Service
This script helps you obtain a long-lived JWT token for static authentication.
"""
import requests
import argparse
import json
import sys
from datetime import datetime, timedelta


def get_token(auth_url, email, password, show_details=False):
    """
    Get JWT token from auth service
    
    Args:
        auth_url: Auth service URL
        email: User email
        password: User password
        show_details: Whether to show token details
        
    Returns:
        dict: Token data or None if failed
    """
    payload = {
        "email": email,
        "password": password
    }
    
    try:
        print(f"\n🔐 Requesting token from: {auth_url}")
        print(f"📧 Email: {email}")
        print(f"⏳ Sending request...\n")
        
        response = requests.post(auth_url, json=payload, timeout=10)
        
        # Show response status
        if response.status_code == 200:
            print(f"✅ Success! Status: {response.status_code}")
        else:
            print(f"❌ Failed! Status: {response.status_code}")
            
        # Parse response
        data = response.json()
        
        if show_details:
            print(f"\n📋 Full Response:")
            print(json.dumps(data, indent=2))
        
        # Check for success
        if response.status_code == 200 and "access_token" in data:
            token = data["access_token"]
            expires_in = data.get("expires_in", 86400)  # Default 24 hours
            
            # Calculate expiry time
            expiry_time = datetime.now() + timedelta(seconds=expires_in)
            
            print(f"\n🎉 Token obtained successfully!")
            print(f"⏰ Expires in: {expires_in} seconds ({expires_in//3600} hours)")
            print(f"📅 Expires at: {expiry_time.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"\n🔑 Token (first 50 chars): {token[:50]}...")
            print(f"\n📄 Full Token:\n{token}")
            
            return {
                "token": token,
                "expires_in": expires_in,
                "expiry_time": expiry_time.isoformat(),
                "refresh_token": data.get("refresh_token")
            }
        else:
            print(f"\n❌ Authentication failed!")
            print(f"Response: {json.dumps(data, indent=2)}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"\n❌ Request failed: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                print(f"Error response: {e.response.text}")
            except:
                pass
        return None
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        return None


def save_to_config(token, config_path):
    """
    Update config file with token
    
    Args:
        token: JWT token string
        config_path: Path to config YAML file
    """
    import yaml
    
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        # Update admin_token
        if 'ondcRegistry' in config:
            config['ondcRegistry']['admin_token'] = token
            
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)
            
            print(f"\n✅ Config updated: {config_path}")
            print(f"📝 Set admin_token in ondcRegistry section")
        else:
            print(f"\n⚠️  Warning: 'ondcRegistry' section not found in config")
            
    except FileNotFoundError:
        print(f"\n❌ Config file not found: {config_path}")
    except Exception as e:
        print(f"\n❌ Failed to update config: {str(e)}")


def main():
    parser = argparse.ArgumentParser(
        description="Get JWT token from ONDC Auth Service",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Get token with valid credentials
  python func_test_scripts/get_jwt_token.py --email admin@example.com --password secret123
  
  # Get token and save to config
  python func_test_scripts/get_jwt_token.py --email admin@example.com --password secret123 --save-config
  
  # Get token from custom auth service
  python func_test_scripts/get_jwt_token.py --auth-url https://custom-auth.com/login --email user@test.com --password pass123
  
  # Show detailed response
  python func_test_scripts/get_jwt_token.py --email admin@example.com --password secret123 --details
        """
    )
    
    parser.add_argument(
        '--auth-url',
        default='https://authservice.kynondc.net/api/auth/login',
        help='Auth service URL (default: https://authservice.kynondc.net/api/auth/login)'
    )
    parser.add_argument(
        '--email',
        required=True,
        help='User email for authentication'
    )
    parser.add_argument(
        '--password',
        required=True,
        help='User password for authentication'
    )
    parser.add_argument(
        '--save-config',
        action='store_true',
        help='Save token to config file automatically'
    )
    parser.add_argument(
        '--config-path',
        default='resources/registry/subscribe/test_subscribe_functional.yml',
        help='Path to config file (default: resources/registry/subscribe/test_subscribe_functional.yml)'
    )
    parser.add_argument(
        '--details',
        action='store_true',
        help='Show detailed response data'
    )
    parser.add_argument(
        '--output',
        help='Save token to file (optional)'
    )
    
    args = parser.parse_args()
    
    # Get token
    result = get_token(args.auth_url, args.email, args.password, args.details)
    
    if result:
        token = result['token']
        
        # Save to config if requested
        if args.save_config:
            save_to_config(token, args.config_path)
        
        # Save to file if requested
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    f.write(token)
                print(f"\n✅ Token saved to: {args.output}")
            except Exception as e:
                print(f"\n❌ Failed to save token to file: {str(e)}")
        
        print("\n" + "="*70)
        print("📋 NEXT STEPS:")
        print("="*70)
        if not args.save_config:
            print("\n1. Copy the token above")
            print(f"2. Edit config: {args.config_path}")
            print("3. Set: admin_token: \"<paste-token-here>\"")
            print("4. Run tests - authentication will use the static token!")
        else:
            print("\n✅ Token already saved to config!")
            print("🚀 Run tests - authentication will use the static token!")
        print("\n" + "="*70)
        
        sys.exit(0)
    else:
        print("\n" + "="*70)
        print("❌ TROUBLESHOOTING:")
        print("="*70)
        print("\n1. Verify your credentials are correct")
        print("2. Check if the email exists in the auth service")
        print("3. Contact your team for valid test credentials")
        print(f"4. Verify auth service is reachable: {args.auth_url}")
        print("\n" + "="*70)
        sys.exit(1)


if __name__ == "__main__":
    main()
