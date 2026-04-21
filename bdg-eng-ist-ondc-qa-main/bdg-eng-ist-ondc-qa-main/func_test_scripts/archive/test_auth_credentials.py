#!/usr/bin/env python3
"""
Test Authentication Credentials for ONDC Registry

Quickly test different credentials against the external auth service
without running the full test suite.

Usage:
    # Interactive mode (prompts for credentials)
    python func_test_scripts/test_auth_credentials.py

    # Command line mode
    python func_test_scripts/test_auth_credentials.py --email admin@example.com --password admin123

    # Test multiple credentials from a file
    python func_test_scripts/test_auth_credentials.py --file credentials.txt

    # Update config if successful
    python func_test_scripts/test_auth_credentials.py --email admin@example.com --password admin123 --update-config
"""

import sys
import os
import argparse
import requests
import yaml
from getpass import getpass
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class AuthTester:
    """Test authentication credentials against ONDC external auth service"""
    
    def __init__(self, auth_url="https://authservice.kynondc.net/api/auth/login"):
        self.auth_url = auth_url
        self.config_file = "resources/registry/subscribe/test_subscribe_functional.yml"
    
    def _mask_email(self, email):
        """
        Return a masked representation of an email address to avoid
        logging it in clear text.
        """
        if not email or "@" not in email:
            return "<redacted>"
        local, domain = email.split("@", 1)
        if not local:
            return f"<redacted>@{domain}"
        # Keep first character of local part and full domain
        first_char = local[0]
        return f"{first_char}{'*' * max(len(local) - 1, 0)}@{domain}"
    
    def test_credentials(self, email, password, show_token=False, context=None):
        """
        Test a single set of credentials
        
        Args:
            email: The username/email for authentication (not logged).
            password: The password for authentication (not logged).
            show_token: Whether to display the returned token.
            context: Optional non-sensitive label for this credential set
                     (for example, "credential set #1").
        
        Returns:
            tuple: (success: bool, token: str, message: str)
        """
        label = context if context is not None else "credential set"
        print("\n" + "="*80)
        print(f"Testing Credentials: {label}")
        print("="*80)
        print(f"Auth URL: {self.auth_url}")
        # Avoid logging user identifiers and passwords
        print("User:     <redacted>")
        print("Password: <redacted>")
        print("-"*80)
        
        # Prepare payload
        payload = {
            "email": email,
            "password": password
        }
        
        try:
            # Make request
            response = requests.post(
                self.auth_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            status_code = response.status_code
            
            # Try to parse JSON response
            try:
                data = response.json()
            except:
                data = {"raw_text": response.text}
            
            # Check if successful
            if status_code == 200:
                # External auth service returns different structure
                access_token = None
                
                # Check different possible response formats
                if isinstance(data, dict):
                    # Format 1: Direct token fields
                    access_token = data.get('access_token') or data.get('accessToken') or data.get('token')
                    
                    # Format 2: Nested in 'data' or 'message'
                    if not access_token and 'data' in data:
                        access_token = data['data'].get('access_token') or data['data'].get('accessToken')
                    
                    if not access_token and 'message' in data:
                        access_token = data['message'].get('access_token') or data['message'].get('accessToken')
                
                if access_token:
                    print(f"✅ SUCCESS! Authentication successful")
                    print(f"Status Code: {status_code}")
                    print(f"Token Type: {data.get('token_type', 'Bearer')}")
                    
                    if 'expires_in' in data:
                        print(f"Expires In: {data['expires_in']} seconds ({data['expires_in']/3600:.1f} hours)")
                    
                    if show_token:
                        print("\n" + "-"*80)
                        print("ACCESS TOKEN:")
                        print("-"*80)
                        print(access_token)
                        print("-"*80)
                    else:
                        print(f"Token Preview: {access_token[:50]}... (use --show-token to see full token)")
                    
                    print("\n" + "="*80)
                    return True, access_token, "Success"
                else:
                    print(f"⚠️  WARNING: Got 200 but no token found in response")
                    print(f"Response: {data}")
                    print("="*80)
                    return False, None, "No token in response"
            
            else:
                # Authentication failed
                error_msg = data.get('message', data.get('error', 'Unknown error'))
                print(f"❌ FAILED! Authentication failed")
                print(f"Status Code: {status_code}")
                print(f"Error: {error_msg}")
                print(f"Full Response: {data}")
                print("="*80)
                return False, None, f"{status_code}: {error_msg}"
        
        except requests.exceptions.Timeout:
            print(f"❌ FAILED! Request timeout")
            print("="*80)
            return False, None, "Timeout"
        
        except requests.exceptions.RequestException as e:
            print(f"❌ FAILED! Request error: {e}")
            print("="*80)
            return False, None, str(e)
        
        except Exception as e:
            print(f"❌ ERROR! Unexpected error: {e}")
            print("="*80)
            import traceback
            traceback.print_exc()
            return False, None, str(e)
    
    def test_multiple_credentials(self, credentials_list, show_token=False):
        """
        Test multiple sets of credentials
        
        Args:
            credentials_list: List of (email, password) tuples
        
        Returns:
            List of results: [(index, success, token, message), ...]
            Note: Returns index instead of email to avoid sensitive data exposure
        """
        results = []
        
        print("\n" + "="*80)
        print(f"TESTING {len(credentials_list)} CREDENTIAL SETS")
        print("="*80)
        
        for idx, (email, password) in enumerate(credentials_list, 1):
            context = f"credential set #{idx}"
            print(f"\n[{idx}/{len(credentials_list)}] Testing {context}")
            success, token, message = self.test_credentials(
                email,
                password,
                show_token=show_token,
                context=context,
            )
            # Store index instead of email to avoid logging sensitive data
            results.append((idx, success, token, message))
        
        # Summary
        print("\n" + "="*80)
        print("SUMMARY")
        print("="*80)
        
        successful = [r for r in results if r[1]]
        failed = [r for r in results if not r[1]]
        
        print(f"Total Tested: {len(results)}")
        print(f"Successful:   {len(successful)}")
        print(f"Failed:       {len(failed)}")
        print("-"*80)
        
        if successful:
            print(f"\n✅ SUCCESSFUL CREDENTIALS: {len(successful)} set(s)")
            for idx, _, token, _ in successful:
                print(f"  • Credential set #{idx}: Authentication succeeded")
        
        if failed:
            print("\n❌ FAILED CREDENTIALS:")
            for idx, _, _, _ in failed:
                print(f"  • Credential set #{idx}: Authentication failed")
        
        print("="*80)
        
        return results
    
    def update_config(self, email, password):
        """Update config file with successful credentials"""
        
        if not os.path.exists(self.config_file):
            print(f"❌ Config file not found: {self.config_file}")
            return False
        
        try:
            # Load config
            with open(self.config_file, 'r') as f:
                config_data = yaml.safe_load(f)
            
            # Update credentials
            if 'ondcRegistry' in config_data:
                config_data['ondcRegistry']['admin_username'] = email
                config_data['ondcRegistry']['admin_password'] = password
                
                # Save config
                with open(self.config_file, 'w') as f:
                    yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)
                
                print(f"\n✅ Updated config file: {self.config_file}")
                print(f"   admin_username: <redacted>")
                print(f"   admin_password: {'*' * len(password)}")
                return True
            else:
                print(f"❌ 'ondcRegistry' section not found in config")
                return False
        
        except Exception as e:
            print(f"❌ Error updating config: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description='Test authentication credentials for ONDC Registry',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python func_test_scripts/test_auth_credentials.py

  # Test specific credentials
  python func_test_scripts/test_auth_credentials.py --email admin@example.com --password admin123

  # Test and update config if successful
  python func_test_scripts/test_auth_credentials.py --email admin@example.com --password admin123 --update-config

  # Show full JWT token
  python func_test_scripts/test_auth_credentials.py --email admin@example.com --password admin123 --show-token

  # Test multiple credentials from file (one per line: email,password)
  python func_test_scripts/test_auth_credentials.py --file credentials.txt

  # Use different auth URL
  python func_test_scripts/test_auth_credentials.py --auth-url https://other-auth.example.com/login --email admin@test.com --password test123
        """
    )
    
    parser.add_argument('--email', '-e', help='Email address for authentication')
    parser.add_argument('--password', '-p', help='Password for authentication')
    parser.add_argument('--file', '-f', help='File containing credentials (email,password per line)')
    parser.add_argument('--auth-url', default='https://authservice.kynondc.net/api/auth/login',
                       help='Authentication service URL')
    parser.add_argument('--update-config', '-u', action='store_true',
                       help='Update config file if authentication is successful')
    parser.add_argument('--show-token', '-t', action='store_true',
                       help='Show full JWT token (default: only preview)')
    
    args = parser.parse_args()
    
    # Create tester
    tester = AuthTester(auth_url=args.auth_url)
    
    # Determine mode
    if args.file:
        # File mode
        if not os.path.exists(args.file):
            print(f"❌ File not found: {args.file}")
            sys.exit(1)
        
        credentials_list = []
        with open(args.file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split(',')
                if len(parts) != 2:
                    print(f"⚠️  Skipping invalid line {line_num}: {line}")
                    continue
                
                email, password = parts[0].strip(), parts[1].strip()
                credentials_list.append((email, password))
        
        results = tester.test_multiple_credentials(credentials_list, show_token=args.show_token)
        
        # Update config with first successful credential
        if args.update_config:
            successful = [r for r in results if r[1]]
            if successful:
                # results store (index, success, token, message)
                first_success_idx = successful[0][0]
                # credentials_list is 0-based; indexes in results start at 1
                email, password = credentials_list[first_success_idx - 1]
                tester.update_config(email, password)
        
    elif args.email and args.password:
        # Command line mode
        success, token, message = tester.test_credentials(args.email, args.password, show_token=args.show_token)
        
        if success and args.update_config:
            tester.update_config(args.email, args.password)
        
        sys.exit(0 if success else 1)
    
    else:
        # Interactive mode
        print("\n" + "="*80)
        print("ONDC Registry - Authentication Credential Tester")
        print("="*80)
        print("\nTest credentials against the external auth service")
        print("Press Ctrl+C to exit\n")
        
        # Get credentials
        email = input("Email: ").strip()
        password = getpass("Password: ").strip()
        
        if not email or not password:
            print("❌ Email and password are required")
            sys.exit(1)
        
        success, token, message = tester.test_credentials(email, password, show_token=args.show_token)
        
        if success and args.update_config:
            confirm = input("\nUpdate config file with these credentials? [y/N]: ").strip().lower()
            if confirm == 'y':
                tester.update_config(email, password)
        
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Interrupted by user")
        sys.exit(1)
