#!/usr/bin/env python3
"""
JWT Token Generator for ONDC Auth Service

Generates valid JWT tokens using the auth service secret key.
These tokens will work with the production auth service!

⚠️  SECURITY WARNING:
- The secret key is sensitive - do not commit to git!
- Keep this file secure
- Rotate secret key if compromised
"""
import jwt
from datetime import datetime, timedelta
import argparse
import json


# ⚠️  SECURITY: Real auth service secret key
# DO NOT COMMIT THIS TO GIT!
DEFAULT_SECRET_KEY = "4DqXIEHY0rMzYOcewhO8tlv0ohfbPX5qLNyk4v5cebH"


class JWTGenerator:
    """Generate valid JWT tokens for ONDC Auth Service"""
    
    def __init__(self, secret_key=DEFAULT_SECRET_KEY):
        """
        Initialize with the auth service secret key
        
        Args:
            secret_key: Auth service secret key (default: production key)
        """
        self.secret_key = secret_key
    
    def generate_token(self, email, role="SUPER_ADMIN", expires_hours=24, sub=None, role_id=None):
        """
        Generate a valid JWT token matching auth service structure
        
        Args:
            email: User email
            role: User role (SUPER_ADMIN, ADMIN, USER, etc.)
            expires_hours: Token validity in hours
            sub: Subject/User UUID (if not provided, generates one)
            role_id: Role UUID (if not provided, generates one)
            
        Returns:
            tuple: (token_string, payload_dict)
        """
        import uuid
        
        # Current time
        now = datetime.utcnow()
        expiry = now + timedelta(hours=expires_hours)
        
        # Generate UUIDs if not provided
        if sub is None:
            sub = str(uuid.uuid4())
        if role_id is None:
            role_id = str(uuid.uuid4())
        
        # Token payload (matching REAL auth service structure)
        # Based on decoded production token
        payload = {
            "sub": sub,  # User UUID (primary identifier)
            "email": email,
            "role": role,
            "roleId": role_id,  # Role UUID
            "iat": int(now.timestamp()),  # Issued at
            "exp": int(expiry.timestamp()),  # Expiry
        }
        
        # Generate token
        token = jwt.encode(payload, self.secret_key, algorithm="HS256")
        
        return token, payload
    
    def decode_token(self, token, verify=False):
        """
        Decode a JWT token (for inspection)
        
        Args:
            token: JWT token string
            verify: Whether to verify signature (requires matching secret)
            
        Returns:
            dict: Decoded payload
        """
        try:
            if verify:
                payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            else:
                payload = jwt.decode(token, options={"verify_signature": False})
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {str(e)}")


def main():
    parser = argparse.ArgumentParser(
        description="JWT Token Generator for ONDC Auth Service",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
✅ This generates VALID tokens for the auth service!

Uses the actual auth service secret key to generate tokens
that will be accepted by production servers.

Examples:
  # Generate a token with default settings (24 hours)
  python func_test_scripts/mock_jwt_generator.py --email admin@test.com
  
  # Generate with custom expiry
  python func_test_scripts/mock_jwt_generator.py --email user@test.com --hours 48
  
  # Generate and save to config
  python func_test_scripts/mock_jwt_generator.py --email admin@test.com --save-config
  
  # Decode a token
  python func_test_scripts/mock_jwt_generator.py --decode "eyJhbGciOiJI..."
  
  # Show token details
  python func_test_scripts/mock_jwt_generator.py --email admin@test.com --details

⚠️  SECURITY WARNING:
  - The secret key is embedded in this script
  - Do not commit this to public repositories
  - Keep this file secure
        """
    )
    
    parser.add_argument('--email', help='Email for token payload')
    parser.add_argument('--sub', help='Subject UUID (user ID). Auto-generated if not provided')
    parser.add_argument('--role-id', help='Role UUID. Auto-generated if not provided')
    parser.add_argument('--role', default='SUPER_ADMIN', help='User role (default: SUPER_ADMIN)')
    parser.add_argument('--hours', type=int, default=24, help='Token validity in hours (default: 24)')
    parser.add_argument('--secret', default=DEFAULT_SECRET_KEY, help='Secret key for signing (default: production key)')
    parser.add_argument('--decode', help='Decode and display a JWT token')
    parser.add_argument('--details', action='store_true', help='Show detailed token information')
    parser.add_argument('--save-config', action='store_true', help='Save token to config file automatically')
    parser.add_argument('--config-path', default='resources/registry/subscribe/test_subscribe_functional.yml', 
                       help='Path to config file (default: resources/registry/subscribe/test_subscribe_functional.yml)')
    
    args = parser.parse_args()
    
    generator = JWTGenerator(secret_key=args.secret)
    
    if args.decode:
        # Decode mode
        print("🔍 Decoding JWT Token")
        print("="*70)
        try:
            payload = generator.decode_token(args.decode, verify=False)
            print("\n📋 Token Payload:")
            print(json.dumps(payload, indent=2))
            
            # Check expiry
            if 'exp' in payload:
                exp_time = datetime.fromtimestamp(payload['exp'])
                now = datetime.utcnow()
                if exp_time > now:
                    remaining = exp_time - now
                    print(f"\n✅ Token valid for: {remaining}")
                else:
                    print(f"\n❌ Token expired at: {exp_time}")
        except Exception as e:
            print(f"\n❌ Error: {str(e)}")
        return
    
    if not args.email:
        print("❌ Error: --email is required for token generation")
        parser.print_help()
        return
    
    # Generate mode
    print("✅ JWT TOKEN GENERATOR - PRODUCTION SECRET KEY")
    print("="*70)
    print("\n✅ This generates VALID tokens for the auth service!")
    print("Using actual production secret key.")
    print("="*70)
    
    token, payload = generator.generate_token(
        email=args.email,
        role=args.role,
        sub=args.sub,
        role_id=args.role_id
    )
    
    print(f"\n📧 Email: {args.email}")
    print(f"🆔 Subject (User UUID): {payload.get('sub')}")
    print(f"👤 Role: {args.role}")
    print(f"🎭 Role ID (UUID): {payload.get('roleId')}")
    print(f"⏰ Expires in: {args.hours} hours")
    
    exp_time = datetime.fromtimestamp(payload['exp'])
    print(f"📅 Expires at: {exp_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    if args.details:
        print(f"\n📋 Payload:")
        print(json.dumps(payload, indent=2))
    
    print(f"\n🔑 Token (first 50 chars):")
    print(f"{token[:50]}...")
    
    print(f"\n📄 Full Token:")
    print(token)
    
    # Save to config if requested
    if args.save_config:
        try:
            import yaml
            config_path = args.config_path
            
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            if 'ondcRegistry' in config:
                config['ondcRegistry']['admin_token'] = token
                
                with open(config_path, 'w') as f:
                    yaml.dump(config, f, default_flow_style=False, sort_keys=False)
                
                print(f"\n✅ Token saved to config: {config_path}")
                print(f"📝 Updated: ondcRegistry.admin_token")
            else:
                print(f"\n⚠️  Warning: 'ondcRegistry' section not found in config")
        except Exception as e:
            print(f"\n❌ Failed to save to config: {str(e)}")
    
    print("\n" + "="*70)
    print("✅ TOKEN VALIDITY:")
    print("="*70)
    print("\n✅ This token WILL work with:")
    print("  • https://authservice.kynondc.net (auth service)")
    print("  • http://34.14.152.92 (registry with external auth)")
    print("  • Any server using the same secret key")
    
    print("\n🎯 NEXT STEPS:")
    if not args.save_config:
        print("  1. Copy the token above")
        print(f"  2. Edit: {args.config_path}")
        print("  3. Set: admin_token: \"<paste-token-here>\"")
        print("  4. Run tests!")
        print("\n  OR run with --save-config to auto-update:")
        print(f"  python func_test_scripts/mock_jwt_generator.py --email {args.email} --save-config")
    else:
        print("  ✅ Token already saved to config!")
        print("  🚀 Run tests now:")
        print("  python driver.py --test ondc_policy_functional --environment ondcRegistry --users 1 --iterations 1 --autostart --autoquit 1")
    
    print("\n⚠️  SECURITY REMINDER:")
    print("  • Keep the secret key secure")
    print("  • Don't commit tokens/secrets to git")
    print("  • Tokens expire after configured time")
    print("="*70)


if __name__ == "__main__":
    main()
