#!/usr/bin/env python3
"""
Generate ED25519 Signature for ONDC API Requests

This script generates the Authorization and Digest headers needed for
V2 and V3 lookup API requests in Postman.

Usage:
    # Using command line arguments
    python func_test_scripts/utils/ondc_util_auth_signature.py \
        --participant-id "test-qa-0d4b8d2a.participant.ondc" \
        --uk-id "dfd8e222-8edf-4664-a8bd-53f41e59fb87" \
        --private-key-seed "41164af92f2710c1fa01e5fa29394d0bda79ed0a31d7b4f24a2192e64f157853" \
        --payload '{"country": "IND", "type": "BPP"}'
    
    # Using defaults from config
    python func_test_scripts/utils/ondc_util_auth_signature.py --version v3
    
    # With custom TTL
    python func_test_scripts/utils/ondc_util_auth_signature.py --version v2 --ttl 600 --payload '{"country": "IND"}'

Output:
    Prints Authorization and Digest headers ready to paste into Postman
"""

import argparse
import json
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tests.utils.ondc_auth_helper import ONDCAuthHelper
import yaml


def load_default_config(version: str = 'v3') -> dict:
    """Load default configuration from YAML files"""
    project_root = Path(__file__).parent.parent
    
    if version == 'v1':
        config_path = project_root / 'resources/registry/lookup/v1/test_lookup_v1.yml'
        with open(config_path) as f:
            config = yaml.safe_load(f)
            return config['ondcRegistryV1Lookup']
    elif version == 'v2':
        config_path = project_root / 'resources/registry/lookup/v2/test_lookup_v2.yml'
        with open(config_path) as f:
            config = yaml.safe_load(f)
            return config['ondcRegistryV2Lookup']
    else:  # v3
        config_path = project_root / 'resources/registry/lookup/v3/test_lookup_functional.yml'
        with open(config_path) as f:
            config = yaml.safe_load(f)
            return config['ondcRegistry']


def generate_signature_headers(
    participant_id: str,
    uk_id: str,
    private_key_seed_hex: str,
    payload: dict,
    ttl: int = 300,
    include_digest: bool = True
) -> dict:
    """
    Generate authentication headers for ONDC request
    
    Args:
        participant_id: ONDC participant ID
        uk_id: Unique key ID
        private_key_seed_hex: 32-byte private key seed (hex string)
        payload: Request payload dictionary
        ttl: Time-to-live in seconds
        include_digest: Whether to include digest header
    
    Returns:
        Dictionary with headers
    """
    # Convert hex seed to bytes
    private_key_seed = bytes.fromhex(private_key_seed_hex)
    
    # Initialize auth helper
    auth_helper = ONDCAuthHelper(
        participant_id=participant_id,
        uk_id=uk_id,
        private_key_seed=private_key_seed
    )
    
    # Generate headers
    headers = auth_helper.generate_headers(
        payload=payload,
        ttl=ttl,
        include_digest=include_digest
    )
    
    return headers


def print_headers_for_postman(headers: dict, payload: dict):
    """Print headers in a format easy to copy into Postman"""
    print("\n" + "="*70)
    print("🔐 ONDC API Authentication Headers")
    print("="*70)
    
    print("\n📋 Copy these headers into Postman:\n")
    
    print("Header Name: Content-Type")
    print("Header Value: application/json")
    print()
    
    if 'Authorization' in headers:
        print("Header Name: Authorization")
        print("Header Value:")
        print(headers['Authorization'])
        print()
    
    if 'Digest' in headers:
        print("Header Name: Digest")
        print("Header Value:")
        print(headers['Digest'])
        print()
    
    print("="*70)
    print("📦 Request Body (raw JSON):")
    print("="*70)
    print(json.dumps(payload, indent=2))
    print()
    
    print("="*70)
    print("ℹ️  Instructions:")
    print("="*70)
    print("1. In Postman, go to the Headers tab")
    print("2. Add/Update each header with the values above")
    print("3. In the Body tab, select 'raw' and 'JSON'")
    print("4. Paste the request body shown above")
    print("5. Send the request")
    print()
    print("⏱️  Note: Signature expires in a few minutes. Regenerate if needed.")
    print("="*70)
    print()


def main():
    parser = argparse.ArgumentParser(
        description='Generate ED25519 signature for ONDC API requests',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate for V3 with default config
  python func_test_scripts/utils/ondc_util_auth_signature.py --version v3
  
  # Generate for V2 with custom payload
  python func_test_scripts/utils/ondc_util_auth_signature.py --version v2 --payload '{"country": "IND", "type": "BPP"}'
  
  # Generate with explicit credentials
  python func_test_scripts/utils/ondc_util_auth_signature.py \\
    --participant-id "test-qa-0d4b8d2a.participant.ondc" \\
    --uk-id "dfd8e222-8edf-4664-a8bd-53f41e59fb87" \\
    --private-key-seed "41164af92f2710c1fa01e5fa29394d0bda79ed0a31d7b4f24a2192e64f157853" \\
    --payload '{"country": "IND", "type": "BPP"}'
        """
    )
    
    parser.add_argument(
        '--version',
        choices=['v1', 'v2', 'v3'],
        default='v3',
        help='API version (default: v3)'
    )
    
    parser.add_argument(
        '--participant-id',
        help='ONDC participant ID (optional, uses config default)'
    )
    
    parser.add_argument(
        '--uk-id',
        help='Unique key ID (optional, uses config default)'
    )
    
    parser.add_argument(
        '--private-key-seed',
        help='Private key seed in hex format (optional, uses config default)'
    )
    
    parser.add_argument(
        '--payload',
        help='Request payload as JSON string (optional, uses config default)'
    )
    
    parser.add_argument(
        '--ttl',
        type=int,
        default=300,
        help='Signature time-to-live in seconds (default: 300)'
    )
    
    parser.add_argument(
        '--no-digest',
        action='store_true',
        help='Exclude digest header (some APIs don\'t require it)'
    )
    
    args = parser.parse_args()
    
    # Load default config
    config = load_default_config(args.version)
    
    # Use provided values or fall back to config defaults
    participant_id = args.participant_id or config.get('participant_id')
    uk_id = args.uk_id or config.get('uk_id')
    private_key_seed = args.private_key_seed or config.get('private_key_seed')
    
    # Parse payload
    if args.payload:
        try:
            payload = json.loads(args.payload)
        except json.JSONDecodeError as e:
            print(f"❌ Error: Invalid JSON payload: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        payload = config.get('default_lookup_payload', {'country': 'IND', 'type': 'BPP'})
    
    # Validate required fields
    if not all([participant_id, uk_id, private_key_seed]):
        print("❌ Error: Missing required credentials", file=sys.stderr)
        print("\nProvide credentials via command line or ensure config file has defaults", file=sys.stderr)
        sys.exit(1)
    
    # V1 doesn't use signatures
    if args.version == 'v1':
        print("\n⚠️  V1 API does not require authentication")
        print("\n📋 Just send the payload directly:\n")
        print(json.dumps(payload, indent=2))
        print()
        sys.exit(0)
    
    # Generate headers
    try:
        headers = generate_signature_headers(
            participant_id=participant_id,
            uk_id=uk_id,
            private_key_seed_hex=private_key_seed,
            payload=payload,
            ttl=args.ttl,
            include_digest=not args.no_digest
        )
        
        # Print in Postman-friendly format
        print_headers_for_postman(headers, payload)
        
    except Exception as e:
        print(f"❌ Error generating signature: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
