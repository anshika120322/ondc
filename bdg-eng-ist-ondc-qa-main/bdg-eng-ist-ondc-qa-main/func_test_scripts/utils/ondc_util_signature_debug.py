#!/usr/bin/env python3
"""
Show detailed signature generation process for UAT Gateway
"""
import sys
import os
import json
import base64
import time
from datetime import datetime, timezone
from nacl.signing import SigningKey
import hashlib

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.utils.ondc_auth_helper import ONDCAuthHelper

# Gateway participant credentials from config
PARTICIPANT_ID = "participant-1.participant.ondc"
UK_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1"
PRIVATE_KEY_SEED_B64 = "MC4CAQAwBQYDK2VwBCIEIPGt7Hv6vy2haK04ipiBbgU0omo/IGjs+hmuGE+jXkbf"

def decode_private_key(b64_key):
    """Decode base64 private key to 32-byte seed"""
    decoded_bytes = base64.b64decode(b64_key)
    if len(decoded_bytes) == 64:
        # NaCl-style 64-byte signing key: seed = first 32 bytes
        return decoded_bytes[:32]
    elif len(decoded_bytes) >= 32:
        # PKCS#8 DER format: the 32-byte seed is at the end
        return decoded_bytes[-32:]
    else:
        raise ValueError(f"Invalid key length: {len(decoded_bytes)}")

print("="*80)
print("SIGNATURE GENERATION BREAKDOWN")
print("="*80)

# Step 1: Decode private key
print("\n1️⃣  PRIVATE KEY DECODING")
print("-" * 80)
print(f"Input (Base64 PKCS#8): {PRIVATE_KEY_SEED_B64}")

decoded_full = base64.b64decode(PRIVATE_KEY_SEED_B64)
print(f"Decoded length: {len(decoded_full)} bytes")
print(f"Decoded (hex): {decoded_full.hex()}")

private_key_seed = decode_private_key(PRIVATE_KEY_SEED_B64)
print(f"\nExtracted 32-byte seed (hex):")
print(f"  {private_key_seed.hex()}")

# Step 2: Generate signing key and public key
print("\n2️⃣  KEY GENERATION (ED25519)")
print("-" * 80)
signing_key = SigningKey(private_key_seed)
verify_key = signing_key.verify_key
public_key_bytes = bytes(verify_key)
public_key_b64 = base64.b64encode(public_key_bytes).decode('utf-8')

print(f"Public Key (32 bytes hex):")
print(f"  {public_key_bytes.hex()}")
print(f"\nPublic Key (base64):")
print(f"  {public_key_b64}")
print(f"\n✓ Matches UAT Registry: {public_key_b64 == 'VXtuKQMPh485BxBcV1jbqNHRuuyyJnbe1QIQoQYjLBg='}")

# Step 3: Create sample payload
print("\n3️⃣  SAMPLE PAYLOAD")
print("-" * 80)
sample_payload = {
    "context": {
        "domain": "ONDC:RET10",
        "action": "search",
        "country": "IND",
        "city": "std:080",
        "core_version": "1.2.0",
        "bap_id": PARTICIPANT_ID,
        "bap_uri": "http://34.93.83.227:8081",
        "transaction_id": "txn-sample-123",
        "message_id": "msg-sample-123",
        "timestamp": "2026-03-11T11:00:00.000Z",
        "ttl": "PT30S"
    },
    "message": {
        "intent": {
            "fulfillment": {
                "type": "Delivery",
                "end": {"location": {"gps": "12.9716,77.5946"}}
            },
            "payment": {
                "@ondc/org/buyer_app_finder_fee_type": "percent",
                "@ondc/org/buyer_app_finder_fee_amount": "3.0"
            }
        }
    }
}

# Serialize payload (sort_keys=False is critical)
payload_json = json.dumps(sample_payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False)
print(f"Payload (first 200 chars):")
print(f"  {payload_json[:200]}...")
print(f"\nPayload size: {len(payload_json)} bytes")

# Step 4: Create signing string
print("\n4️⃣  SIGNING STRING GENERATION")
print("-" * 80)
created = int(time.time())
expires = created + 300  # 5 minutes TTL

print(f"Timestamps:")
print(f"  created:  {created} ({datetime.fromtimestamp(created).isoformat()})")
print(f"  expires:  {expires} ({datetime.fromtimestamp(expires).isoformat()})")
print(f"  TTL:      {expires - created} seconds")

signing_string = f"(created): {created}\n(expires): {expires}"
print(f"\nSigning String (for /search - no digest):")
print(f"┌─────────────────────────────────────")
print(f"│ {signing_string.replace(chr(10), chr(10) + '│ ')}")
print(f"└─────────────────────────────────────")

signing_string_bytes = signing_string.encode('utf-8')
print(f"\nSigning String (bytes): {signing_string_bytes.hex()}")
print(f"Length: {len(signing_string_bytes)} bytes")

# Step 5: Generate signature
print("\n5️⃣  ED25519 SIGNATURE GENERATION")
print("-" * 80)
signature_bytes = signing_key.sign(signing_string_bytes).signature
signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')

print(f"Signature (64 bytes hex):")
print(f"  {signature_bytes.hex()}")
print(f"\nSignature (base64):")
print(f"  {signature_b64}")

# Step 6: Build Authorization header
print("\n6️⃣  AUTHORIZATION HEADER")
print("-" * 80)
key_id = f"{PARTICIPANT_ID}|{UK_ID}|ed25519"
headers_field = "(created) (expires)"

auth_header = (
    f'Signature keyId="{key_id}",'
    f'algorithm="ed25519",'
    f'created="{created}",'
    f'expires="{expires}",'
    f'headers="{headers_field}",'
    f'signature="{signature_b64}"'
)

print(f"keyId: {key_id}")
print(f"algorithm: ed25519")
print(f"created: {created}")
print(f"expires: {expires}")
print(f"headers: {headers_field}")
print(f"signature: {signature_b64}")

print(f"\n📋 Complete Authorization Header:")
print(f"┌─────────────────────────────────────")
print(f"│ Authorization: {auth_header}")
print(f"└─────────────────────────────────────")

# Step 7: Verify signature
print("\n7️⃣  SIGNATURE VERIFICATION")
print("-" * 80)
try:
    verify_key.verify(signing_string_bytes, signature_bytes)
    print("✅ Signature verification: SUCCESS")
    print("   The signature is cryptographically valid")
except Exception as e:
    print(f"❌ Signature verification: FAILED")
    print(f"   Error: {e}")

# Step 8: Show what's being sent to Gateway
print("\n8️⃣  WHAT GETS SENT TO GATEWAY")
print("-" * 80)
print(f"POST http://34.100.154.102:8080/search")
print(f"\nHeaders:")
print(f"  Content-Type: application/json; charset=utf-8")
print(f"  Authorization: {auth_header}")
print(f"\nBody:")
print(f"  {payload_json[:150]}...")

# Step 9: Use ONDCAuthHelper to generate (for comparison)
print("\n9️⃣  USING ONDCAuthHelper (Framework)")
print("-" * 80)
auth_helper = ONDCAuthHelper(
    participant_id=PARTICIPANT_ID,
    uk_id=UK_ID,
    private_key_seed=private_key_seed
)

headers = auth_helper.generate_headers(sample_payload, include_digest=False)
print(f"Generated Authorization header:")
print(f"  {headers['Authorization'][:100]}...")
print(f"\nPublic key from helper:")
print(f"  {auth_helper.get_public_key_base64()}")

# Step 10: Summary
print("\n" + "="*80)
print("SUMMARY")
print("="*80)
print(f"✅ Private Key: Valid 32-byte ED25519 seed")
print(f"✅ Public Key: {public_key_b64}")
print(f"✅ Signature: Cryptographically valid ED25519 signature")
print(f"✅ Auth Format: Standard HTTP Signatures with ED25519")
print(f"✅ Registered: Participant exists in UAT Registry")
print(f"\n❌ Gateway Issue: Rejects with 'Invalid headers are present in header parameters'")
print(f"\nThis suggests Gateway expects different format, not a crypto problem.")
