"""
ONDC-SIG helper — prints a fresh Authorization header for a given request.
Usage:
    python sign.py <subscriber_id> <uk_id> <private_key_seed_b64> <method> <path> <body_json>
Example:
    python sign.py "bpp-prop-inactive-20260331140211.ondc.org" \
                   "41b3f741-b70a-4e4d-8d6b-484c6a45d376" \
                   "MC4CAQAwBQYDK2VwBCIEIPGt7Hv6vy2haK04ipiBbgU0omo/IGjs+hmuGE+jXkbf" \
                   "POST" "/on_search" '{"context":{...}}'
"""
import sys, base64, json
sys.path.insert(0, '..')
sys.path.insert(0, '../../workflow-suite')

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from src.auth.ondc_signature import ONDCAuthManager

def seed_to_pem(seed_b64: str) -> str:
    raw = base64.b64decode(seed_b64 + '==')
    key = Ed25519PrivateKey.from_private_bytes(raw[-32:])
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()

def main():
    if len(sys.argv) < 7:
        print("Usage: python sign.py <subscriber_id> <uk_id> <seed_b64> <method> <path> <body_json>")
        sys.exit(1)

    sub_id, uk_id, seed_b64, method, path, body_json = sys.argv[1:7]
    body = json.loads(body_json)
    pem = seed_to_pem(seed_b64)

    mgr = ONDCAuthManager()
    mgr.register_participant(sub_id, uk_id, pem)
    headers = mgr.create_auth_header(sub_id, body=body, method=method, path=path)
    print(headers['Authorization'])

if __name__ == '__main__':
    main()
