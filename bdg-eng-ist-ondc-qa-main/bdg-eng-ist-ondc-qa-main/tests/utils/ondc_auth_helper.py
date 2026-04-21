"""
ONDC Authentication Helper
Generates BLAKE2b-512 digest and Ed25519 signatures for ONDC API requests
"""

import json
import time
import base64
import hashlib
import logging
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

logger = logging.getLogger(__name__)


class ONDCAuthHelper:
    """Helper class to generate ONDC authentication headers"""
    
    def __init__(self, participant_id: str, uk_id: str, private_key_seed: bytes):
        """
        Initialize the auth helper
        
        Args:
            participant_id: ONDC participant ID (e.g., "buyer-1.bap.ondc")
            uk_id: Unique key ID (e.g., "buyer-key-001")
            private_key_seed: 32-byte seed for Ed25519 key (REQUIRED)
        
        Raises:
            ValueError: If inputs are invalid
        """
        if not participant_id or not isinstance(participant_id, str):
            raise ValueError("participant_id must be a non-empty string")
        if not uk_id or not isinstance(uk_id, str):
            raise ValueError("uk_id must be a non-empty string")
        if not private_key_seed:
            raise ValueError("private_key_seed is required. Do not use hardcoded keys in production.")
        if not isinstance(private_key_seed, bytes) or len(private_key_seed) != 32:
            raise ValueError(f"private_key_seed must be exactly 32 bytes, got {len(private_key_seed) if isinstance(private_key_seed, bytes) else 'non-bytes'}")
        
        self.participant_id = participant_id
        self.uk_id = uk_id
        
        # Generate keypair from seed
        self.private_key = Ed25519PrivateKey.from_private_bytes(private_key_seed)
        self.public_key = self.private_key.public_key()
    
    def blake2b_512_digest(self, data: bytes) -> str:
        """
        Compute BLAKE2b-512 digest
        
        Args:
            data: Bytes to hash
            
        Returns:
            Base64-encoded digest string
        """
        h = hashlib.blake2b(data, digest_size=64)
        return base64.b64encode(h.digest()).decode('utf-8')
    
    def generate_headers(self, payload: dict, ttl: int = 300, include_digest: bool = True) -> dict:
        """
        Generate Authorization headers for ONDC request.

        Args:
            payload: Request payload dictionary
            ttl: Time-to-live in seconds (default: 300)
            include_digest: Whether to include BLAKE2b-512 digest in the signing
                string and as a separate Digest header (default: True).
                Set to False for APIs that no longer require digest (e.g. /search).

        Returns:
            Dictionary with Authorization, Content-Type, and optionally Digest headers.

        Raises:
            ValueError: If ttl is invalid
        """
        if ttl <= 0:
            raise ValueError(f"ttl must be positive, got {ttl}")

        # CRITICAL: Use sort_keys=False to match server expectations (dev's working script)
        # Pre-serialize JSON to ensure the body sent matches what was signed
        payload_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False).encode('utf-8')

        # Timestamps
        created = int(time.time())
        expires = created + ttl

        if include_digest:
            # Compute digest and include it in the signing string
            digest_b64 = self.blake2b_512_digest(payload_bytes)
            signing_string = f"(created): {created}\n(expires): {expires}\ndigest: BLAKE-512={digest_b64}"
            headers_field = '(created) (expires) digest'
        else:
            digest_b64 = None
            signing_string = f"(created): {created}\n(expires): {expires}"
            headers_field = '(created) (expires)'

        # Sign with Ed25519
        signature = self.private_key.sign(signing_string.encode('utf-8'))
        signature_b64 = base64.b64encode(signature).decode('utf-8')

        # Build Authorization header
        # Registry requires created and expires as quoted strings
        key_id = f"{self.participant_id}|{self.uk_id}|ed25519"
        auth_header = (
            f'Signature keyId="{key_id}",'
            f'algorithm="ed25519",'
            f'created="{created}",'
            f'expires="{expires}",'
            f'headers="{headers_field}",'
            f'signature="{signature_b64}"'
        )

        result = {
            'Authorization': auth_header,
            'Content-Type': 'application/json',
            'serialized_body': payload_bytes.decode('utf-8')  # Return pre-serialized JSON for V3 requests
        }

        if include_digest:
            result['Digest'] = f'BLAKE-512={digest_b64}'

        return result
    
    def get_public_key_base64(self) -> str:
        """
        Get the public key in base64 format
        
        Returns:
            Base64-encoded public key
        """
        from cryptography.hazmat.primitives import serialization
        
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return base64.b64encode(public_bytes).decode('utf-8')
