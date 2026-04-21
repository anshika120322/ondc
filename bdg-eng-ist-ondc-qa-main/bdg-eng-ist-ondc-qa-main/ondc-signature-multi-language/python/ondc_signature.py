"""
ONDC Ed25519 Signature Authentication Module - Python Reference Implementation

Implements the ONDC protocol signature scheme for V3 API authentication.
"""

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple, Union
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


class ONDCSignature:
    """ONDC Signature Generator for V3 API Authentication"""
    
    def __init__(self, subscriber_id: str, unique_key_id: str, private_key_seed: bytes):
        """
        Initialize ONDC signature generator.
        
        Args:
            subscriber_id: Unique subscriber ID
            unique_key_id: Unique key identifier
            private_key_seed: 32-byte seed for Ed25519 key generation
        """
        self.subscriber_id = subscriber_id
        self.unique_key_id = unique_key_id
        
        if not isinstance(private_key_seed, bytes) or len(private_key_seed) != 32:
            raise ValueError(f"private_key_seed must be exactly 32 bytes, got {len(private_key_seed)}")
        
        self.private_key = Ed25519PrivateKey.from_private_bytes(private_key_seed)
        self.public_key = self.private_key.public_key()
        self.public_key_b64 = self._get_public_key_b64()
    
    def _get_public_key_b64(self) -> str:
        """Get DER/SPKI-encoded public key (base64)."""
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_bytes).decode('utf-8')
    
    def _create_digest(self, body: Optional[Union[Dict, str, bytes]] = None) -> str:
        """Create BLAKE2b-512 digest of request body."""
        if body is None or body == {} or body == b'' or body == '':
            raw = b''
        elif isinstance(body, bytes):
            raw = body
        elif isinstance(body, str):
            raw = body.encode('utf-8')
        else:
            raw = json.dumps(body, separators=(', ', ': '), sort_keys=True, ensure_ascii=False).encode('utf-8')

        digest = hashlib.blake2b(raw, digest_size=64).digest()
        return base64.b64encode(digest).decode('utf-8')
    
    def _create_signing_string(self, created: int, expires: int, digest: str) -> str:
        """Create the signing string according to ONDC spec."""
        return f"(created): {created}\n(expires): {expires}\ndigest: BLAKE-512={digest}"
    
    def _sign_string(self, signing_string: str) -> str:
        """Sign the signing string with Ed25519 private key."""
        signature = self.private_key.sign(signing_string.encode('utf-8'))
        return base64.b64encode(signature).decode('utf-8')
    
    def generate_signature_header(
        self,
        body: Optional[Union[Dict, str, bytes]] = None,
        created: Optional[int] = None,
        expires: Optional[int] = None
    ) -> Tuple[str, str, int, int]:
        """
        Generate complete Signature authorization header and Digest header.
        
        Returns:
            Tuple of (authorization_header, digest_header, created_timestamp, expires_timestamp)
        """
        # Generate timestamps
        if created is None:
            now = datetime.now(timezone.utc)
            created = int(now.timestamp())
        if expires is None:
            # 60-second validity window (ONDC recommended: 30-60 seconds)
            expires = created + 60
        
        # Create digest
        digest = self._create_digest(body)
        digest_header = f"BLAKE-512={digest}"
        
        # Create signing string
        signing_string = self._create_signing_string(created, expires, digest)
        
        # Generate signature
        signature = self._sign_string(signing_string)
        
        # Construct Signature header
        key_id = f"{self.subscriber_id}|{self.unique_key_id}|ed25519"
        
        header = (
            f'Signature keyId="{key_id}",'
            f'algorithm="ed25519",'
            f'created="{created}",'
            f'expires="{expires}",'
            f'headers="(created) (expires) digest",'
            f'signature="{signature}"'
        )
        
        return header, digest_header, created, expires
