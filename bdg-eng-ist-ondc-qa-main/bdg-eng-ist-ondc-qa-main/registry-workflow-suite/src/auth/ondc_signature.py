"""
ONDC Ed25519 Signature Authentication Module

Implements the ONDC protocol signature scheme for V3 API authentication.
Generates Ed25519 signatures and constructs the Signature authorization header.
"""

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple, Union
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


class ONDCSignature:
    """
    ONDC Signature Generator for V3 API Authentication
    
    Implements Ed25519 signature generation following ONDC protocol specification:
    1. Create signing string from request components
    2. Generate Ed25519 signature
    3. Construct Signature authorization header
    """
    
    def __init__(self, subscriber_id: str, unique_key_id: str, private_key_pem: Optional[str] = None, private_key_seed: Optional[bytes] = None):
        """
        Initialize ONDC signature generator.
        
        Args:
            subscriber_id: Unique subscriber ID (e.g., "buyer-app.example.com")
            unique_key_id: Unique key identifier used in registry
            private_key_pem: PEM-encoded Ed25519 private key (if None, generates new key)
            private_key_seed: 32-byte seed for Ed25519 key generation (alternative to PEM)
        
        Note:
            If both private_key_pem and private_key_seed are provided, private_key_seed takes precedence
        """
        self.subscriber_id = subscriber_id
        self.unique_key_id = unique_key_id
        
        if private_key_seed:
            # Generate key from seed (same as ONDCAuthHelper)
            if not isinstance(private_key_seed, bytes) or len(private_key_seed) != 32:
                raise ValueError(f"private_key_seed must be exactly 32 bytes, got {len(private_key_seed) if isinstance(private_key_seed, bytes) else 'non-bytes'}")
            self.private_key = Ed25519PrivateKey.from_private_bytes(private_key_seed)
        elif private_key_pem:
            self.private_key = serialization.load_pem_private_key(
                private_key_pem.encode(), password=None
            )
        else:
            # Generate new Ed25519 key pair for testing
            self.private_key = Ed25519PrivateKey.generate()
        
        # Get public key for verification
        self.public_key = self.private_key.public_key()
        self.public_key_b64 = self._get_public_key_b64()
    
    def _get_public_key_b64(self) -> str:
        """Get DER/SPKI-encoded public key (base64), matching ONDC standard and registry /public/keys format."""
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_bytes).decode('utf-8')
    
    def _create_digest(self, body: Optional[Union[Dict, str, bytes]] = None) -> str:
        """
        Create BLAKE2b-512 digest of request body.

        Args:
            body: Request body as a dict, already-serialized str/bytes, or None for requests with no body.
                  Pass the exact bytes/string being sent on the wire to guarantee the digest matches.

        Returns:
            Base64-encoded BLAKE2b-512 digest
        """
        if body is None or body == {} or body == b'' or body == '':
            raw = b''
        elif isinstance(body, bytes):
            raw = body
        elif isinstance(body, str):
            raw = body.encode('utf-8')
        else:
            # Dict: serialize the same way requests.post(json=body) does —
            # json.dumps default separators are (', ', ': ') in Python 3.
            raw = json.dumps(body, separators=(', ', ': '), sort_keys=False).encode('utf-8')

        digest = hashlib.blake2b(raw, digest_size=64).digest()
        return base64.b64encode(digest).decode('utf-8')
    
    def _create_signing_string(
        self,
        created: int,
        expires: int,
        digest: str,
        method: str = "POST",
        path: str = "/api/v3/subscribe"
    ) -> str:
        """
        Create the signing string according to ONDC spec.
        
        Format:
        (created): <timestamp>
        (expires): <timestamp>
        digest: BLAKE-512=<digest>
        
        Args:
            created: Unix timestamp when signature was created
            expires: Unix timestamp when signature expires
            digest: Base64-encoded BLAKE2b digest
            method: HTTP method (POST, PATCH, etc.)
            path: Request path
            
        Returns:
            Formatted signing string
        """
        parts = [
            f"(created): {created}",
            f"(expires): {expires}",
            f"digest: BLAKE-512={digest}"
        ]
        return '\n'.join(parts)
    
    def _sign_string(self, signing_string: str) -> str:
        """
        Sign the signing string with Ed25519 private key.
        
        Args:
            signing_string: String to sign
            
        Returns:
            Base64-encoded signature
        """
        signature = self.private_key.sign(signing_string.encode('utf-8'))
        return base64.b64encode(signature).decode('utf-8')
    
    def generate_signature_header(
        self,
        body: Optional[Union[Dict, str, bytes]] = None,
        method: str = "POST",
        path: str = "/api/v3/subscribe",
        validity_seconds: int = 300,
        invalid: bool = False
    ) -> Tuple[str, str, int, int]:
        """
        Generate complete Signature authorization header and Digest header.
        
        ONDC Signature Format:
        Signature keyId="{subscriber_id}|{unique_key_id}|ed25519",
                  algorithm="ed25519",
                  created=<timestamp>,
                  expires=<timestamp>,
                  headers="(created) (expires) digest",
                  signature="<base64_signature>"
        
        Args:
            body: Request body dictionary
            method: HTTP method
            path: Request path
            validity_seconds: Signature validity duration (default 5 minutes)
            invalid: If True, generate an intentionally invalid signature for testing
            
        Returns:
            Tuple of (authorization_header, digest_header, created_timestamp, expires_timestamp)
        """
        # Generate timestamps
        now = datetime.now(timezone.utc)
        created = int(now.timestamp())
        expires = created + validity_seconds
        
        # Create digest
        digest = self._create_digest(body)
        digest_header = f"BLAKE-512={digest}"
        
        # Create signing string
        signing_string = self._create_signing_string(created, expires, digest, method, path)
        
        # Generate signature
        signature = self._sign_string(signing_string)
        
        # Corrupt signature if invalid flag is set
        if invalid:
            # Corrupt the signature by flipping some bytes
            sig_bytes = base64.b64decode(signature)
            # Flip first 4 bytes to make it invalid
            corrupted = bytes([b ^ 0xFF for b in sig_bytes[:4]]) + sig_bytes[4:]
            signature = base64.b64encode(corrupted).decode('utf-8')
        
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
    
    def get_public_key_for_registration(self) -> Dict:
        """
        Get public key in format suitable for participant registration.
        
        Returns:
            Dictionary with key data for /api/v3/subscribe request
        """
        return {
            "signing_public_key": self.public_key_b64,
            "encryption_public_key": self.public_key_b64,  # Same key for simplicity in tests
            "signed_algorithm": "ED25519",
            "encryption_algorithm": "X25519",
            "valid_from": datetime.now(timezone.utc).isoformat(),
            "valid_until": datetime(2030, 12, 31, 23, 59, 59, tzinfo=timezone.utc).isoformat()
        }
    
    def get_private_key_pem(self) -> str:
        """Get PEM-encoded private key for storage/reuse."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

    def get_private_key_seed_b64(self) -> str:
        """Get raw 32-byte Ed25519 seed as base64.
        
        This is the format expected by /signature/generate as `private_key_b64`.
        The PEM/PKCS8 format encodes to 48 bytes and will be rejected by the server.
        """
        seed_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        return base64.b64encode(seed_bytes).decode('utf-8')


class ONDCAuthManager:
    """
    Manages ONDC authentication credentials for multiple participants.
    Handles key generation, storage, and signature generation.
    """
    
    def __init__(self):
        """Initialize the auth manager."""
        self.participants: Dict[str, ONDCSignature] = {}
    
    def register_participant(
        self,
        subscriber_id: str,
        unique_key_id: str,
        private_key_pem: Optional[str] = None,
        private_key_seed: Optional[bytes] = None
    ) -> ONDCSignature:
        """
        Register a participant and generate/store their signing credentials.
        
        Args:
            subscriber_id: Unique subscriber ID
            unique_key_id: Unique key identifier
            private_key_pem: Optional existing private key (PEM format)
            private_key_seed: Optional 32-byte private key seed (alternative to PEM)
            
        Returns:
            ONDCSignature instance for this participant
        """
        signer = ONDCSignature(subscriber_id, unique_key_id, private_key_pem, private_key_seed)
        self.participants[subscriber_id] = signer
        return signer
    
    def get_signer(self, subscriber_id: str) -> Optional[ONDCSignature]:
        """Get signature generator for a registered participant."""
        return self.participants.get(subscriber_id)
    
    def create_auth_header(
        self,
        subscriber_id: str,
        body: Optional[Dict] = None,
        method: str = "POST",
        path: str = "/api/v3/subscribe",
        invalid: bool = False
    ) -> Dict[str, str]:
        """
        Create authorization and digest headers for a participant.
        
        Args:
            subscriber_id: Participant subscriber ID
            body: Request body
            method: HTTP method
            path: Request path
            invalid: If True, generate an intentionally invalid signature for testing
            
        Returns:
            Dictionary with 'Authorization' and 'Digest' headers
            
        Raises:
            ValueError: If participant not registered
        """
        signer = self.get_signer(subscriber_id)
        if not signer:
            raise ValueError(f"Participant {subscriber_id} not registered with auth manager")
        
        auth_header, digest_header, _, _ = signer.generate_signature_header(body, method, path, invalid=invalid)
        return {
            'Authorization': auth_header,
            'Digest': digest_header
        }


def hex_seed_to_pem(hex_seed: str) -> str:
    """
    Convert a hex-encoded Ed25519 private key seed to PEM format.
    
    Args:
        hex_seed: 64-character hex string (32 bytes)
        
    Returns:
        PEM-encoded private key string
        
    Raises:
        ValueError: If hex_seed is invalid
    """
    try:
        # Convert hex to bytes
        seed_bytes = bytes.fromhex(hex_seed)
        if len(seed_bytes) != 32:
            raise ValueError(f"Private key seed must be 32 bytes, got {len(seed_bytes)}")
        
        # Create Ed25519 private key from seed
        private_key = Ed25519PrivateKey.from_private_bytes(seed_bytes)
        
        # Convert to PEM format
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return pem.decode('utf-8')
    except ValueError as e:
        raise ValueError(f"Invalid hex seed: {e}")
    except Exception as e:
        raise ValueError(f"Failed to convert hex seed to PEM: {e}")
