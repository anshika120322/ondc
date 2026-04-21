"""
Enhanced HTTP Client with Admin JWT and V3 ONDC Signature Support

Unified HTTP client that handles both authentication schemes automatically.
"""

import requests
import urllib3
from typing import Dict, Optional, Any, Literal
from ..auth.admin_auth import AdminAuth
from ..auth.ondc_signature import ONDCAuthManager

# Disable SSL warnings for UAT environment with self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


AuthType = Literal["admin", "v3", "none"]


class HTTPClient:
    """
    Enhanced HTTP Client with multi-auth support.
    
    Supports:
    - Admin JWT authentication (auto-login/refresh)
    - V3 ONDC Ed25519 signature authentication
    - Unauthenticated requests
    """
    
    def __init__(self, base_url: str, admin_username: str = "admin", admin_password: str = "admin123",
                 auth_url: Optional[str] = None,
                 username_field: str = "username", password_field: str = "password",
                 token_field: str = "access_token", verify_ssl: bool = False):
        """
        Initialize HTTP client.
        
        Args:
            base_url: Base URL of the registry API
            admin_username: Admin username/email value for JWT auth
            admin_password: Admin password value for JWT auth
            auth_url: Optional external auth service login URL passed to AdminAuth
            username_field: Payload key for the username credential (e.g. "email")
            password_field: Payload key for the password credential
            token_field: Key name for the token in the login response (e.g. "accessToken")
            verify_ssl: Whether to verify SSL certificates (default: False for UAT compatibility)
        """
        self.base_url = base_url.rstrip('/')
        self.admin_auth = AdminAuth(base_url, admin_username, admin_password,
                                    auth_url=auth_url,
                                    username_field=username_field,
                                    password_field=password_field,
                                    token_field=token_field,
                                    verify_ssl=verify_ssl)
        self.ondc_auth = ONDCAuthManager()
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/json'
        })
    
    def register_v3_participant(
        self,
        subscriber_id: str,
        unique_key_id: str,
        private_key_pem: Optional[str] = None,
        private_key_seed: Optional[bytes] = None
    ):
        """
        Register a V3 participant for ONDC signature authentication.
        
        Args:
            subscriber_id: Subscriber ID for the participant
            unique_key_id: Unique key identifier
            private_key_pem: Optional existing private key (PEM format, generates new if None)
            private_key_seed: Optional 32-byte private key seed (alternative to PEM)
        """
        self.ondc_auth.register_participant(subscriber_id, unique_key_id, private_key_pem, private_key_seed)
    
    def get_v3_public_key(self, subscriber_id: str) -> Optional[Dict]:
        """
        Get public key for a registered V3 participant.
        
        Args:
            subscriber_id: Subscriber ID
            
        Returns:
            Public key data dictionary or None if not registered
        """
        signer = self.ondc_auth.get_signer(subscriber_id)
        if signer:
            return signer.get_public_key_for_registration()
        return None

    def get_v3_full_key_info(self, subscriber_id: str) -> Optional[Dict]:
        """
        Get complete key pair info (public + private) for a registered V3 participant.
        Useful for capturing generated keys in test output so they can be reused.

        Args:
            subscriber_id: Subscriber ID

        Returns:
            Dictionary with full key data including private_key_pem, or None if not registered
        """
        signer = self.ondc_auth.get_signer(subscriber_id)
        if not signer:
            return None
        pub_key_data = signer.get_public_key_for_registration()
        return {
            "subscriber_id": subscriber_id,
            "unique_key_id": signer.unique_key_id,
            "private_key_b64": signer.get_private_key_seed_b64(),
            "private_key_pem": signer.get_private_key_pem(),
            "signing_public_key": pub_key_data.get("signing_public_key"),
            "encryption_public_key": pub_key_data.get("encryption_public_key"),
            "signed_algorithm": pub_key_data.get("signed_algorithm"),
            "encryption_algorithm": pub_key_data.get("encryption_algorithm"),
            "valid_from": pub_key_data.get("valid_from"),
            "valid_until": pub_key_data.get("valid_until"),
        }
    
    def _get_auth_headers(
        self,
        auth_type: AuthType,
        subscriber_id: Optional[str] = None,
        method: str = "GET",
        path: str = "/",
        body: Optional[Dict] = None,
        invalid_signature: bool = False
    ) -> Dict[str, str]:
        """
        Get authentication headers based on auth type.
        
        Args:
            auth_type: Type of authentication ("admin", "v3", "v3_lookup", "none")
            subscriber_id: Required for V3 auth (or pre-registered participant for v3_lookup)
            method: HTTP method (for V3 signature)
            path: Request path (for V3 signature)
            body: Request body (for V3 signature)
            
        Returns:
            Dictionary of headers
        """
        headers = {}
        
        if auth_type == "admin":
            headers.update(self.admin_auth.get_auth_header())
        
        elif auth_type in ("v3", "v3_lookup"):
            if not subscriber_id:
                raise ValueError(f"subscriber_id required for {auth_type} authentication")
            
            v3_headers = self.ondc_auth.create_auth_header(
                subscriber_id,
                body=body,
                method=method,
                path=path,
                invalid=invalid_signature
            )
            headers.update(v3_headers)
        
        # auth_type == "none" returns empty headers
        
        return headers
    
    def request(
        self,
        method: str,
        endpoint: str,
        auth_type: AuthType = "none",
        subscriber_id: Optional[str] = None,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        timeout: int = 30,
        invalid_signature: bool = False
    ) -> requests.Response:
        """
        Make HTTP request with appropriate authentication.
        
        Args:
            method: HTTP method (GET, POST, PATCH, DELETE, etc.)
            endpoint: API endpoint path (e.g., "/admin/subscribe")
            auth_type: Authentication type ("admin", "v3", "v3_lookup", "none")
            subscriber_id: Subscriber ID (required for V3 and v3_lookup auth)
            data: Request body data
            params: Query parameters
            headers: Additional headers
            timeout: Request timeout in seconds
            invalid_signature: If True, generate intentionally invalid signature for testing (V3 only)
            
        Returns:
            Response object
        """
        url = endpoint if endpoint.startswith("http") else f"{self.base_url}{endpoint}"
        
        # Get authentication headers
        auth_headers = self._get_auth_headers(
            auth_type=auth_type,
            subscriber_id=subscriber_id,
            method=method,
            path=endpoint,
            body=data,  # Pass the dict, ONDC signature will serialize it
            invalid_signature=invalid_signature
        )
        
        # Merge headers
        request_headers = {**self.session.headers, **auth_headers}
        if headers:
            request_headers.update(headers)
        
        # Debug V00 specifically
        import json as json_module
        print(f"    [HTTP] {method} {url}")
        print(f"    [HTTP] Auth type: {auth_type}")
        if auth_headers:
            print(f"    [HTTP] Auth headers: {list(auth_headers.keys())}")
        if data:
            print(f"    [HTTP] Body size: {len(json_module.dumps(data, separators=(', ', ': ')))} bytes")
            if isinstance(data, dict):
                print(f"    [HTTP] Body keys: {list(data.keys())[:5]}...")
            else:
                print(f"    [HTTP] Body type: {type(data).__name__}, length: {len(data)}")
        
        # Prepare and send request
        # NOTE: Creating a fresh session per request to avoid connection pool issues
        # that occur when reusing self.session in certain contexts
        try:
            req = requests.Request(method, url, json=data, params=params, headers=request_headers)
            prepared = req.prepare()
            
            print(f"    [HTTP] Prepared request - Content-Length: {prepared.headers.get('Content-Length')}")
            
            session = requests.Session()
            response = session.send(prepared, timeout=timeout, verify=False)
            
            print(f"    [HTTP] Response: {response.status_code}")
            return response
        except Exception as e:
            print(f"    [HTTP] ERROR: {type(e).__name__}: {str(e)[:100]}")
            raise
    
    def get(self, endpoint: str, auth_type: AuthType = "none", **kwargs) -> requests.Response:
        """GET request."""
        return self.request("GET", endpoint, auth_type=auth_type, **kwargs)
    
    def post(self, endpoint: str, auth_type: AuthType = "none", **kwargs) -> requests.Response:
        """POST request."""
        return self.request("POST", endpoint, auth_type=auth_type, **kwargs)
    
    def patch(self, endpoint: str, auth_type: AuthType = "none", **kwargs) -> requests.Response:
        """PATCH request."""
        return self.request("PATCH", endpoint, auth_type=auth_type, **kwargs)
    
    def delete(self, endpoint: str, auth_type: AuthType = "none", **kwargs) -> requests.Response:
        """DELETE request."""
        return self.request("DELETE", endpoint, auth_type=auth_type, **kwargs)
    
    def admin_login(self) -> bool:
        """Explicitly trigger admin login."""
        return self.admin_auth.login()
    
    def close(self):
        """Close the session."""
        self.session.close()
