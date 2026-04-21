"""
Enhanced HTTP Client with Admin JWT and V3 ONDC Signature Support

Unified HTTP client that handles both authentication schemes automatically.
"""

import json
import requests
import urllib3
from typing import Dict, Optional, Any, Literal
from ..auth.admin_auth import AdminAuth
from ..auth.ondc_signature import ONDCAuthManager


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
                 token_field: str = "access_token",
                 ssl_verify: bool = True):
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
        """
        self.base_url = base_url.rstrip('/')
        if not ssl_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.admin_auth = AdminAuth(base_url, admin_username, admin_password,
                                    auth_url=auth_url,
                                    username_field=username_field,
                                    password_field=password_field,
                                    token_field=token_field,
                                    ssl_verify=ssl_verify)
        self.ondc_auth = ONDCAuthManager()
        self.session = requests.Session()
        self.session.verify = ssl_verify
        self.session.headers.update({
            'Accept': 'application/json'
        })
    
    def register_v3_participant(
        self,
        subscriber_id: str,
        unique_key_id: str,
        private_key_pem: Optional[str] = None
    ):
        """
        Register a V3 participant for ONDC signature authentication.
        
        Args:
            subscriber_id: Subscriber ID for the participant
            unique_key_id: Unique key identifier
            private_key_pem: Optional existing private key (generates new if None)
        """
        self.ondc_auth.register_participant(subscriber_id, unique_key_id, private_key_pem)
    
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
        invalid_signature: bool = False,
        include_digest: bool = True
    ) -> Dict[str, str]:
        """
        Get authentication headers based on auth type.
        
        Args:
            auth_type: Type of authentication ("admin", "v3", "none")
            subscriber_id: Required for V3 auth
            method: HTTP method (for V3 signature)
            path: Request path (for V3 signature)
            body: Request body (for V3 signature)
            include_digest: If False, omit digest from the ONDC-SIG signing string
                            and headers= field (e.g. for /v3.0/lookup)
            
        Returns:
            Dictionary of headers
        """
        headers = {}
        
        if auth_type == "admin":
            headers.update(self.admin_auth.get_auth_header())
        
        elif auth_type == "v3":
            if not subscriber_id:
                raise ValueError("subscriber_id required for V3 authentication")
            
            v3_headers = self.ondc_auth.create_auth_header(
                subscriber_id,
                body=body,
                method=method,
                path=path,
                invalid=invalid_signature,
                include_digest=include_digest
            )
            v3_headers.pop('Digest', None)
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
        invalid_signature: bool = False,
        include_digest: bool = True
    ) -> requests.Response:
        """
        Make HTTP request with appropriate authentication.
        
        Args:
            method: HTTP method (GET, POST, PATCH, DELETE, etc.)
            endpoint: API endpoint path (e.g., "/admin/subscribe")
            auth_type: Authentication type ("admin", "v3", "none")
            subscriber_id: Subscriber ID (required for V3 auth)
            data: Request body data
            params: Query parameters
            headers: Additional headers
            timeout: Request timeout in seconds
            invalid_signature: If True, generate intentionally invalid signature for testing (V3 only)
            include_digest: If False, omit digest from ONDC-SIG signing string and headers= field
            
        Returns:
            Response object
        """
        url = f"{self.base_url}{endpoint}"
        
        # Get authentication headers
        auth_headers = self._get_auth_headers(
            auth_type=auth_type,
            subscriber_id=subscriber_id,
            method=method,
            path=endpoint,
            body=data,  # Pass the dict, ONDC signature will serialize it
            invalid_signature=invalid_signature,
            include_digest=include_digest
        )
        
        # Merge headers
        request_headers = {**self.session.headers, **auth_headers}
        if headers:
            request_headers.update(headers)
        
        print(f"    [HTTP] {method} {url}")
        print(f"    [HTTP] Auth type: {auth_type}")
        if auth_headers:
            print(f"    [HTTP] Auth headers: {list(auth_headers.keys())}")
        if data:
            print(f"    [HTTP] Body size: {len(json.dumps(data, separators=(',', ':')))} bytes")
            print(f"    [HTTP] Body keys: {list(data.keys())[:5]}...")
        
        # Prepare and send request.
        # ONDC-SIG body digest is computed with compact JSON (separators=(',',':'))
        # matching the func_test_scripts/ondc_gw_*_api_tests.py pattern.  We serialise the
        # body to the same compact bytes and send them as raw data so the Gateway's
        # BLAKE2b verification is exactly over the bytes on the wire.
        try:
            if data and not isinstance(data, (bytes, str)):
                body_bytes = json.dumps(
                    data, separators=(',', ':'), sort_keys=False, ensure_ascii=False
                ).encode('utf-8')
                request_headers.setdefault('Content-Type', 'application/json; charset=utf-8')
                req = requests.Request(method, url, data=body_bytes, params=params, headers=request_headers)
            else:
                req = requests.Request(method, url, json=data, params=params, headers=request_headers)
            prepared = req.prepare()
            
            print(f"    [HTTP] Prepared request - Content-Length: {prepared.headers.get('Content-Length')}")
            
            response = self.session.send(prepared, timeout=timeout)
            
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
