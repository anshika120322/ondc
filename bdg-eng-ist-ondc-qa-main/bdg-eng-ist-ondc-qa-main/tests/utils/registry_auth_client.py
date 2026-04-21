"""
Registry Admin Authentication Client
Manages JWT token generation and refresh for Registry Admin API
"""
import requests
import time
import json
import base64


class RegistryAuthClient:
    """Client for Registry Admin API authentication"""
    
    def _decode_jwt_payload(self, token):
        """
        Decode JWT payload without verification (to check expiration)
        
        Args:
            token: JWT token string
            
        Returns:
            dict: Decoded payload or None if invalid
        """
        try:
            # JWT format: header.payload.signature
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode payload (add padding if needed)
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding
            
            decoded = base64.urlsafe_b64decode(payload)
            return json.loads(decoded)
        except Exception as e:
            print(f"[RegistryAuthClient] Failed to decode JWT: {e}")
            return None
    
    def _is_token_expired(self, token):
        """
        Check if a JWT token is expired
        
        Args:
            token: JWT token string
            
        Returns:
            bool: True if token is expired or invalid, False if still valid
        """
        payload = self._decode_jwt_payload(token)
        if not payload:
            return True
        
        # Check expiration (exp is in seconds since epoch)
        exp = payload.get('exp')
        if not exp:
            print("[RegistryAuthClient] Warning: Token has no expiration claim")
            return False  # Assume valid if no exp claim
        
        # Add 5 second buffer to account for clock skew
        if time.time() >= (exp - 5):
            print(f"[RegistryAuthClient] Token is expired (exp: {exp}, now: {time.time()})")
            return True
        
        return False
    
    def __init__(self, base_url, username="test", password="test", proxies=None, verify=None, static_token=None, auth_url=None):
        """
        Initialize the auth client
        
        Args:
            base_url: Registry API base URL (e.g., "http://34.14.152.92")
            username: Admin username (default: "test" for dev environment)
            password: Admin password (default: "test" for dev environment)
            proxies: Optional proxy configuration dict (for ProxyServer)
            verify: Optional SSL verification config (certificate path or False)
            static_token: Optional static JWT token (skips login if provided)
            auth_url: Optional external auth service URL (e.g., "https://authservice.kynondc.net/api/auth/login")
                     If not provided, uses {base_url}/admin/auth/login
        """
        self.base_url = base_url.rstrip("/")
        self.auth_url = auth_url.rstrip("/") if auth_url else None
        self.username = username
        self.password = password
        self.proxies = proxies
        self.verify = verify if verify is not None else True
        
        # Validate static token if provided
        if static_token:
            if self._is_token_expired(static_token):
                print("[RegistryAuthClient] WARNING: Provided static token is expired, will use dynamic login instead")
                self._token = None
                self._expiry = 0
            else:
                print("[RegistryAuthClient] Using provided static token")
                self._token = static_token
                self._expiry = 0  # Mark as static (no auto-refresh)
        else:
            self._token = None
            self._expiry = 0
            
        self._refresh_token = None

    def _login(self):
        """Login and get new access token"""
        # Use external auth URL if provided, otherwise use base_url
        if self.auth_url:
            url = self.auth_url
            # External auth service uses "email" field instead of "username"
            payload = {
                "email": self.username,  # username actually contains email when using external auth
                "password": self.password
            }
        else:
            url = f"{self.base_url}/admin/auth/login"
            # Built-in registry auth uses "username" field
            payload = {
                "username": self.username,
                "password": self.password
            }

        try:
            print(f"[RegistryAuthClient] Attempting login to {url} with username: {self.username}")
            response = requests.post(url, json=payload, timeout=10, 
                                    proxies=self.proxies, verify=self.verify)
            
            # Log response details for debugging
            print(f"[RegistryAuthClient] Login response status: {response.status_code}")
            print(f"[RegistryAuthClient] Login response: {response.text[:200]}")
            
            response.raise_for_status()

            data = response.json()
            # Support both snake_case and camelCase response formats
            self._token = data.get("accessToken") or data.get("access_token")
            self._refresh_token = data.get("refreshToken") or data.get("refresh_token")
            # expires_in is in seconds, refresh 30 seconds before expiry
            expires_in = data.get("expiresIn") or data.get("expires_in", 86400)
            self._expiry = time.time() + expires_in - 30
            
            if not self._token:
                raise Exception("No access token in login response")
            
            print(f"[RegistryAuthClient] Login successful. Token expires in {expires_in} seconds")
            print(f"[RegistryAuthClient] Token (first 50 chars): {self._token[:50]}...")
            
        except requests.exceptions.RequestException as e:
            print(f"[RegistryAuthClient] Login failed: {str(e)}")
            if hasattr(e.response, 'text'):
                print(f"[RegistryAuthClient] Error response: {e.response.text}")
            raise

    def _refresh(self):
        """Refresh access token using refresh token"""
        if not self._refresh_token:
            # No refresh token available, do full login
            self._login()
            return
            
        url = f"{self.base_url}/admin/auth/refresh"
        headers = {
            "Authorization": f"Bearer {self._refresh_token}",
            "Content-Type": "application/json"
        }

        try:
            response = requests.post(url, headers=headers, timeout=10,
                                    proxies=self.proxies, verify=self.verify)
            response.raise_for_status()

            data = response.json()
            # Support both snake_case and camelCase response formats
            self._token = data.get("accessToken") or data.get("access_token")
            # Keep existing refresh token or get new one
            self._refresh_token = data.get("refreshToken") or data.get("refresh_token", self._refresh_token)
            expires_in = data.get("expiresIn") or data.get("expires_in", 86400)
            self._expiry = time.time() + expires_in - 30
            
            print(f"[RegistryAuthClient] Token refreshed successfully. Expires in {expires_in} seconds")
            
        except requests.exceptions.RequestException as e:
            print(f"[RegistryAuthClient] Refresh failed, doing full login: {str(e)}")
            # Fallback to full login if refresh fails
            self._login()

    def get_token(self):
        """
        Get valid access token, refreshing if needed
        
        Returns:
            str: Valid JWT access token
        """
        # If static token was validated during init (expiry == 0 means static), use it
        if self._token and self._expiry == 0:
            print("[RegistryAuthClient] Using validated static token")
            return self._token
            
        # Check if token needs refresh/login
        if not self._token or time.time() >= self._expiry:
            # Try refresh first, fallback to login
            if self._refresh_token:
                self._refresh()
            else:
                self._login()
        return self._token

    def get_auth_headers(self):
        """
        Get authorization headers for API requests
        
        Returns:
            dict: Headers with Bearer token
        """
        return {
            "Authorization": f"Bearer {self.get_token()}",
            "Content-Type": "application/json"
        }
