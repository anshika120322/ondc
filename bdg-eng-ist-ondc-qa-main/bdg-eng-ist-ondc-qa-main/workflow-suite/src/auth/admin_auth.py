"""
Admin JWT Authentication Module

Handles JWT token-based authentication for Admin API endpoints.
"""

import requests
from typing import Optional, Dict
from datetime import datetime, timezone


class AdminAuth:
    """
    Admin JWT Authentication Manager
    
    Handles login and JWT token management for Admin API access.
    Automatically refreshes tokens when expired.
    """
    
    def __init__(self, base_url: str, username: str = "admin", password: str = "admin123",
                 auth_url: Optional[str] = None,
                 username_field: str = "username", password_field: str = "password",
                 token_field: str = "access_token",
                 ssl_verify: bool = True):
        """
        Initialize Admin authentication.
        
        Args:
            base_url: Base URL of the registry API (e.g., "http://localhost:8080")
            username: Credential value for the username/email field
            password: Credential value for the password field
            auth_url: Optional external auth service login URL.
                      If provided, login requests are sent here instead of
                      {base_url}/admin/auth/login.
                      Example: "https://authservice.kynondc.net/api/auth/login"
            username_field: Key name for the username in the login payload (default: "username").
                            Set to "email" for external auth services that expect an email field.
            password_field: Key name for the password in the login payload (default: "password").
            token_field: Key name for the token in the login response body (default: "access_token").
                         Set to "accessToken" if the external auth service uses camelCase.
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.auth_url = auth_url  # None → use default internal login endpoint
        self.username_field = username_field
        self.password_field = password_field
        self.token_field = token_field
        self.ssl_verify = ssl_verify
        self.token: Optional[str] = None
        self.token_expiry: Optional[datetime] = None
    
    def login(self) -> bool:
        """
        Perform admin login and obtain JWT token.
        
        Returns:
            True if login successful, False otherwise
        """
        login_url = self.auth_url if self.auth_url else f"{self.base_url}/admin/auth/login"
        
        payload = {
            self.username_field: self.username,
            self.password_field: self.password,
        }
        
        try:
            response = requests.post(login_url, json=payload, timeout=10, verify=self.ssl_verify)
            
            if response.status_code == 200:
                data = response.json()
                self.token = data.get(self.token_field) or data.get('access_token') or data.get('token')
                
                if not self.token:
                    print(f"Login failed: No token in response - {data}")
                    return False
                
                # Set token expiry (typically 24 hours, set to 23 hours to be safe)
                self.token_expiry = datetime.now(timezone.utc).timestamp() + (23 * 3600)
                
                return True
            else:
                print(f"Login failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            print(f"Login error: {e}")
            return False
    
    def is_token_valid(self) -> bool:
        """
        Check if current token is valid and not expired.
        
        Returns:
            True if token is valid, False otherwise
        """
        if not self.token:
            return False
        
        if self.token_expiry:
            # Refresh if expiring in next 5 minutes
            if datetime.now(timezone.utc).timestamp() > (self.token_expiry - 300):
                return False
        
        return True
    
    def get_token(self) -> Optional[str]:
        """
        Get valid JWT token, automatically logging in if needed.
        
        Returns:
            JWT token string or None if login fails
        """
        if not self.is_token_valid():
            if not self.login():
                return None
        
        return self.token
    
    def get_auth_header(self) -> Dict[str, str]:
        """
        Get authorization header with valid JWT token.
        
        Returns:
            Dictionary with Authorization header
        """
        token = self.get_token()
        if not token:
            raise RuntimeError("Failed to obtain admin JWT token")
        
        return {"Authorization": f"Bearer {token}"}
    
    def logout(self):
        """Clear stored credentials."""
        self.token = None
        self.token_expiry = None
