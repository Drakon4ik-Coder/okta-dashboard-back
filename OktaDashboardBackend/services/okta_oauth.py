import logging
import requests
import base64
import time
import uuid
import jwt
import json
import hashlib
import os
import re
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from typing import Dict, Optional, Tuple, Any
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

class OktaOAuthClient:
    """
    OAuth client for Okta authentication.
    
    This class implements OAuth 2.0 authorization code flow to authenticate with Okta,
    supporting the zero trust security model by validating access tokens and user information.
    """
    
    # Class-level cache for RSA keys
    _rsa_key_cache = {}
    
    def __init__(self):
        """Initialize the OAuth client with settings from Django configuration"""
        self.client_id = settings.OKTA_CLIENT_ID
        self.client_secret = settings.OKTA_CLIENT_SECRET
        self.redirect_uri = settings.OKTA_REDIRECT_URI
        self.authorization_endpoint = settings.OKTA_AUTHORIZATION_ENDPOINT
        self.token_endpoint = settings.OKTA_TOKEN_ENDPOINT
        self.userinfo_endpoint = settings.OKTA_USER_INFO_ENDPOINT
        
        # Generate RSA key pair for DPoP (with caching)
        self._setup_key_pair()
        
        # Headers for token requests
        auth_string = f"{self.client_id}:{self.client_secret}"
        encoded_auth = base64.b64encode(auth_string.encode()).decode()
        self.token_headers = {
            "Authorization": f"Basic {encoded_auth}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        # Cache for DPoP nonces with expiration
        self.nonce_cache_key = f"dpop_nonce_{self.client_id}"
        self.nonce_cache_ttl = 300  # 5 minutes
        
        # Session for connection pooling and performance optimization
        self.session = self._create_optimized_session()
    
    def _create_optimized_session(self) -> requests.Session:
        """Create and configure an optimized requests session with connection pooling"""
        session = requests.Session()
        
        # Configure connection pooling
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,  # Number of connection pools (one per host)
            pool_maxsize=20,      # Max connections per pool
            max_retries=2,        # Auto-retry on connection errors
            pool_block=False      # Don't block when pool is depleted
        )
        
        # Mount the adapter for both HTTP and HTTPS
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def _setup_key_pair(self):
        """Set up RSA key pair for DPoP proof with caching"""
        # Try to get from class cache first
        cache_key = f"rsa_keys_{self.client_id}"
        if cache_key in self._rsa_key_cache:
            logger.debug("Using cached RSA key pair")
            key_data = self._rsa_key_cache[cache_key]
            self.private_key = key_data['private_key']
            self.jwk = key_data['jwk']
            return
            
        # Try to get from Django cache
        cached_key_data = cache.get(cache_key)
        if cached_key_data:
            logger.debug("Using Django cached RSA key pair")
            # We need to deserialize the private key
            self.private_key = serialization.load_pem_private_key(
                cached_key_data['private_key_pem'],
                password=None
            )
            self.jwk = cached_key_data['jwk']
        else:
            # Generate new keys
            logger.debug("Generating new RSA key pair")
            self._generate_key_pair()
            
            # Save to Django cache
            private_key_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            cache.set(cache_key, {
                'private_key_pem': private_key_pem,
                'jwk': self.jwk
            }, 86400)  # Cache for 24 hours
            
            # Save to class cache
            self._rsa_key_cache[cache_key] = {
                'private_key': self.private_key,
                'jwk': self.jwk
            }
    
    def _generate_key_pair(self):
        """Generate RSA key pair for DPoP proof"""
        # Generate private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Get public key in JWK format
        public_key = self.private_key.public_key()
        public_numbers = public_key.public_numbers()
        
        # Convert to JWK format
        self.jwk = {
            "kty": "RSA",
            "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
            "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
            "alg": "RS256",
            "use": "sig"
        }
    
    def _create_dpop_proof(self, http_method: str, url: str, nonce: Optional[str] = None) -> str:
        """
        Create a DPoP proof JWT for API requests.
        
        Args:
            http_method: HTTP method (POST, GET, etc.)
            url: Target URL
            nonce: Optional nonce from server
            
        Returns:
            DPoP proof JWT string
        """
        # Create the private key in PEM format for JWT signing
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Parse the URL to extract components and normalize for DPoP
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        
        # For token endpoint, use full URL
        normalized_url = url
        
        # Create DPoP proof JWT
        now = int(time.time())
        proof = {
            "jti": str(uuid.uuid4()),  # Unique identifier
            "htm": http_method,        # HTTP method
            "htu": normalized_url,     # HTTP target URL
            "iat": now,                # Issued at time
            "exp": now + 60            # Expiration (1 minute)
        }
        
        # Add nonce if provided - required for subsequent requests
        if nonce:
            proof["nonce"] = nonce
        
        # Create the header with the JWK
        header = {
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": self.jwk
        }
        
        # Sign the JWT
        dpop_proof = jwt.encode(
            payload=proof,
            key=private_key_pem,
            algorithm="RS256",
            headers=header
        )
        
        return dpop_proof
        
    def _get_dpop_nonce(self, url: str) -> Optional[str]:
        """
        Get a DPoP nonce from the server by making a minimal request.
        This is required for DPoP security to prevent replay attacks.
        
        Args:
            url: The URL to request the nonce from
            
        Returns:
            The DPoP nonce if available, None otherwise
        """
        try:
            # Create initial DPoP proof without nonce
            initial_proof = self._create_dpop_proof("POST", url)
            
            # Create minimal headers
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "DPoP": initial_proof
            }
            
            # Create a minimal client assertion
            client_assertion = self._create_client_assertion(url)
            
            # Prepare minimal data
            data = {
                "client_id": self.client_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion,
                "grant_type": "client_credentials"
            }
            
            # Make a minimal request to get the nonce
            response = self.session.post(
                url,
                headers=headers,
                data=data,
                timeout=10
            )
            
            # Check for DPoP-Nonce header (case insensitive)
            for header_name, header_value in response.headers.items():
                if header_name.lower() == 'dpop-nonce':
                    return header_value
            
            # Also check WWW-Authenticate header for nonce
            www_auth = response.headers.get("WWW-Authenticate", "")
            if "dpop" in www_auth.lower() and "nonce=" in www_auth.lower():
                import re
                nonce_match = re.search(r'nonce="([^"]+)"', www_auth)
                if nonce_match:
                    return nonce_match.group(1)
            
            # No nonce found
            return None
                
        except Exception as e:
            logger.error(f"Error getting DPoP nonce: {str(e)}")
            return None
            
    def _create_client_assertion(self, audience: str) -> str:
        """
        Create a signed JWT assertion for client authentication using private_key_jwt
        
        Args:
            audience: The audience for the token (typically the token endpoint)
            
        Returns:
            Signed JWT token as string
        """
        # Convert private key to PEM format for JWT signing
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Create JWT assertion
        now = int(time.time())
        payload = {
            "iss": self.client_id,     # Issuer is the client_id
            "sub": self.client_id,     # Subject is also the client_id
            "aud": audience,           # Audience is the token endpoint
            "jti": str(uuid.uuid4()),  # Unique identifier
            "iat": now,                # Issued at time
            "exp": now + 60            # Expires in 1 minute
        }
        
        # Sign the JWT
        client_assertion = jwt.encode(
            payload=payload,
            key=private_key_pem,
            algorithm="RS256"
        )
        
        return client_assertion

    def get_client_credentials_token(self, scopes: str = "okta.logs.read okta.users.read") -> Dict:
        """
        Get an OAuth 2.0 access token using client credentials flow with private_key_jwt and DPoP.
        
        This implementation uses:
        1. private_key_jwt for client authentication (more secure than client secret)
        2. DPoP proof for enhanced security and token binding
        3. Automatic nonce handling with retry logic
        
        Args:
            scopes: Space-separated list of scopes to request
            
        Returns:
            Dict containing the access token and other token information
        """
        try:
            logger.debug(f"Getting OAuth token using client credentials flow with private_key_jwt and DPoP")
            
            # Step 1: Get a DPoP nonce
            token_url = self.token_endpoint
            dpop_nonce = self._get_dpop_nonce(token_url)
            
            # Step 2: Create DPoP proof with nonce if available
            dpop_proof = self._create_dpop_proof("POST", token_url, dpop_nonce)
            
            # Step 3: Create client assertion for private_key_jwt
            client_assertion = self._create_client_assertion(token_url)
            
            # Step 4: Prepare headers and data
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "DPoP": dpop_proof
            }
            
            data = {
                "client_id": self.client_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion,
                "grant_type": "client_credentials",
                "scope": scopes,
                "token_type": "DPoP"
            }
            
            # Step 5: Make the initial request
            logger.debug(f"Making token request with private_key_jwt and DPoP")
            response = self.session.post(
                token_url,
                headers=headers,
                data=data,
                timeout=15
            )
            
            # Step 6: Handle response, including retry with new nonce if needed
            if response.status_code == 200:
                token_data = response.json()
                logger.info(f"Successfully obtained DPoP token (expires in {token_data.get('expires_in', 'unknown')} seconds)")
                
                # Log the scopes that were granted (may differ from what was requested)
                granted_scopes = token_data.get('scope', '')
                if granted_scopes:
                    logger.debug(f"Granted scopes: {granted_scopes}")
                
                return token_data
            
            # Handle nonce errors - if we received a new nonce, retry
            if response.status_code in [400, 401] and "DPoP-Nonce" in response.headers:
                new_nonce = response.headers.get("DPoP-Nonce")
                logger.debug(f"Received new nonce in error response, retrying: {new_nonce}")
                
                # Create a new DPoP proof with the new nonce
                new_dpop_proof = self._create_dpop_proof("POST", token_url, new_nonce)
                headers["DPoP"] = new_dpop_proof
                
                # Create a new client assertion (for security best practice)
                new_client_assertion = self._create_client_assertion(token_url)
                data["client_assertion"] = new_client_assertion
                
                # Retry with the new nonce
                retry_response = self.session.post(
                    token_url,
                    headers=headers,
                    data=data,
                    timeout=15
                )
                
                if retry_response.status_code == 200:
                    token_data = retry_response.json()
                    logger.info(f"Successfully obtained DPoP token after retry (expires in {token_data.get('expires_in', 'unknown')} seconds)")
                    return token_data
                else:
                    # Log the error before raising exception
                    logger.error(f"Token request failed after retry: {retry_response.status_code} - {retry_response.text[:200]}")
                    
                    try:
                        error_data = retry_response.json()
                        error_msg = f"{error_data.get('error')}: {error_data.get('error_description')}"
                    except:
                        error_msg = retry_response.text[:200] if retry_response.text else f"Status {retry_response.status_code}"
                    
                    raise Exception(f"Failed to obtain OAuth token after retry: {error_msg}")
            
            # Handle errors
            logger.error(f"Token request failed: {response.status_code} - {response.text[:200]}")
            
            try:
                error_data = response.json()
                error_msg = f"{error_data.get('error')}: {error_data.get('error_description')}"
            except:
                error_msg = response.text[:200] if response.text else f"Status {response.status_code}"
            
            raise Exception(f"Failed to obtain OAuth token: {error_msg}")
            
        except Exception as e:
            logger.error(f"Error in client credentials flow: {str(e)}")
            raise Exception(f"OAuth token acquisition failed: {str(e)}")