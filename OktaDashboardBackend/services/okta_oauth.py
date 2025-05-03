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
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class OktaOAuthClient:
    """
    OAuth client for Okta authentication with enhanced security features.
    
    This class implements OAuth 2.0 flows to authenticate with Okta,
    supporting the zero trust security model through:
    1. DPoP (Demonstrating Proof of Possession) for token binding
    2. private_key_jwt for client authentication (more secure than client secret)
    3. Automatic token refresh and proper token lifetime management
    """
    
    # Class-level cache for RSA keys
    _rsa_key_cache = {}
    
    def __init__(self, use_registered_keys=True):
        """
        Initialize the OAuth client with settings from Django configuration
        
        Args:
            use_registered_keys: Whether to use the registered keys from the keys/ directory
                                 If False, dynamically generate keys (but this won't work with real Okta unless registered)
        """
        self.client_id = settings.OKTA_CLIENT_ID
        self.client_secret = settings.OKTA_CLIENT_SECRET
        self.redirect_uri = settings.OKTA_REDIRECT_URI
        self.authorization_endpoint = settings.OKTA_AUTHORIZATION_ENDPOINT
        self.token_endpoint = settings.OKTA_TOKEN_ENDPOINT
        self.userinfo_endpoint = settings.OKTA_USER_INFO_ENDPOINT
        self.org_url = settings.OKTA_ORG_URL
        
        # Load or generate RSA key pair for DPoP
        self._setup_key_pair(use_registered_keys)
        
        # Headers for token requests (will be set during request creation)
        self.token_headers = {}
        
        # Cache for DPoP nonces with expiration
        self.nonce_cache_key = f"dpop_nonce_{self.client_id}"
        
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
    
    def _setup_key_pair(self, use_registered_keys=True):
        """
        Set up RSA key pairs for both DPoP and client authentication
        
        Args:
            use_registered_keys: Whether to use the registered keys from keys/ directory
        """
        if use_registered_keys:
            try:
                # Use the same private key that was registered with Okta
                private_key_path = os.path.join(settings.BASE_DIR, 'keys', 'private_key.pem')
                with open(private_key_path, 'rb') as key_file:
                    private_key_data = key_file.read()
                
                self.private_key = serialization.load_pem_private_key(
                    private_key_data,
                    password=None
                )
                logger.info("Successfully loaded the registered private key")
                
                # Generate JWK from the loaded key
                self._generate_jwk_from_key()
                
                # For DPoP, we'll generate a separate key (security best practice)
                self.dpop_private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                self._generate_dpop_jwk()
                
                return
            except Exception as e:
                logger.warning(f"Could not load registered private key: {e}. Generating new keys.")
        
        # If we reach here, either use_registered_keys is False or loading failed
        # Generate client auth key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self._generate_jwk_from_key()
        
        # Use the same key for DPoP to keep it simple when not using registered keys
        self.dpop_private_key = self.private_key
        self.dpop_jwk = self.jwk
    
    def _generate_jwk_from_key(self):
        """Generate JWK from the client authentication private key"""
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
    
    def _generate_dpop_jwk(self):
        """Generate JWK for DPoP (separate from client authentication key)"""
        dpop_public_key = self.dpop_private_key.public_key()
        dpop_public_numbers = dpop_public_key.public_numbers()
        
        # Convert to JWK format
        self.dpop_jwk = {
            "kty": "RSA",
            "e": base64.urlsafe_b64encode(dpop_public_numbers.e.to_bytes((dpop_public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
            "n": base64.urlsafe_b64encode(dpop_public_numbers.n.to_bytes((dpop_public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
            "alg": "RS256",
            "use": "sig"
        }
    
    def _normalize_url_for_dpop(self, method: str, url: str) -> str:
        """
        Normalize URL for DPoP proof as per Okta requirements
        
        Args:
            method: HTTP method
            url: The original URL
            
        Returns:
            Normalized URL for DPoP proof
        """
        parsed_url = urlparse(url)
        
        # For Okta System Log API, use exactly '/api/v1/logs'
        if '/api/v1/logs' in url:
            return "/api/v1/logs"
        elif '/oauth2/v1/token' in url:
            # For token endpoint, use full URL
            return url
        else:
            # For other endpoints, use the full URL
            return url
    
    def _create_dpop_proof(self, http_method: str, url: str, access_token: Optional[str] = None, nonce: Optional[str] = None) -> str:
        """
        Create a DPoP proof JWT for API requests with token binding.
        
        Args:
            http_method: HTTP method (POST, GET, etc.)
            url: Target URL
            access_token: Optional access token to bind to the proof
            nonce: Optional nonce from server
            
        Returns:
            DPoP proof JWT string
        """
        # Create the private key in PEM format for JWT signing
        private_key_pem = self.dpop_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Normalize URL for DPoP
        normalized_url = self._normalize_url_for_dpop(http_method, url)
        
        # Create DPoP proof JWT
        now = int(time.time())
        proof = {
            "jti": str(uuid.uuid4()),  # Unique identifier
            "htm": http_method,        # HTTP method
            "htu": normalized_url,     # HTTP target URL (normalized)
            "iat": now,                # Issued at time
            "exp": now + 60            # Expiration (1 minute)
        }
        
        # Add token binding with 'ath' claim if access token is provided
        if access_token:
            # Create hash of the access token
            access_token_hash = hashlib.sha256(access_token.encode()).digest()
            # Base64url encode the hash
            ath = base64.urlsafe_b64encode(access_token_hash).decode('utf-8').rstrip('=')
            proof["ath"] = ath
        
        # Add nonce if provided - required for subsequent requests
        if nonce:
            proof["nonce"] = nonce
            logger.debug(f"Including nonce in DPoP proof: {nonce}")
        
        # Create the header with the JWK
        header = {
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": self.dpop_jwk
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
        # Check if we have a cached nonce
        cached_nonce = cache.get(self.nonce_cache_key)
        if cached_nonce:
            logger.debug(f"Using cached DPoP nonce: {cached_nonce}")
            return cached_nonce
            
        try:
            # Create initial DPoP proof without nonce
            initial_proof = self._create_dpop_proof("POST", url)
            
            # Create client assertion for private_key_jwt
            client_assertion = self._create_client_assertion(url)
            
            # Create minimal headers
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "DPoP": initial_proof
            }
            
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
                    # Cache the nonce for future use
                    cache.set(self.nonce_cache_key, header_value, timeout=3600)
                    logger.debug(f"Got DPoP nonce from response: {header_value}")
                    return header_value
            
            # Check error response for nonce information
            try:
                error_data = response.json()
                logger.debug(f"Error response content: {error_data}")
                
                # Check for use_dpop_nonce error - a specific Okta error indicating nonce is required
                if error_data.get("error") == "use_dpop_nonce":
                    # Look for nonce in WWW-Authenticate header
                    www_auth = response.headers.get("WWW-Authenticate", "")
                    if "nonce=" in www_auth:
                        nonce_match = re.search(r'nonce="([^"]+)"', www_auth)
                        if nonce_match:
                            nonce = nonce_match.group(1)
                            # Cache the nonce
                            cache.set(self.nonce_cache_key, nonce, timeout=3600)
                            logger.debug(f"Extracted nonce from WWW-Authenticate: {nonce}")
                            return nonce
                    
                    # Sometimes the nonce is in a separate DPoP-Nonce header
                    dpop_nonce_header = response.headers.get("DPoP-Nonce")
                    if dpop_nonce_header:
                        cache.set(self.nonce_cache_key, dpop_nonce_header, timeout=3600)
                        logger.debug(f"Found nonce in DPoP-Nonce header: {dpop_nonce_header}")
                        return dpop_nonce_header
                    
                    # If still no nonce, look for it in the response body
                    error_description = error_data.get("error_description", "")
                    if "nonce" in error_description.lower():
                        nonce_match = re.search(r'nonce[=:]\s*["\']?([^"\']+)["\']?', error_description, re.IGNORECASE)
                        if nonce_match:
                            nonce = nonce_match.group(1)
                            cache.set(self.nonce_cache_key, nonce, timeout=3600)
                            logger.debug(f"Extracted nonce from error description: {nonce}")
                            return nonce
            except Exception as e:
                logger.warning(f"Error parsing response JSON: {e}")
            
            # Also check WWW-Authenticate header for nonce (if not already checked)
            www_auth = response.headers.get("WWW-Authenticate", "")
            if "nonce=" in www_auth:
                nonce_match = re.search(r'nonce="([^"]+)"', www_auth)
                if nonce_match:
                    nonce = nonce_match.group(1)
                    # Cache the nonce
                    cache.set(self.nonce_cache_key, nonce, timeout=3600)
                    logger.debug(f"Extracted nonce from WWW-Authenticate: {nonce}")
                    return nonce
            
            # As a last resort, try to get the nonce with a separate HEAD request
            try:
                head_response = self.session.head(
                    url,
                    headers={"Accept": "application/json", "DPoP": initial_proof},
                    timeout=5
                )
                
                for header_name, header_value in head_response.headers.items():
                    if header_name.lower() == 'dpop-nonce':
                        cache.set(self.nonce_cache_key, header_value, timeout=3600)
                        logger.debug(f"Got DPoP nonce from HEAD request: {header_value}")
                        return header_value
                
                www_auth = head_response.headers.get("WWW-Authenticate", "")
                if "nonce=" in www_auth:
                    nonce_match = re.search(r'nonce="([^"]+)"', www_auth)
                    if nonce_match:
                        nonce = nonce_match.group(1)
                        cache.set(self.nonce_cache_key, nonce, timeout=3600)
                        logger.debug(f"Extracted nonce from HEAD WWW-Authenticate: {nonce}")
                        return nonce
            except Exception as head_error:
                logger.warning(f"Error in HEAD request for nonce: {head_error}")
            
            # No nonce found in any of the attempts
            logger.warning("Failed to obtain DPoP nonce from Okta")
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
            
        Raises:
            Exception: If the token request fails
        """
        try:
            logger.debug(f"Getting OAuth token using client credentials flow with private_key_jwt and DPoP")
            
            # Step 1: Get a DPoP nonce
            token_url = self.token_endpoint
            dpop_nonce = self._get_dpop_nonce(token_url)
            
            # Step 2: Create DPoP proof with nonce if available
            dpop_proof = self._create_dpop_proof("POST", token_url, None, dpop_nonce)

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
            
            # Check for new nonce in the response headers
            new_nonce = None
            for header_name, header_value in response.headers.items():
                if header_name.lower() == 'dpop-nonce':
                    new_nonce = header_value
                    cache.set(self.nonce_cache_key, new_nonce, timeout=3600)
                    logger.debug(f"Updated cached DPoP nonce from response: {new_nonce}")
                    break
            
            # Step 6: Handle response, including retry with new nonce if needed
            if response.status_code == 200:
                token_data = response.json()
                logger.info(f"Successfully obtained DPoP token (expires in {token_data.get('expires_in', 'unknown')} seconds)")
                
                # Store the DPoP nonce in the token data for future use
                if new_nonce:
                    token_data['_dpop_nonce'] = new_nonce
                
                # Log the scopes that were granted (may differ from what was requested)
                granted_scopes = token_data.get('scope', '')
                if granted_scopes:
                    logger.debug(f"Granted scopes: {granted_scopes}")
                
                return token_data
            
            # Handle nonce errors - if we received a new nonce, retry
            if response.status_code in [400, 401] and new_nonce:
                logger.debug(f"Received new nonce in error response, retrying: {new_nonce}")
                
                # Create a new DPoP proof with the new nonce
                new_dpop_proof = self._create_dpop_proof("POST", token_url, None, new_nonce)
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
                
                # Check for another new nonce
                final_nonce = None
                for header_name, header_value in retry_response.headers.items():
                    if header_name.lower() == 'dpop-nonce':
                        final_nonce = header_value
                        cache.set(self.nonce_cache_key, final_nonce, timeout=3600)
                        logger.debug(f"Updated cached DPoP nonce from retry response: {final_nonce}")
                        break
                
                if retry_response.status_code == 200:
                    token_data = retry_response.json()
                    logger.info(f"Successfully obtained DPoP token after retry (expires in {token_data.get('expires_in', 'unknown')} seconds)")
                    
                    # Store the final DPoP nonce in the token data for future use
                    if final_nonce:
                        token_data['_dpop_nonce'] = final_nonce
                    
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
            
    def create_api_headers(self, access_token: str, method: str, url: str, nonce: Optional[str] = None) -> Dict[str, str]:
        """
        Create headers for Okta API requests with DPoP binding
        
        Args:
            access_token: The DPoP access token
            method: HTTP method for the request
            url: Target URL for the request
            nonce: Optional DPoP nonce
            
        Returns:
            Dict of HTTP headers
        """
        # Create DPoP proof with token binding
        dpop_proof = self._create_dpop_proof(method, url, access_token, nonce)
        
        # Create headers
        headers = {
            "Authorization": f"DPoP {access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "DPoP": dpop_proof
        }
        
        return headers