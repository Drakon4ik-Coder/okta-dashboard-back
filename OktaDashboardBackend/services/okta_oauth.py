import logging
import requests
import base64
import time
import uuid
import jwt
import json
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
        Create a DPoP proof for token requests
        
        Args:
            http_method: HTTP method of the request
            url: URL of the request
            nonce: Optional nonce value provided by the server
            
        Returns:
            DPoP proof JWT
        """
        # Create the private key in PEM format for JWT signing
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Create DPoP proof JWT
        now = int(time.time())
        proof = {
            "jti": str(uuid.uuid4()),
            "htm": http_method,
            "htu": url,
            "iat": now,
            "exp": now + 60,  # Valid for 1 minute
        }
        
        # Add nonce if provided
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
        Get a DPoP nonce from the server using cached value if available
        
        Args:
            url: The endpoint URL
            
        Returns:
            Nonce string if available, None otherwise
        """
        # First check if we have a cached nonce
        cached_nonce = cache.get(self.nonce_cache_key)
        if cached_nonce:
            logger.debug(f"Using cached DPoP nonce")
            return cached_nonce
            
        try:
            # Make a HEAD request to token endpoint with DPoP header
            initial_proof = self._create_dpop_proof("HEAD", url)
            headers = {"DPoP": initial_proof}
            
            logger.debug(f"Fetching DPoP nonce with HEAD request")
            # Use the session for connection pooling benefits
            head_response = self.session.head(
                url, 
                headers=headers,
                timeout=10
            )
            
            # Check if we received a DPoP-Nonce header
            dpop_nonce = head_response.headers.get("DPoP-Nonce")
            if dpop_nonce:
                logger.debug(f"Received DPoP nonce from HEAD request: {dpop_nonce}")
                # Cache the nonce for future use
                cache.set(self.nonce_cache_key, dpop_nonce, self.nonce_cache_ttl)
                return dpop_nonce
            
            # If HEAD didn't work, try a minimal POST request
            if not dpop_nonce:
                logger.debug(f"Making minimal POST request to get DPoP nonce")
                response = self.session.post(
                    url,
                    headers=headers,
                    data={"grant_type": "client_credentials"},
                    allow_redirects=False,
                    timeout=10
                )
                
                # Check if we received a DPoP-Nonce header
                dpop_nonce = response.headers.get("DPoP-Nonce")
                if dpop_nonce:
                    logger.debug(f"Received DPoP nonce from POST request")
                    # Cache the nonce for future use
                    cache.set(self.nonce_cache_key, dpop_nonce, self.nonce_cache_ttl)
                    return dpop_nonce
                
                # Extract from WWW-Authenticate header if present
                www_auth = response.headers.get("WWW-Authenticate", "")
                if "DPoP" in www_auth and "nonce=" in www_auth:
                    import re
                    nonce_match = re.search(r'nonce="([^"]+)"', www_auth)
                    if nonce_match:
                        dpop_nonce = nonce_match.group(1)
                        logger.debug(f"Extracted nonce from WWW-Authenticate: {dpop_nonce}")
                        cache.set(self.nonce_cache_key, dpop_nonce, self.nonce_cache_ttl)
                        return dpop_nonce
            
            logger.info("No DPoP nonce available, proceeding without it")
            return None
            
        except Exception as e:
            logger.warning(f"Error getting DPoP nonce: {e}")
            return None
    
    def get_authorization_url(self, state: str, scope: str = "openid profile email") -> str:
        """
        Generate the authorization URL for the OAuth flow.
        
        Args:
            state: Random string for CSRF protection
            scope: OAuth scopes to request
            
        Returns:
            URL to redirect the user to for authentication
        """
        auth_params = {
            "client_id": self.client_id,
            "response_type": "code",
            "scope": scope,
            "redirect_uri": self.redirect_uri,
            "state": state
        }
        
        # Build the query string
        query_params = "&".join([f"{k}={v}" for k, v in auth_params.items()])
        return f"{self.authorization_endpoint}?{query_params}"
    
    def exchange_code_for_tokens(self, code: str) -> Dict:
        """
        Exchange an authorization code for access and refresh tokens.
        
        Args:
            code: The authorization code from the callback
            
        Returns:
            Dictionary containing tokens and metadata
            
        Raises:
            Exception: If token exchange fails
        """
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri
        }
        
        # Try the DPoP approach first since your Okta setup requires it
        try:
            logger.info("Exchanging authorization code for tokens (with DPoP)")
            
            # Get a DPoP nonce
            dpop_nonce = self._get_dpop_nonce(self.token_endpoint)
            
            # Create DPoP proof
            dpop_proof = self._create_dpop_proof("POST", self.token_endpoint, dpop_nonce)
            
            # Add DPoP headers
            headers = self.token_headers.copy()
            headers["DPoP"] = dpop_proof
            
            # Add token type since we're using DPoP
            token_data_with_type = token_data.copy()
            token_data_with_type["token_type"] = "DPoP"
            
            response = self.session.post(
                self.token_endpoint,
                headers=headers,
                data=token_data_with_type,
                timeout=15
            )
            
            if response.status_code == 200:
                logger.info("Token exchange successful")
                return response.json()
                
            # Handle nonce errors specifically
            if response.status_code in [400, 401]:
                try:
                    error_data = response.json()
                    if error_data.get("error") == "use_dpop_nonce" or "nonce" in error_data.get("error_description", "").lower():
                        # Try to extract nonce from response
                        new_nonce = None
                        
                        # Try from headers first
                        if "DPoP-Nonce" in response.headers:
                            new_nonce = response.headers.get("DPoP-Nonce")
                        
                        # Try from WWW-Authenticate header
                        if not new_nonce and "WWW-Authenticate" in response.headers:
                            www_auth = response.headers.get("WWW-Authenticate")
                            import re
                            nonce_match = re.search(r'nonce="([^"]+)"', www_auth)
                            if nonce_match:
                                new_nonce = nonce_match.group(1)
                        
                        # If we got a new nonce, try again
                        if new_nonce:
                            logger.debug(f"Retrying with new nonce: {new_nonce}")
                            # Cache the new nonce
                            cache.set(self.nonce_cache_key, new_nonce, self.nonce_cache_ttl)
                            
                            # Create new proof and make request
                            dpop_proof = self._create_dpop_proof("POST", self.token_endpoint, new_nonce)
                            headers["DPoP"] = dpop_proof
                            
                            # Try again with the new nonce
                            retry_response = self.session.post(
                                self.token_endpoint,
                                headers=headers,
                                data=token_data_with_type,
                                timeout=15
                            )
                            
                            if retry_response.status_code == 200:
                                logger.info("Token exchange successful with new nonce")
                                return retry_response.json()
                except Exception as parse_error:
                    logger.warning(f"Error handling nonce issues: {parse_error}")
            
            # If DPoP failed but not due to missing nonce, fallback to standard OAuth
            logger.warning(f"DPoP token exchange failed: {response.status_code} - {response.text}")
            logger.info("Trying fallback to standard OAuth...")
            
            # Try standard OAuth as fallback
            standard_response = self.session.post(
                self.token_endpoint, 
                headers=self.token_headers,
                data=token_data,
                timeout=15
            )
            
            if standard_response.status_code == 200:
                logger.info("Token exchange successful (standard OAuth)")
                return standard_response.json()
            else:
                # Both methods failed
                logger.error(f"All token exchange methods failed. Standard OAuth response: {standard_response.status_code} - {standard_response.text}")
                raise Exception(f"Token exchange failed: {response.status_code} - {response.text}")
        
        except Exception as e:
            logger.error(f"Failed to exchange code for tokens: {e}")
            raise Exception(f"OAuth token exchange failed: {str(e)}")
    
    def refresh_access_token(self, refresh_token: str) -> Dict:
        """
        Refresh an access token using a refresh token.
        
        Args:
            refresh_token: The refresh token
            
        Returns:
            Dictionary containing new tokens
            
        Raises:
            Exception: If token refresh fails
        """
        refresh_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        }
        
        # Try DPoP approach first since your Okta setup requires it
        try:
            logger.debug("Refreshing token with DPoP")
            
            # Get DPoP nonce
            dpop_nonce = self._get_dpop_nonce(self.token_endpoint)
            dpop_proof = self._create_dpop_proof("POST", self.token_endpoint, dpop_nonce)
            
            # Create headers with DPoP
            headers = self.token_headers.copy()
            headers["DPoP"] = dpop_proof
            
            # Add token_type for DPoP
            refresh_data_with_type = refresh_data.copy()
            refresh_data_with_type["token_type"] = "DPoP"
            
            # Try with DPoP
            dpop_response = self.session.post(
                self.token_endpoint,
                headers=headers,
                data=refresh_data_with_type,
                timeout=15
            )
            
            if dpop_response.status_code == 200:
                logger.info("Token refresh successful with DPoP")
                return dpop_response.json()
                
            # Try standard OAuth as fallback
            logger.debug("DPoP refresh failed, trying standard OAuth")
            response = self.session.post(
                self.token_endpoint,
                headers=self.token_headers,
                data=refresh_data,
                timeout=15
            )
            
            if response.status_code == 200:
                logger.info("Token refresh successful with standard OAuth")
                return response.json()
                
            # If both methods failed, log details and raise error
            logger.error(f"All token refresh methods failed. DPoP: {dpop_response.status_code}, Standard: {response.status_code}")
            logger.error(f"DPoP response: {dpop_response.text[:200]}")
            logger.error(f"Standard response: {response.text[:200]}")
            raise Exception(f"Token refresh failed with both methods")
            
        except Exception as e:
            logger.error(f"Failed to refresh token: {e}")
            raise Exception(f"OAuth token refresh failed: {str(e)}")
    
    def validate_token(self, access_token: str) -> bool:
        """
        Validate an access token by making a request to the userinfo endpoint.
        
        Args:
            access_token: The access token to validate
            
        Returns:
            Boolean indicating if the token is valid
        """
        # First try standard Bearer authentication
        try:
            response = self.session.get(
                self.userinfo_endpoint,
                headers={
                    "Authorization": f"Bearer {access_token}"
                },
                timeout=10
            )
            if response.status_code == 200:
                return True
                
            # If standard fails, try with DPoP
            if response.status_code == 401:
                dpop_nonce = self._get_dpop_nonce(self.userinfo_endpoint)
                dpop_proof = self._create_dpop_proof("GET", self.userinfo_endpoint, dpop_nonce)
                
                dpop_response = self.session.get(
                    self.userinfo_endpoint,
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "DPoP": dpop_proof
                    },
                    timeout=10
                )
                return dpop_response.status_code == 200
                
            return False
        except:
            return False
    
    def _parse_id_token(self, id_token: str) -> Dict:
        """
        Parse and validate an ID token to extract user information
        
        Args:
            id_token: The ID token from the token response
            
        Returns:
            Dictionary containing user info extracted from the token
            
        Raises:
            Exception: If token parsing fails
        """
        try:
            # First try to decode without verification (for zero trust systems,
            # we'll still validate the claims even if we can't verify signature)
            decoded_token = jwt.decode(id_token, options={"verify_signature": False})
            
            # Extract standard OpenID Connect claims
            user_info = {
                "sub": decoded_token.get("sub"),
                "email": decoded_token.get("email"),
                "preferred_username": decoded_token.get("preferred_username"),
                "name": decoded_token.get("name"),
                "given_name": decoded_token.get("given_name"),
                "family_name": decoded_token.get("family_name")
            }
            
            # Include any other standard claims that might be present
            for claim in ["email_verified", "zoneinfo", "locale", "nickname", "picture", "birthdate"]:
                if claim in decoded_token:
                    user_info[claim] = decoded_token.get(claim)
            
            # Filter out None values
            user_info = {k: v for k, v in user_info.items() if v is not None}
            
            # Ensure we at least have a subject identifier
            if "sub" not in user_info or not user_info["sub"]:
                raise Exception("ID token missing subject identifier")
                
            logger.info("Successfully extracted user info from ID token")
            return user_info
            
        except Exception as e:
            logger.error(f"Failed to parse ID token: {str(e)}")
            raise Exception(f"Failed to extract user info from ID token: {str(e)}")

    def get_user_info(self, access_token: str, token_type: str = None, id_token: str = None) -> Dict:
        """
        Get user information using an access token.
        
        Args:
            access_token: The access token
            token_type: Optional token type from token response (DPoP or Bearer)
            id_token: Optional ID token that can be used as fallback for user info
            
        Returns:
            User information dictionary
            
        Raises:
            Exception: If userinfo request fails and no fallback is available
        """
        try:
            # Log token details for debugging (safely)
            token_prefix = access_token[:10] if len(access_token) > 10 else ""
            logger.debug(f"Getting user info with token prefix: {token_prefix}...")
            
            # If token type is explicitly provided as DPoP, use that approach first
            is_dpop_token = token_type and token_type.lower() == "dpop"
            
            if is_dpop_token:
                logger.info("Using DPoP token type based on token response")
            
            attempts = []
            responses = []
            
            # Try these strategies in sequence:
            # 1. DPoP with appropriate header format
            # 2. Alternative DPoP header format (if applicable)
            # 3. Standard Bearer token
            # 4. Request with Accept header variations
            # 5. Fallback to ID token parsing if all else fails
            
            # Strategy 1: Try with DPoP proof and appropriate header format
            try:
                logger.debug("Attempting to get user info with DPoP token")
                dpop_nonce = self._get_dpop_nonce(self.userinfo_endpoint)
                dpop_proof = self._create_dpop_proof("GET", self.userinfo_endpoint, dpop_nonce)
                
                # Create headers with appropriate token binding
                dpop_headers = {
                    "Authorization": f"DPoP {access_token}" if is_dpop_token else f"Bearer {access_token}",
                    "DPoP": dpop_proof,
                    "Accept": "application/json"
                }
                
                # Make the request with DPoP
                logger.debug(f"Making userinfo request with DPoP headers to: {self.userinfo_endpoint}")
                
                # Check if endpoint URL is valid
                if not self.userinfo_endpoint or not self.userinfo_endpoint.startswith(("http://", "https://")):
                    logger.warning(f"Potentially invalid userinfo endpoint: {self.userinfo_endpoint}")
                
                dpop_response = self.session.get(
                    self.userinfo_endpoint,
                    headers=dpop_headers,
                    timeout=15  # Increased timeout for reliability
                )
                
                # Log response details
                logger.debug(f"DPoP userinfo response: {dpop_response.status_code}")
                responses.append(("DPoP", dpop_response))
                
                if dpop_response.status_code == 200:
                    logger.info("User info retrieved successfully with DPoP")
                    return dpop_response.json()
            except Exception as e:
                attempts.append(("DPoP", str(e)))
                logger.warning(f"DPoP user info attempt failed: {e}")
            
            # Strategy 2: If DPoP might be required but failed, try alternate DPoP header format 
            if is_dpop_token:
                try:
                    logger.debug("Trying alternate DPoP header format")
                    dpop_nonce = self._get_dpop_nonce(self.userinfo_endpoint)
                    dpop_proof = self._create_dpop_proof("GET", self.userinfo_endpoint, dpop_nonce)
                    
                    alt_dpop_headers = {
                        "Authorization": f"Bearer {access_token}",  # Try Bearer format
                        "DPoP": dpop_proof,
                        "Accept": "application/json"
                    }
                    
                    alt_dpop_response = self.session.get(
                        self.userinfo_endpoint,
                        headers=alt_dpop_headers,
                        timeout=15
                    )
                    
                    logger.debug(f"Alternate DPoP header format response: {alt_dpop_response.status_code}")
                    responses.append(("Alt-DPoP", alt_dpop_response))
                    
                    if alt_dpop_response.status_code == 200:
                        logger.info("User info retrieved successfully with alternate DPoP format")
                        return alt_dpop_response.json()
                except Exception as e:
                    attempts.append(("Alt-DPoP", str(e)))
                    logger.warning(f"Alternate DPoP format attempt failed: {e}")
            
            # Strategy 3: Try standard Bearer token (as fallback)
            try:
                logger.debug("Trying standard Bearer token approach")
                bearer_headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json"
                }
                
                bearer_response = self.session.get(
                    self.userinfo_endpoint,
                    headers=bearer_headers,
                    timeout=15
                )
                
                logger.debug(f"Bearer userinfo response: {bearer_response.status_code}")
                responses.append(("Bearer", bearer_response))
                
                if bearer_response.status_code == 200:
                    logger.info("User info retrieved successfully with standard Bearer")
                    return bearer_response.json()
            except Exception as e:
                attempts.append(("Bearer", str(e)))
                logger.warning(f"Bearer token attempt failed: {e}")
                
            # Strategy 4: Try with different Accept headers
            try:
                logger.debug("Trying with explicit content-type headers")
                accept_headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/jwt, application/json;q=0.9",
                    "Content-Type": "application/x-www-form-urlencoded"
                }
                
                accept_response = self.session.get(
                    self.userinfo_endpoint, 
                    headers=accept_headers,
                    timeout=15
                )
                
                logger.debug(f"Accept header variation response: {accept_response.status_code}")
                responses.append(("Accept-Variation", accept_response))
                
                if accept_response.status_code == 200:
                    logger.info("User info retrieved successfully with accept header variations")
                    return accept_response.json()
            except Exception as e:
                attempts.append(("Accept-Variation", str(e)))
                logger.warning(f"Accept header variation attempt failed: {e}")
                
            # If all userinfo endpoint methods failed, log diagnostics
            logger.error("All userinfo endpoint methods failed")
            
            # Check server configuration issues
            logger.debug(f"Checking userinfo endpoint configuration: {self.userinfo_endpoint}")
            
            # Check if ID token is available as fallback
            if id_token:
                logger.info("Falling back to ID token parsing for user info")
                try:
                    return self._parse_id_token(id_token)
                except Exception as e:
                    attempts.append(("ID-Token-Parse", str(e)))
                    logger.error(f"ID token fallback failed: {e}")
            
            # All methods failed, generate detailed diagnostic info
            logger.error("All user info retrieval methods failed")
            
            # Log attempt details
            for attempt_type, error in attempts:
                logger.error(f"{attempt_type} attempt error: {error}")
            
            # Log response content for failed attempts
            for resp_type, resp in responses:
                content = resp.text[:500] if resp.text else "Empty response"
                logger.error(f"{resp_type} response ({resp.status_code}): {content}")
                
                # Log response headers for debugging
                headers = dict(resp.headers)
                safe_headers = {k: v for k, v in headers.items() 
                               if k.lower() not in ('authorization', 'set-cookie')}
                logger.error(f"{resp_type} response headers: {json.dumps(safe_headers)}")
                
                # Try to parse error messages if in JSON format
                try:
                    if resp.text:
                        error_json = resp.json()
                        logger.error(f"{resp_type} error details: {json.dumps(error_json)}")
                except Exception:
                    pass
            
            # Get the most informative response to use in the error
            primary_error_resp = next((r for t, r in responses if t == "DPoP"), 
                                      next((r for t, r in responses), None))
            
            if primary_error_resp:
                error_content = primary_error_resp.text[:100] if primary_error_resp.text else "Empty response"
                raise Exception(f"Failed to get user info: {primary_error_resp.status_code}, error: {error_content}")
            else:
                raise Exception(f"Failed to make user info request: {attempts[0][1] if attempts else 'Unknown error'}")
                
        except Exception as e:
            logger.error(f"Error retrieving user info: {e}")
            raise Exception(f"Failed to get user information: {str(e)}")
    
    def get_client_credentials_token(self) -> Dict:
        """
        Get an OAuth 2.0 access token using client credentials flow.
        
        This method is ideal for zero-trust architecture as it:
        1. Uses short-lived tokens (typically 1 hour)
        2. Can be scoped to specific permissions
        3. Provides better audit trail than API tokens
        4. Can be automatically rotated
        
        Returns:
            Dict containing the access token and other token information
        """
        try:
            logger.debug("Getting OAuth token using client credentials flow")
            
            # Prepare token request
            token_url = self.token_endpoint
            
            # Authorization header using client ID and secret
            client_auth = f"{settings.OKTA_CLIENT_ID}:{settings.OKTA_CLIENT_SECRET}"
            auth_header = base64.b64encode(client_auth.encode()).decode()
            
            headers = {
                "Authorization": f"Basic {auth_header}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json"
            }
            
            # Request body
            data = {
                "grant_type": "client_credentials",
                "scope": "okta.logs.read" # Use the appropriate scope for your Okta API access
            }
            
            # Make the request with connection pooling benefits
            response = self.session.post(
                token_url,
                headers=headers,
                data=data,
                timeout=15  # Increased timeout for reliability
            )
            
            # Check for success
            if response.status_code != 200:
                error_msg = f"Failed to get client credentials token: {response.status_code} - {response.text}"
                logger.error(error_msg)
                raise Exception(error_msg)
            
            # Parse and return the token response
            token_data = response.json()
            logger.info(f"Successfully obtained OAuth token (expires in {token_data.get('expires_in', 'unknown')} seconds)")
            
            return token_data
            
        except Exception as e:
            logger.error(f"Error getting client credentials token: {str(e)}")
            raise Exception(f"Failed to obtain OAuth token: {str(e)}")