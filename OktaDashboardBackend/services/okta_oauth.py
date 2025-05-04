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
        
        # Session for connection pooling and performance optimization
        self.session = self._create_optimized_session()
    
    def _create_optimized_session(self) -> requests.Session:
        """Create and configure an optimized requests session with connection pooling"""
        session = requests.Session()
        
        # Configure connection pooling
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=2,
            pool_block=False
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
                
                # Get public key in JWK format from the loaded key
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
                
                # Generate a separate key for DPoP (security best practice)
                self.dpop_private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                
                # Get public key in JWK format for DPoP
                dpop_public_key = self.dpop_private_key.public_key()
                dpop_public_numbers = dpop_public_key.public_numbers()
                
                # Convert to JWK format for DPoP
                self.dpop_jwk = {
                    "kty": "RSA",
                    "e": base64.urlsafe_b64encode(dpop_public_numbers.e.to_bytes((dpop_public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                    "n": base64.urlsafe_b64encode(dpop_public_numbers.n.to_bytes((dpop_public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                    "alg": "RS256",
                    "use": "sig"
                }
                
            except Exception as e:
                logger.warning(f"Could not load registered private key: {e}. Generating new keys.")
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
                
                # Use the same key for DPoP in this case
                self.dpop_private_key = self.private_key
                self.dpop_jwk = self.jwk
    
    def _normalize_url_for_dpop(self, http_method: str, url: str) -> str:
        """
        Normalize URL for DPoP proof as per Okta requirements
        
        Args:
            http_method: HTTP method
            url: The original URL
            
        Returns:
            Normalized URL for DPoP proof
        """
        parsed_url = urlparse(url)
        
        # For Okta System Log API, use exactly '/api/v1/logs' as specified in documentation
        if '/api/v1/logs' in url:
            normalized_url = url
            logger.debug(f"Using documented API path for logs API: {normalized_url}")
        elif 'oauth2/v1/token' in url:
            # For token endpoint, use full URL (this works)
            normalized_url = url
            logger.debug(f"Using full URL for token endpoint: {normalized_url}")
        else:
            # For other cases, use the full URL
            normalized_url = url
            logger.debug(f"Using full URL for endpoint: {normalized_url}")
            
        return normalized_url
    
    def create_dpop_proof(self, http_method: str, url: str, nonce: Optional[str] = None, access_token: Optional[str] = None) -> str:
        """
        Create a DPoP proof JWT for API requests with token binding.
        
        Args:
            http_method: HTTP method (POST, GET, etc.)
            url: Target URL
            nonce: Optional nonce from server
            access_token: Optional access token to bind to the proof
            
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
            "jti": str(uuid.uuid4()),
            "htm": http_method,
            "htu": normalized_url,
            "iat": now,
            "exp": now + 60,  # Valid for 1 minute
        }
        
        # Add token binding with 'ath' claim if access_token is provided
        if access_token:
            # Create hash of the access token for the 'ath' claim
            access_token_hash = hashlib.sha256(access_token.encode()).digest()
            # Base64url encode the hash
            ath = base64.urlsafe_b64encode(access_token_hash).decode('utf-8').rstrip('=')
            proof["ath"] = ath
            logger.debug(f"Generated access token hash (ath) for token binding: {ath[:10]}...")
        
        # Add nonce if provided - THIS IS CRITICAL
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
        
        # Debug: decode and print the payload to verify
        try:
            decoded = jwt.decode(dpop_proof, options={"verify_signature": False})
            logger.debug(f"DPoP proof payload: {json.dumps(decoded)}")
        except Exception as e:
            logger.error(f"Error decoding JWT: {e}")
        
        return dpop_proof
    
    def create_client_assertion(self, audience: str) -> str:
        """
        Create a signed JWT assertion for client authentication using private_key_jwt
        
        Args:
            audience: The audience for the token (typically the token endpoint)
            
        Returns:
            Signed JWT token as string
        """
        # Create the private key in PEM format for JWT signing
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Create JWT assertion
        now = int(time.time())
        payload = {
            "iss": self.client_id,      # Issuer - must be the client_id
            "sub": self.client_id,      # Subject - must be the client_id
            "aud": audience,            # Audience - token endpoint
            "jti": str(uuid.uuid4()),   # Unique identifier
            "iat": now,                 # Issued at time
            "exp": now + 60             # Expiration time (1 minute)
        }
        
        # Sign the JWT
        client_assertion = jwt.encode(
            payload=payload,
            key=private_key_pem,
            algorithm="RS256"
        )
        
        logger.debug("Created private_key_jwt client assertion for authentication")
        return client_assertion
    
    def get_dpop_nonce(self, url: str) -> Optional[str]:
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
            initial_proof = self.create_dpop_proof("POST", url)
            
            # Create client assertion for private_key_jwt
            client_assertion = self.create_client_assertion(url)
            
            minimal_headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "DPoP": initial_proof
            }
            
            minimal_data = {
                "client_id": self.client_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion,
                "grant_type": "client_credentials"
            }
            
            dpop_nonce = None
            
            # Make a minimal request to get the nonce
            minimal_response = self.session.post(
                url,
                headers=minimal_headers,
                data=minimal_data,
                timeout=10
            )
            
            logger.debug(f"Minimal POST status: {minimal_response.status_code}")
            logger.debug(f"Response headers: {dict(minimal_response.headers)}")
            
            # Check for DPoP-Nonce header
            if "DPoP-Nonce" in minimal_response.headers:
                dpop_nonce = minimal_response.headers.get("DPoP-Nonce")
                logger.info(f"Got DPoP nonce from response: {dpop_nonce}")
                return dpop_nonce
            
            # Try to extract nonce from error response
            try:
                error_data = minimal_response.json()
                logger.debug(f"Error response: {error_data}")
                
                # Check error description for nonce info
                error_desc = error_data.get("error_description", "")
                if "nonce" in error_desc.lower():
                    logger.info("Error indicates nonce issue")
                    
                    # Check WWW-Authenticate header
                    www_auth = minimal_response.headers.get("WWW-Authenticate", "")
                    if "nonce=" in www_auth:
                        nonce_match = re.search(r'nonce="([^"]+)"', www_auth)
                        if nonce_match:
                            dpop_nonce = nonce_match.group(1)
                            logger.info(f"Extracted nonce from WWW-Authenticate: {dpop_nonce}")
                            return dpop_nonce
            except Exception as parse_error:
                logger.error(f"Error parsing response: {parse_error}")
                logger.debug(f"Raw response: {minimal_response.text[:200]}")
            
            # As a last resort, try to get the nonce with a separate HEAD request
            try:
                head_response = self.session.head(
                    url,
                    headers={"Accept": "application/json", "DPoP": initial_proof},
                    timeout=5
                )
                
                for header_name, header_value in head_response.headers.items():
                    if header_name.lower() == 'dpop-nonce':
                        logger.debug(f"Got DPoP nonce from HEAD request: {header_value}")
                        return header_value
                
                www_auth = head_response.headers.get("WWW-Authenticate", "")
                if "nonce=" in www_auth:
                    nonce_match = re.search(r'nonce="([^"]+)"', www_auth)
                    if nonce_match:
                        nonce = nonce_match.group(1)
                        logger.debug(f"Extracted nonce from HEAD WWW-Authenticate: {nonce}")
                        return nonce
            except Exception as head_error:
                logger.warning(f"Error in HEAD request for nonce: {head_error}")
            
            return None
                
        except Exception as e:
            logger.error(f"Error getting DPoP nonce: {str(e)}")
            return None
    
    def get_client_credentials_token(self, scopes: str = "okta.logs.read okta.users.read") -> Dict:
        """
        Get an OAuth 2.0 access token using client credentials flow with private_key_jwt and DPoP.
        
        Args:
            scopes: Space-separated list of scopes to request
            
        Returns:
            Dict containing the access token and other token information
            
        Raises:
            Exception: If the token request fails
        """
        try:
            logger.info("Attempting OAuth token request with private_key_jwt and DPoP...")
            
            # Step 1: Get a DPoP nonce
            token_url = self.token_endpoint
            dpop_nonce = self.get_dpop_nonce(token_url)
            
            # Step 2: Create client assertion using private_key_jwt
            client_assertion = self.create_client_assertion(token_url)
            
            # Step 3: Create DPoP proof WITH the nonce
            dpop_proof = self.create_dpop_proof("POST", token_url, dpop_nonce)
            
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "DPoP": dpop_proof
            }
            
            # Try with the Okta Management API scope
            data = {
                "client_id": self.client_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion,
                "grant_type": "client_credentials",
                "scope": scopes,
                "token_type": "DPoP"
            }
            
            token_response = self.session.post(
                token_url,
                headers=headers,
                data=data,
                timeout=15
            )
            
            logger.debug(f"Token request status code: {token_response.status_code}")
            logger.debug(f"Token response headers: {dict(token_response.headers)}")
            
            # Check if we need to retry with a new nonce
            if token_response.status_code in [400, 401] and "DPoP-Nonce" in token_response.headers:
                logger.info("Got a new nonce in the error response, retrying...")
                new_nonce = token_response.headers.get("DPoP-Nonce")
                logger.debug(f"New nonce: {new_nonce}")
                
                # Create a new proof with the new nonce
                new_proof = self.create_dpop_proof("POST", token_url, new_nonce)
                headers["DPoP"] = new_proof
                
                # Create a new client assertion
                client_assertion = self.create_client_assertion(token_url)
                data["client_assertion"] = client_assertion
                
                # Try again
                logger.info("Retrying with new nonce...")
                retry_response = self.session.post(
                    token_url,
                    headers=headers,
                    data=data,
                    timeout=15
                )
                
                logger.debug(f"Retry status code: {retry_response.status_code}")
                
                if retry_response.status_code == 200:
                    logger.info("Successfully obtained token after retry!")
                    token_json = retry_response.json()
                    access_token = token_json.get("access_token")
                    expires_in = token_json.get("expires_in")
                    token_type = token_json.get("token_type", "DPoP")
                    
                    logger.debug(f"Token type: {token_type}")
                    logger.debug(f"Expires in: {expires_in} seconds")
                    logger.debug(f"Access token: {access_token[:10]}...{access_token[-10:] if access_token else ''}")
                    
                    # Check what scopes we got in the token
                    scope = token_json.get("scope", "")
                    logger.debug(f"Granted scopes: {scope}")
                    
                    # Get api_nonce from retry response
                    api_nonce = retry_response.headers.get("DPoP-Nonce") or new_nonce
                    token_json['_dpop_nonce'] = api_nonce
                    
                    return token_json
                else:
                    logger.error(f"Token request failed after retry: {retry_response.text[:200]}")
                    try:
                        error_data = retry_response.json()
                        logger.debug(f"Error details: {json.dumps(error_data, indent=2)}")
                    except Exception:
                        pass
                    raise Exception(f"Failed to obtain OAuth token after retry")
            else:
                # Handle the original token response if we didn't need to retry
                if token_response.status_code == 200:
                    logger.info("Successfully obtained token on first attempt!")
                    token_json = token_response.json()
                    access_token = token_json.get("access_token")
                    expires_in = token_json.get("expires_in")
                    token_type = token_json.get("token_type", "DPoP")
                    
                    logger.debug(f"Token type: {token_type}")
                    logger.debug(f"Expires in: {expires_in} seconds")
                    logger.debug(f"Access token: {access_token[:10]}...{access_token[-10:] if access_token else ''}")
                    
                    # Check what scopes we got in the token
                    scope = token_json.get("scope", "")
                    logger.debug(f"Granted scopes: {scope}")
                    
                    # Get api_nonce from token response
                    api_nonce = token_response.headers.get("DPoP-Nonce") or dpop_nonce
                    token_json['_dpop_nonce'] = api_nonce
                    
                    return token_json
                else:
                    logger.error(f"Token request failed: {token_response.text[:200]}")
                    try:
                        error_data = token_response.json()
                        logger.debug(f"Error details: {json.dumps(error_data, indent=2)}")
                        error_msg = f"{error_data.get('error')}: {error_data.get('error_description')}"
                    except Exception:
                        error_msg = token_response.text[:200] if token_response.text else f"Status {token_response.status_code}"
                    
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
        dpop_proof = self.create_dpop_proof(method, url, nonce, access_token)
        
        # Create headers
        headers = {
            "Authorization": f"DPoP {access_token}",
            "Accept": "application/json",
            "DPoP": dpop_proof
        }
        
        return headers