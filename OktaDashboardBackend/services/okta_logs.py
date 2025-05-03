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
from urllib.parse import urlparse
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from django.conf import settings
from django.core.cache import cache
from cryptography.hazmat.primitives import serialization
from pymongo import MongoClient

from OktaDashboardBackend.services.okta_oauth import OktaOAuthClient
from OktaDashboardBackend.services.database import DatabaseService

logger = logging.getLogger(__name__)

class OktaLogsClient:
    """
    Client for accessing Okta System Logs API with enhanced security features.
    
    This client uses the OAuth 2.0 client credentials flow with:
    1. DPoP (Demonstrating Proof of Possession) for token binding
    2. private_key_jwt for client authentication (more secure than client secret)
    3. Automatic token refresh and proper token lifetime management
    4. Specialized error handling for Logs API permission issues
    5. MongoDB storage for retrieved logs
    
    NOTE: Based on testing, this implementation focuses on the Regular Logs API
    which has been confirmed to be working (/api/v1/logs endpoint).
    """
    
    def __init__(self, use_direct_mongodb=False):
        """
        Initialize the Logs API client
        
        Args:
            use_direct_mongodb: If True, use direct MongoDB connection instead of DatabaseService
        """
        self.oauth_client = OktaOAuthClient()
        self.org_url = settings.OKTA_ORG_URL
        self.logs_endpoint = f"{self.org_url}/api/v1/logs"
        
        # Token cache key for this specific client
        self.token_cache_key = "okta_logs_token"
        
        # DPoP nonce cache key
        self.nonce_cache_key = "okta_logs_dpop_nonce"
        
        # MongoDB settings
        self.use_direct_mongodb = use_direct_mongodb
        self.db_name = settings.MONGODB_SETTINGS.get('db', 'okta_dashboard')
        self.logs_collection_name = 'okta_logs'
        
        if not use_direct_mongodb:
            # Use DatabaseService
            self.db_service = DatabaseService()
        else:
            # Direct MongoDB connection parameters
            self.mongo_host = settings.MONGODB_SETTINGS.get('host', 'mongodb://localhost:27017/')
            self.mongo_client = None
        
        # Session for connection pooling and performance optimization
        self.session = self._create_optimized_session()
        
        logger.info(f"OktaLogsClient initialized with logs endpoint: {self.logs_endpoint}")
    
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
    
    def _get_token(self) -> str:
        """
        Get a valid access token, either from cache or by requesting a new one.
        
        Returns:
            Access token string
        """
        # Try to get the token from cache first
        cached_token_data = cache.get(self.token_cache_key)
        
        if cached_token_data:
            # Check if the cached token is still valid (with a 60-second buffer)
            expiry_time = cached_token_data.get('expiry_time', 0)
            if expiry_time > time.time() + 60:
                logger.debug("Using cached Okta API token")
                return cached_token_data.get('access_token')
        
        # No valid cached token, get a new one
        logger.info("Requesting new Okta API token")
        
        # Request token with specific scopes required for logs
        token_data = self.oauth_client.get_client_credentials_token(scopes="okta.logs.read okta.users.read")
        
        access_token = token_data.get('access_token')
        token_type = token_data.get('token_type')
        expires_in = token_data.get('expires_in', 3600)  # Default to 1 hour if not specified
        
        # Calculate absolute expiry time
        expiry_time = time.time() + expires_in
        
        # Cache the token data with absolute expiry time
        cache.set(
            self.token_cache_key,
            {
                'access_token': access_token,
                'token_type': token_type,
                'expiry_time': expiry_time,
                'scope': token_data.get('scope', '')
            },
            # Set cache expiry to match token lifetime (minus a small buffer)
            timeout=expires_in - 60 if expires_in > 60 else expires_in
        )
        
        # Also check for DPoP nonce in response headers and cache it
        dpop_nonce = token_data.get('_dpop_nonce')
        if dpop_nonce:
            cache.set(self.nonce_cache_key, dpop_nonce, timeout=3600)
            logger.debug(f"Cached DPoP nonce: {dpop_nonce}")
        
        return access_token
    
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
        
        # For Okta System Log API, use exactly '/api/v1/logs' as specified in documentation
        if '/api/v1/logs' in url:
            return "/api/v1/logs"
        elif 'oauth2/v1/token' in url:
            # For token endpoint, use full URL
            return url
        else:
            # For other endpoints, use the full URL
            return url
            
    def _get_dpop_nonce(self, url: str) -> Optional[str]:
        """
        Get a DPoP nonce for a specific URL
        
        Args:
            url: The target URL
            
        Returns:
            DPoP nonce if available, None otherwise
        """
        # Try to get from cache first
        cached_nonce = cache.get(self.nonce_cache_key)
        if cached_nonce:
            logger.debug(f"Using cached DPoP nonce: {cached_nonce}")
            return cached_nonce
            
        # If not in cache, try to get a new one with a minimal request
        try:
            # Create a DPoP proof without nonce
            token_url = settings.OKTA_TOKEN_ENDPOINT
            initial_proof = self._create_dpop_proof(
                "POST", 
                token_url, 
                None,  # No access token for this probe request
                None   # No nonce yet
            )
            
            # Create minimal headers
            minimal_headers = {
                "Accept": "application/json",
                "DPoP": initial_proof
            }
            
            # Make a HEAD request to probe for nonce
            response = self.session.head(
                url, 
                headers=minimal_headers,
                timeout=10
            )
            
            # Check for DPoP-Nonce header
            if "DPoP-Nonce" in response.headers:
                nonce = response.headers.get("DPoP-Nonce")
                logger.debug(f"Got DPoP nonce from response: {nonce}")
                
                # Cache the nonce
                cache.set(self.nonce_cache_key, nonce, timeout=3600)
                return nonce
            
            # Check WWW-Authenticate header for nonce
            www_auth = response.headers.get("WWW-Authenticate", "")
            if "nonce=" in www_auth:
                nonce_match = re.search(r'nonce="([^"]+)"', www_auth)
                if nonce_match:
                    nonce = nonce_match.group(1)
                    logger.debug(f"Extracted nonce from WWW-Authenticate: {nonce}")
                    
                    # Cache the nonce
                    cache.set(self.nonce_cache_key, nonce, timeout=3600)
                    return nonce
            
            return None
            
        except Exception as e:
            logger.warning(f"Error getting DPoP nonce: {str(e)}")
            return None
    
    def _create_dpop_proof(self, method: str, url: str, access_token: Optional[str] = None, nonce: Optional[str] = None) -> str:
        """
        Create a DPoP proof JWT for API requests, with optional token binding
        
        Args:
            method: HTTP method
            url: Target URL
            access_token: Optional access token to bind to
            nonce: Optional nonce from server
            
        Returns:
            DPoP proof JWT string
        """
        # Load the private key and JWK from oauth client
        private_key = self.oauth_client.private_key
        jwk = self.oauth_client.jwk
        
        # Create the private key in PEM format for JWT signing
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Normalize the URL for proper DPoP usage
        normalized_url = self._normalize_url_for_dpop(method, url)
        
        # Create DPoP proof JWT
        now = int(time.time())
        proof = {
            "jti": str(uuid.uuid4()),
            "htm": method,
            "htu": normalized_url,
            "iat": now,
            "exp": now + 60,  # Valid for 1 minute
        }
        
        # Add token binding with 'ath' claim if access token is provided
        if access_token:
            # Create hash of the access token for the 'ath' claim
            access_token_hash = hashlib.sha256(access_token.encode()).digest()
            # Base64url encode the hash
            ath = base64.urlsafe_b64encode(access_token_hash).decode('utf-8').rstrip('=')
            proof["ath"] = ath
        
        # Add nonce if provided - CRITICAL for Okta API
        if nonce:
            proof["nonce"] = nonce
            logger.debug(f"Including nonce in DPoP proof: {nonce}")
        
        # Create the header with the JWK
        header = {
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": jwk
        }
        
        # Sign the JWT
        dpop_proof = jwt.encode(
            payload=proof,
            key=private_key_pem,
            algorithm="RS256",
            headers=header
        )
        
        return dpop_proof
        
    def _get_mongodb_collection(self):
        """
        Get MongoDB collection for logs, either via DatabaseService or direct connection
        
        Returns:
            MongoDB collection
        """
        if not self.use_direct_mongodb:
            # Use DatabaseService
            return self.db_service.get_collection(self.db_name, self.logs_collection_name)
        else:
            # Direct MongoDB connection
            if not self.mongo_client:
                import mongoengine
                
                # Disconnect any existing connections first
                mongoengine.disconnect_all()
                
                # Create direct connection
                self.mongo_client = MongoClient(self.mongo_host)
            
            # Return collection
            return self.mongo_client[self.db_name][self.logs_collection_name]
    
    def _store_logs_in_mongodb(self, logs_data: List[Dict]) -> bool:
        """
        Store logs in MongoDB with proper indexing and error handling
        
        Args:
            logs_data: List of log entries to store
            
        Returns:
            True if successful, False otherwise
        """
        if not logs_data:
            logger.warning("No logs to store in MongoDB")
            return False
            
        try:
            # Get MongoDB collection
            logs_collection = self._get_mongodb_collection()
            
            # Ensure indexes exist for efficient querying
            # We do this in a try-except block to avoid errors if indexes already exist
            try:
                logs_collection.create_index("uuid", unique=True)
                logs_collection.create_index("published")
                logs_collection.create_index("eventType")
                logs_collection.create_index([("actor.id", 1), ("published", -1)])
                logs_collection.create_index([("target.id", 1), ("published", -1)])
                logs_collection.create_index("outcome.result")
            except Exception as e:
                logger.debug(f"Index creation note: {str(e)}")
            
            # Process each log entry before insertion
            processed_logs = []
            for log in logs_data:
                # Add import timestamp
                log['_imported_at'] = datetime.utcnow().isoformat()
                
                # Add MongoDB-specific fields for efficient querying
                if 'published' in log and isinstance(log['published'], str):
                    try:
                        # Store the published date as ISODate for MongoDB
                        published_date = datetime.fromisoformat(log['published'].replace('Z', '+00:00'))
                        log['_published_date'] = published_date
                    except Exception as date_error:
                        logger.warning(f"Error parsing published date: {date_error}")
                
                processed_logs.append(log)
            
            # Use bulk insert for performance, with ordered=False to continue on duplicate key errors
            if processed_logs:
                result = logs_collection.insert_many(processed_logs, ordered=False)
                inserted_count = len(result.inserted_ids)
                logger.info(f"Successfully stored {inserted_count} out of {len(processed_logs)} logs in MongoDB")
                return True
            else:
                return False
                
        except Exception as e:
            logger.error(f"Error storing logs in MongoDB: {str(e)}")
            return False
    
    def get_logs(self, params: Optional[Dict] = None, retry_on_error: bool = True, store_in_mongodb: bool = True) -> List[Dict]:
        """
        Get logs from the Okta System Log API and optionally store them in MongoDB
        
        Args:
            params: Optional query parameters for filtering logs
            retry_on_error: Whether to retry on certain errors (default: True)
            store_in_mongodb: Whether to store the logs in MongoDB (default: True)
            
        Returns:
            List of log entries
            
        Raises:
            Exception: If the logs API request fails
        """
        try:
            # Default parameters if none provided
            if params is None:
                params = {"limit": 100}
            
            # Get an access token
            access_token = self._get_token()
            
            # Get the DPoP nonce if available
            dpop_nonce = self._get_dpop_nonce(self.logs_endpoint)
            
            # Create DPoP proof with token binding
            # For logs API, use exactly '/api/v1/logs' (not the full URL) for the htu claim
            dpop_proof = self._create_dpop_proof(
                "GET", 
                self.logs_endpoint,
                access_token,
                dpop_nonce
            )
            
            # Set up headers with DPoP proof
            headers = {
                "Authorization": f"DPoP {access_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "DPoP": dpop_proof
            }
            
            # Debug information
            logger.debug(f"Making logs request to {self.logs_endpoint}")
            logger.debug(f"Query parameters: {params}")
            
            # Check if the filter parameter uses proper ISO 8601 format
            if 'filter' in params and 'published gt' in params['filter']:
                logger.debug(f"Filter detected: {params['filter']}")
                
                # Make sure it's properly formatted for Okta API
                # Okta's API expects filter=published gt "2025-05-03T01:04:38.075Z"
                # Note: Make sure the date has a 'Z' suffix and milliseconds end with Z, not microseconds
                if 'Z"' not in params['filter']:
                    logger.debug("Fixing timestamp format in filter")
                    date_pattern = r'"([^"]+)"'
                    match = re.search(date_pattern, params['filter'])
                    if match:
                        original_date = match.group(1)
                        if '.' in original_date:
                            # If there are microseconds, truncate to milliseconds and add Z
                            base_date, fraction = original_date.split('.')
                            if 'Z' not in fraction:
                                # Truncate microseconds to 3 digits (milliseconds) and add Z
                                fixed_date = f"{base_date}.{fraction[:3]}Z"
                                params['filter'] = params['filter'].replace(original_date, fixed_date)
                                logger.debug(f"Fixed timestamp in filter: {params['filter']}")
                        elif 'Z' not in original_date:
                            # If no fraction, add Z if missing
                            fixed_date = f"{original_date}Z"
                            params['filter'] = params['filter'].replace(original_date, fixed_date)
                            logger.debug(f"Added Z suffix to timestamp: {params['filter']}")
            
            # Make the request
            response = self.session.get(
                self.logs_endpoint,
                headers=headers,
                params=params,
                timeout=30  # Longer timeout for logs API
            )
            
            # Debug information - get full URL after params are added
            logger.debug(f"Full request URL: {response.request.url}")
            logger.debug(f"Response status: {response.status_code}")
            
            # Check for new nonce in the response and update cache
            if "DPoP-Nonce" in response.headers:
                new_nonce = response.headers.get("DPoP-Nonce")
                logger.debug(f"Got new DPoP nonce from response: {new_nonce}")
                cache.set(self.nonce_cache_key, new_nonce, timeout=3600)
            
            if response.status_code == 200:
                logs_data = response.json()
                logger.info(f"Successfully retrieved {len(logs_data)} logs from {self.logs_endpoint}")
                
                # Store logs in MongoDB if requested
                if store_in_mongodb and logs_data:
                    self._store_logs_in_mongodb(logs_data)
                
                return logs_data
            elif response.status_code == 401 and "DPoP-Nonce" in response.headers and retry_on_error:
                # Token or DPoP proof rejected, but we have a new nonce - retry
                logger.warning("DPoP proof rejected, trying again with new nonce")
                new_nonce = response.headers.get("DPoP-Nonce")
                cache.set(self.nonce_cache_key, new_nonce, timeout=3600)
                
                # Retry with new nonce
                return self.get_logs(params, retry_on_error=False, store_in_mongodb=store_in_mongodb)
                
            elif response.status_code == 401 and retry_on_error:
                # Token might be invalid, clear cache and try again with a new token
                logger.warning("Token rejected, getting a new one and retrying")
                cache.delete(self.token_cache_key)
                
                # Recursive call with retry_on_error=False to prevent infinite recursion
                return self.get_logs(params, retry_on_error=False, store_in_mongodb=store_in_mongodb)
            else:
                # Log the error and response content
                logger.error(f"Failed to get logs. Status: {response.status_code}")
                logger.error(f"Response content: {response.text[:500]}")
                
                try:
                    error_data = response.json()
                    logger.error(f"Error details: {json.dumps(error_data)}")
                    error_msg = error_data.get("errorSummary", f"Status code: {response.status_code}")
                except Exception:
                    error_msg = f"Status code: {response.status_code}, Response: {response.text[:200]}"
                    
                # If it's a 400 error, it might be a filter format issue
                if response.status_code == 400 and 'filter' in params:
                    logger.warning("Potential issue with filter format. Trying simplified request.")
                    
                    # Try a simpler request with just the limit parameter
                    simpler_params = {"limit": params.get("limit", 100)}
                    if retry_on_error:
                        return self.get_logs(simpler_params, retry_on_error=False, store_in_mongodb=store_in_mongodb)
                
                raise Exception(f"Failed to get Okta logs: {error_msg}")
                
        except Exception as e:
            logger.error(f"Error retrieving logs: {str(e)}")
            raise Exception(f"Failed to retrieve Okta logs: {str(e)}")