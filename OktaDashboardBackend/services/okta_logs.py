import logging
import requests
import base64
import time
import uuid
import jwt
import json
import hashlib
import os
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from django.conf import settings
from django.core.cache import cache
from cryptography.hazmat.primitives import serialization

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
    
    def __init__(self):
        """Initialize the Logs API client"""
        self.oauth_client = OktaOAuthClient()
        self.org_url = settings.OKTA_ORG_URL
        self.logs_endpoint = f"{self.org_url}/api/v1/logs"
        
        # Token cache key for this specific client
        self.token_cache_key = "okta_logs_token"
        
        # MongoDB settings
        self.db_service = DatabaseService()
        self.db_name = settings.MONGODB_SETTINGS.get('db', 'okta_dashboard')
        self.logs_collection_name = 'okta_logs'
        
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
        
        return access_token
    
    def _create_dpop_proof_with_token_binding(self, method: str, url: str, access_token: str, nonce: Optional[str] = None) -> str:
        """
        Create a DPoP proof JWT for API requests with token binding
        
        Args:
            method: HTTP method
            url: Target URL
            access_token: The access token to bind to
            nonce: Optional nonce from server
            
        Returns:
            DPoP proof JWT string
        """
        # Load the private key used for DPoP
        private_key = self.oauth_client.private_key
        jwk = self.oauth_client.jwk
        
        # Create the private key in PEM format for JWT signing
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Create hash of the access token for the 'ath' claim
        access_token_hash = hashlib.sha256(access_token.encode()).digest()
        # Base64url encode the hash
        ath = base64.urlsafe_b64encode(access_token_hash).decode('utf-8').rstrip('=')
        
        # Create DPoP proof JWT
        now = int(time.time())
        proof_payload = {
            "jti": str(uuid.uuid4()),
            "htm": method,
            "htu": url,
            "iat": now,
            "exp": now + 60,  # Valid for 1 minute
            "ath": ath  # Add token binding
        }
        
        # Add nonce if provided
        if nonce:
            proof_payload["nonce"] = nonce
        
        # Create the header with the JWK
        header = {
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": jwk
        }
        
        # Sign the JWT
        dpop_proof = jwt.encode(
            payload=proof_payload,
            key=private_key_pem,
            algorithm="RS256",
            headers=header
        )
        
        return dpop_proof
    
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
            logs_collection = self.db_service.get_collection(self.db_name, self.logs_collection_name)
            
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
            dpop_nonce = self.oauth_client._get_dpop_nonce(self.logs_endpoint)
            
            # Create DPoP proof with token binding
            dpop_proof = self._create_dpop_proof_with_token_binding(
                "GET", 
                self.logs_endpoint,  # Use the base endpoint, not including query params
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
            
            logger.debug(f"Making logs request to {self.logs_endpoint}")
            response = self.session.get(
                self.logs_endpoint,
                headers=headers,
                params=params,
                timeout=30  # Longer timeout for logs API
            )
            
            if response.status_code == 200:
                logs_data = response.json()
                logger.info(f"Successfully retrieved {len(logs_data)} logs from {self.logs_endpoint}")
                
                # Store logs in MongoDB if requested
                if store_in_mongodb and logs_data:
                    self._store_logs_in_mongodb(logs_data)
                
                return logs_data
            elif response.status_code == 401 and retry_on_error:
                # Token might be invalid, clear cache and try again with a new token
                logger.warning("Token rejected, getting a new one and retrying")
                cache.delete(self.token_cache_key)
                
                # Recursive call with retry_on_error=False to prevent infinite recursion
                return self.get_logs(params, retry_on_error=False, store_in_mongodb=store_in_mongodb)
            else:
                # Log the error
                logger.error(f"Failed to get logs. Status: {response.status_code}")
                try:
                    error_data = response.json()
                    logger.error(f"Error details: {json.dumps(error_data)}")
                    error_msg = error_data.get("errorSummary", f"Status code: {response.status_code}")
                except Exception:
                    error_msg = f"Status code: {response.status_code}, Response: {response.text[:200]}"
                    
                raise Exception(f"Failed to get Okta logs: {error_msg}")
                
        except Exception as e:
            logger.error(f"Error retrieving logs: {str(e)}")
            raise Exception(f"Failed to retrieve Okta logs: {str(e)}")
    
    def get_logs_with_filter(self, event_type: Optional[str] = None, 
                            start_date: Optional[str] = None,
                            end_date: Optional[str] = None,
                            filter_expression: Optional[str] = None,
                            limit: int = 100,
                            store_in_mongodb: bool = True) -> List[Dict]:
        """
        Get logs with specific filters
        
        Args:
            event_type: Optional event type to filter (e.g., "user.session.start")
            start_date: Optional start date in ISO 8601 format
            end_date: Optional end date in ISO 8601 format
            filter_expression: Optional custom filter expression
            limit: Maximum number of records to return
            store_in_mongodb: Whether to store the logs in MongoDB
            
        Returns:
            List of log entries
        """
        # Build the parameters
        params = {"limit": limit}
        
        # Build filter expressions
        filters = []
        
        if event_type:
            filters.append(f'eventType eq "{event_type}"')
        
        if start_date:
            filters.append(f'published gt "{start_date}"')
            
        if end_date:
            filters.append(f'published lt "{end_date}"')
        
        # Add custom filter if provided
        if filter_expression:
            filters.append(f'({filter_expression})')
        
        # Combine all filters
        if filters:
            params["filter"] = " and ".join(filters)
        
        return self.get_logs(params, store_in_mongodb=store_in_mongodb)
    
    def search_logs(self, query: str, limit: int = 100, store_in_mongodb: bool = True) -> List[Dict]:
        """
        Search logs using a simple query string
        
        Args:
            query: Search query string
            limit: Maximum number of records to return
            store_in_mongodb: Whether to store the logs in MongoDB
            
        Returns:
            List of log entries
        """
        # For simple queries, we'll try to be smart about common patterns
        params = {"limit": limit}
        
        # Check for common query patterns and convert to appropriate filters
        if "@" in query:  # Looks like an email
            params["filter"] = f'actor.alternateId eq "{query}"'
        elif query.startswith("user."):  # Looks like an event type
            params["filter"] = f'eventType eq "{query}"'
        elif query.lower() in ["success", "failed", "failure", "error"]:
            params["filter"] = f'outcome.result eq "{query.upper()}"'
        else:
            # General search - try to find matching targets or actors
            # This is an approximation, as Okta Logs API doesn't have a true search
            params["q"] = query
        
        return self.get_logs(params, store_in_mongodb=store_in_mongodb)
    
    def get_logs_from_mongodb(self, 
                             event_type: Optional[str] = None,
                             start_date: Optional[str] = None,
                             end_date: Optional[str] = None,
                             user_id: Optional[str] = None,
                             limit: int = 100,
                             skip: int = 0) -> List[Dict]:
        """
        Retrieve logs from MongoDB with filtering capabilities
        
        Args:
            event_type: Optional event type filter
            start_date: Optional start date in ISO format
            end_date: Optional end date in ISO format
            user_id: Optional user ID to filter (checks both actor and target)
            limit: Maximum number of records to return
            skip: Number of records to skip (for pagination)
            
        Returns:
            List of log entries from MongoDB
        """
        try:
            # Get MongoDB collection
            logs_collection = self.db_service.get_collection(self.db_name, self.logs_collection_name)
            
            # Build query
            query = {}
            
            if event_type:
                query["eventType"] = event_type
                
            date_query = {}
            if start_date:
                try:
                    start_datetime = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                    date_query["$gte"] = start_datetime
                except ValueError:
                    logger.warning(f"Invalid start_date format: {start_date}")
                    
            if end_date:
                try:
                    end_datetime = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                    date_query["$lte"] = end_datetime
                except ValueError:
                    logger.warning(f"Invalid end_date format: {end_date}")
                    
            if date_query:
                query["_published_date"] = date_query
                
            if user_id:
                # Check for user_id in either actor or target
                query["$or"] = [
                    {"actor.id": user_id},
                    {"target.id": user_id}
                ]
                
            # Perform query
            results = list(logs_collection.find(query)
                          .sort("published", -1)
                          .skip(skip)
                          .limit(limit))
            
            # Remove MongoDB _id field before returning
            for result in results:
                if "_id" in result:
                    del result["_id"]
                    
            logger.info(f"Retrieved {len(results)} logs from MongoDB")
            return results
            
        except Exception as e:
            logger.error(f"Error retrieving logs from MongoDB: {str(e)}")
            return []
            
    def sync_recent_logs(self, hours: int = 24) -> Dict[str, Any]:
        """
        Sync recent logs from Okta to MongoDB
        
        Args:
            hours: Number of hours of logs to sync (default: 24)
            
        Returns:
            Dictionary with sync results
        """
        try:
            # Calculate start date
            start_date = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + 'Z'
            
            # Get logs from Okta with date filter
            params = {
                "filter": f'published gt "{start_date}"',
                "limit": 1000  # Maximum allowed by Okta API
            }
            
            logs = self.get_logs(params, store_in_mongodb=True)
            
            return {
                "success": True,
                "logs_synced": len(logs),
                "sync_period_hours": hours,
                "start_date": start_date
            }
            
        except Exception as e:
            logger.error(f"Error syncing recent logs: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "sync_period_hours": hours
            }