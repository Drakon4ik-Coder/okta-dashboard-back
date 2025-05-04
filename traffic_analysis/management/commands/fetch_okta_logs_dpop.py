import logging
import argparse
import requests
import base64
import time
import uuid
import jwt
import json
import hashlib
import os
import sys
import re
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.conf import settings
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from urllib.parse import urlparse, quote
from pymongo import MongoClient

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Fetches Okta logs using DPoP authentication and stores them in MongoDB'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=0,
            help='Fetch logs from the last N days'
        )
        parser.add_argument(
            '--hours',
            type=int,
            default=0,
            help='Fetch logs from the last N hours'
        )
        parser.add_argument(
            '--minutes',
            type=int,
            default=15,
            help='Fetch logs from the last N minutes'
        )
        parser.add_argument(
            '--limit',
            type=int,
            default=100,
            help='Maximum number of logs to fetch per request (max 1000)'
        )
        parser.add_argument(
            '--filter',
            type=str,
            help='Filter query for Okta logs (e.g. "eventType eq \"user.session.start\"")'
        )
        parser.add_argument(
            '--since',
            type=str,
            help='ISO8601 timestamp to fetch logs since (e.g. "2025-05-01T00:00:00.000Z")'
        )
        parser.add_argument(
            '--max-pages',
            type=int,
            default=10,
            help='Maximum number of pages to fetch (0 for unlimited)'
        )
        parser.add_argument(
            '--direct-mongo',
            action='store_true',
            default=False,
            help='Use direct MongoDB connection instead of DatabaseService'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            default=False,
            help='Only fetch logs, do not store them in the database'
        )
        parser.add_argument(
            '--debug',
            action='store_true',
            default=False,
            help='Enable debug output'
        )

    def handle(self, *args, **options):
        days = options['days']
        hours = options['hours']
        minutes = options['minutes']
        limit = min(options['limit'], 1000)  # Okta API max limit is 1000
        filter_query = options.get('filter')
        since_param = options.get('since')
        max_pages = options['max_pages']
        use_direct_mongo = options['direct_mongo']
        dry_run = options['dry_run']
        debug = options['debug']
        
        # Calculate the start time based on provided options
        if since_param:
            try:
                # Parse the provided ISO8601 timestamp
                start_time = datetime.fromisoformat(since_param.replace('Z', '+00:00'))
                self.stdout.write(f"Using provided since parameter: {since_param}")
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error parsing since parameter: {e}"))
                self.stdout.write(self.style.ERROR("Using default time range instead"))
                # Fall back to calculating time range
                start_time = self._calculate_start_time(days, hours, minutes)
        else:
            # Calculate based on days, hours, minutes
            start_time = self._calculate_start_time(days, hours, minutes)
            
        # Format the start time for Okta's since parameter (ISO 8601 with exactly 3 decimal places)
        since_iso = start_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        self.stdout.write(f"Fetching Okta logs since {since_iso}")
        
        # Get Okta settings from Django settings
        org_url = settings.OKTA_ORG_URL
        client_id = settings.OKTA_CLIENT_ID
        client_secret = settings.OKTA_CLIENT_SECRET
        token_endpoint = settings.OKTA_TOKEN_ENDPOINT or f"{org_url}/oauth2/v1/token"
        
        # Validate required parameters
        if not org_url or not client_id or not token_endpoint:
            self.stdout.write(self.style.ERROR("ERROR: Missing required Okta configuration."))
            self.stdout.write(self.style.ERROR("Please set OKTA_ORG_URL and OKTA_CLIENT_ID in your settings.py or .env file."))
            return
        
        try:
            # Load or generate RSA key pair
            self.stdout.write("Loading registered private key from keys/private_key.pem...")
            try:
                # Use the same private key that was registered with Okta
                private_key_path = os.path.join(settings.BASE_DIR, 'keys', 'private_key.pem')
                with open(private_key_path, 'rb') as key_file:
                    private_key_data = key_file.read()
                
                private_key = serialization.load_pem_private_key(
                    private_key_data,
                    password=None
                )
                self.stdout.write(self.style.SUCCESS("✅ Successfully loaded the registered private key!"))
                
                # Get public key in JWK format from the loaded key
                public_key = private_key.public_key()
                public_numbers = public_key.public_numbers()
                
                # Convert to JWK format
                jwk = {
                    "kty": "RSA",
                    "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                    "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                    "alg": "RS256",
                    "use": "sig"
                }
                
                # Generate a separate key for DPoP (security best practice)
                dpop_private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                
                # Get public key in JWK format for DPoP
                dpop_public_key = dpop_private_key.public_key()
                dpop_public_numbers = dpop_public_key.public_numbers()
                
                # Convert to JWK format for DPoP
                dpop_jwk = {
                    "kty": "RSA",
                    "e": base64.urlsafe_b64encode(dpop_public_numbers.e.to_bytes((dpop_public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                    "n": base64.urlsafe_b64encode(dpop_public_numbers.n.to_bytes((dpop_public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                    "alg": "RS256",
                    "use": "sig"
                }
                
            except Exception as e:
                self.stdout.write(self.style.WARNING(f"[ERROR] Error loading the registered private key: {e}"))
                self.stdout.write(self.style.WARNING("Generating a new key pair instead - IMPORTANT: This won't work with Okta unless registered"))
                # Generate private key
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                
                # Get public key in JWK format
                public_key = private_key.public_key()
                public_numbers = public_key.public_numbers()
                
                # Convert to JWK format
                jwk = {
                    "kty": "RSA",
                    "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                    "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                    "alg": "RS256",
                    "use": "sig"
                }
                
                # Use the same key for DPoP in this case
                dpop_private_key = private_key
                dpop_jwk = jwk
            
            self.stdout.write("RSA key pair setup completed")
            
            # Create a function to create DPoP proof
            def create_dpop_proof(http_method, url, nonce=None, access_token=None):
                # Create the private key in PEM format for JWT signing
                private_key_pem = dpop_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                # Parse the URL to extract components
                parsed_url = urlparse(url)
                
                if debug:
                    self.stdout.write(f"Original URL for DPoP: {url}")
                    self.stdout.write(f"Parsed URL - scheme: {parsed_url.scheme}, netloc: {parsed_url.netloc}, path: {parsed_url.path}, query: {parsed_url.query}")
                
                # For Okta System Log API, use exactly '/api/v1/logs' as specified in documentation
                if '/api/v1/logs' in url:
                    normalized_url = "/api/v1/logs"
                    if debug:
                        self.stdout.write(f"Using documented API path for logs API: {normalized_url}")
                elif 'oauth2/v1/token' in url:
                    # For token endpoint, use full URL (this works)
                    normalized_url = url
                    if debug:
                        self.stdout.write(f"Using full URL for token endpoint: {normalized_url}")
                else:
                    # For other cases, use the full URL
                    normalized_url = url
                    if debug:
                        self.stdout.write(f"Using full URL for endpoint: {normalized_url}")
                
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
                    if debug:
                        self.stdout.write(f"Generated access token hash (ath) for token binding: {ath[:10]}...")
                
                # Add nonce if provided - THIS IS CRITICAL
                if nonce:
                    proof["nonce"] = nonce
                    if debug:
                        self.stdout.write(f"Including nonce in DPoP proof: {nonce}")
                
                # Create the header with the JWK
                header = {
                    "typ": "dpop+jwt",
                    "alg": "RS256",
                    "jwk": dpop_jwk
                }
                
                # Sign the JWT
                dpop_proof = jwt.encode(
                    payload=proof,
                    key=private_key_pem,
                    algorithm="RS256",
                    headers=header
                )
                
                # Debug: decode and print the payload to verify
                if debug:
                    try:
                        decoded = jwt.decode(dpop_proof, options={"verify_signature": False})
                        self.stdout.write(f"DPoP proof payload: {json.dumps(decoded)}")
                    except Exception as e:
                        self.stdout.write(f"Error decoding JWT: {e}")
                
                return dpop_proof
            
            # Function to create private_key_jwt client assertion
            def create_client_assertion(token_url):
                # Create the private key in PEM format for JWT signing
                # IMPORTANT: This is where we use the registered private key
                private_key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                # Create JWT assertion
                now = int(time.time())
                payload = {
                    "iss": client_id,      # Issuer - must be the client_id
                    "sub": client_id,      # Subject - must be the client_id
                    "aud": token_url,      # Audience - token endpoint
                    "jti": str(uuid.uuid4()),   # Unique identifier
                    "iat": now,                 # Issued at time
                    "exp": now + 60             # Expiration time (1 minute)
                }
                
                # Get key ID from environment or from a default fallback
                key_id = os.environ.get('OKTA_LOGS_KEY_ID', 'jvZNekvTGbOrrbbtpmL89qZon5s8WGqR65wtko1yFpc')
                if debug:
                    self.stdout.write(f"Using key ID (kid): {key_id}")
                
                # Create JWT header with kid
                headers = {
                    "alg": "RS256",
                    "kid": key_id  # Add the key ID to the JWT header
                }
                
                # Sign the JWT with headers that include the kid
                client_assertion = jwt.encode(
                    payload=payload,
                    key=private_key_pem,
                    algorithm="RS256",
                    headers=headers
                )
                
                if debug:
                    self.stdout.write("Created private_key_jwt client assertion for authentication")
                return client_assertion
            
            # Function to store logs in MongoDB
            def store_logs_in_mongodb(logs_data):
                if not logs_data:
                    self.stdout.write("No logs to store in MongoDB")
                    return 0
                
                try:
                    # Import the required MongoDB libraries
                    import mongoengine
                    from pymongo import MongoClient
                    
                    # Disconnect any existing connections first
                    mongoengine.disconnect_all()
                    if debug:
                        self.stdout.write("Disconnected existing MongoDB connections")
                    
                    # Get MongoDB settings from Django settings
                    mongo_settings = settings.MONGODB_SETTINGS
                    mongo_host = mongo_settings.get('host', 'mongodb://localhost:27017/')
                    db_name = mongo_settings.get('db', 'okta_dashboard')
                    collection_name = 'okta_logs'
                    
                    # Create direct connection to MongoDB
                    client = MongoClient(mongo_host)
                    logs_collection = client[db_name][collection_name]
                    self.stdout.write(self.style.SUCCESS(f"✓ Successfully connected to MongoDB at {mongo_host}"))
                    
                    # Create indexes if they don't exist
                    try:
                        logs_collection.create_index("uuid", unique=True)
                        logs_collection.create_index("published")
                        logs_collection.create_index("eventType")
                        logs_collection.create_index([("actor.id", 1), ("published", -1)])
                        logs_collection.create_index([("target.id", 1), ("published", -1)])
                        if debug:
                            self.stdout.write("✓ Successfully created MongoDB indexes for logs collection")
                    except Exception as e:
                        if debug:
                            self.stdout.write(f"Note about indexes: {str(e)}")
                    
                    # Process the logs for storage
                    # Add import timestamp
                    for log in logs_data:
                        log['_imported_at'] = datetime.utcnow().isoformat()
                        
                        # Add MongoDB-specific fields for efficient querying
                        if 'published' in log and isinstance(log['published'], str):
                            try:
                                # Store the published date as ISODate for MongoDB
                                published_date = datetime.fromisoformat(log['published'].replace('Z', '+00:00'))
                                log['_published_date'] = published_date.isoformat()
                            except Exception as date_error:
                                if debug:
                                    self.stdout.write(f"Error parsing published date: {date_error}")
                    
                    inserted_count = 0
                    try:
                        # Use bulk insert with unordered option to continue on duplicate key errors
                        result = logs_collection.insert_many(logs_data, ordered=False)
                        inserted_count = len(result.inserted_ids)
                        self.stdout.write(self.style.SUCCESS(f"✓ Successfully stored {inserted_count} logs in MongoDB"))
                    except Exception as e:
                        if "E11000 duplicate key error" in str(e):
                            # Try to extract count from the error message
                            match = re.search(r'Inserted (\d+) document', str(e))
                            if match:
                                inserted_count = int(match.group(1))
                                self.stdout.write(f"Partially inserted {inserted_count} logs, some were already in MongoDB (duplicate keys)")
                            else:
                                self.stdout.write("Some logs were already in MongoDB (duplicate keys)")
                        else:
                            self.stdout.write(self.style.ERROR(f"Error during MongoDB insertion: {str(e)}"))
                    
                    # Don't forget to close the connection when done
                    client.close()
                    if debug:
                        self.stdout.write("MongoDB connection closed")
                    
                    return inserted_count
                        
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"Error with MongoDB integration: {str(e)}"))
                    return 0
            
            # Step 1: First try to get a nonce via a minimal POST request
            self.stdout.write("\nRequesting DPoP nonce via minimal POST request...")
            initial_proof = create_dpop_proof("POST", token_endpoint)
            
            # Create client assertion for private_key_jwt
            client_assertion = create_client_assertion(token_endpoint)
            
            minimal_headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "DPoP": initial_proof
            }
            
            minimal_data = {
                "client_id": client_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion,
                "grant_type": "client_credentials"
            }
            
            dpop_nonce = None
            try:
                minimal_response = requests.post(
                    token_endpoint,
                    headers=minimal_headers,
                    data=minimal_data,
                    timeout=10
                )
                
                if debug:
                    self.stdout.write(f"Minimal POST status: {minimal_response.status_code}")
                    self.stdout.write(f"Response headers: {dict(minimal_response.headers)}")
                
                # Check for DPoP-Nonce header
                if "DPoP-Nonce" in minimal_response.headers:
                    dpop_nonce = minimal_response.headers.get("DPoP-Nonce")
                    self.stdout.write(f"✓ Got DPoP nonce from response: {dpop_nonce}")
                else:
                    # Try to extract from error response
                    try:
                        error_data = minimal_response.json()
                        if debug:
                            self.stdout.write(f"Error response: {error_data}")
                        
                        # Check error description for nonce info
                        error_desc = error_data.get("error_description", "")
                        if "nonce" in error_desc.lower():
                            self.stdout.write("Error indicates nonce issue")
                            
                            # Check WWW-Authenticate header
                            www_auth = minimal_response.headers.get("WWW-Authenticate", "")
                            if "nonce=" in www_auth:
                                nonce_match = re.search(r'nonce="([^"]+)"', www_auth)
                                if nonce_match:
                                    dpop_nonce = nonce_match.group(1)
                                    self.stdout.write(f"✓ Extracted nonce from WWW-Authenticate: {dpop_nonce}")
                    except Exception as parse_error:
                        self.stdout.write(f"Error parsing response: {parse_error}")
                        if debug:
                            self.stdout.write(f"Raw response: {minimal_response.text[:200]}")
                        
            except Exception as e:
                self.stdout.write(f"Error in minimal POST: {e}")
            
            # Step 2: Now try the token request with nonce (if we have one)
            self.stdout.write("\nAttempting OAuth token request with private_key_jwt and DPoP...")
            
            # Create client assertion using private_key_jwt
            client_assertion = create_client_assertion(token_endpoint)
            
            # Create DPoP proof WITH the nonce
            dpop_proof = create_dpop_proof("POST", token_endpoint, dpop_nonce)
            
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "DPoP": dpop_proof
            }
            
            # Try with the Okta Management API scope
            data = {
                "client_id": client_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion,
                "grant_type": "client_credentials",
                "scope": "okta.logs.read okta.users.read",  # Request multiple scopes for Okta APIs
                "token_type": "DPoP"
            }
            
            token_response = requests.post(
                token_endpoint,
                headers=headers,
                data=data,
                timeout=15
            )
            
            if debug:
                self.stdout.write(f"Token request status code: {token_response.status_code}")
                self.stdout.write(f"Token response headers: {dict(token_response.headers)}")
            
            access_token = None
            
            # Check if we need to retry with a new nonce
            if token_response.status_code in [400, 401] and "DPoP-Nonce" in token_response.headers:
                self.stdout.write("Got a new nonce in the error response, retrying...")
                new_nonce = token_response.headers.get("DPoP-Nonce")
                if debug:
                    self.stdout.write(f"New nonce: {new_nonce}")
                
                # Create a new proof with the new nonce
                new_proof = create_dpop_proof("POST", token_endpoint, new_nonce)
                headers["DPoP"] = new_proof
                
                # Create a new client assertion
                client_assertion = create_client_assertion(token_endpoint)
                data["client_assertion"] = client_assertion
                
                # Try again
                self.stdout.write("Retrying with new nonce...")
                retry_response = requests.post(
                    token_endpoint,
                    headers=headers,
                    data=data,
                    timeout=15
                )
                
                if debug:
                    self.stdout.write(f"Retry status code: {retry_response.status_code}")
                
                if retry_response.status_code == 200:
                    self.stdout.write(self.style.SUCCESS("✓ Successfully obtained token after retry!"))
                    token_json = retry_response.json()
                    access_token = token_json.get("access_token")
                    expires_in = token_json.get("expires_in")
                    token_type = token_json.get("token_type", "DPoP")
                    
                    if debug:
                        self.stdout.write(f"Token type: {token_type}")
                        self.stdout.write(f"Expires in: {expires_in} seconds")
                        self.stdout.write(f"Access token: {access_token[:10]}...{access_token[-10:] if access_token else ''}")
                    
                    # Check what scopes we got in the token
                    scope = token_json.get("scope", "")
                    if debug:
                        self.stdout.write(f"Granted scopes: {scope}")
                    
                    # Get api_nonce from retry response
                    api_nonce = retry_response.headers.get("DPoP-Nonce") or new_nonce
                else:
                    self.stdout.write(self.style.ERROR(f"Token request failed after retry: {retry_response.text[:200]}"))
                    try:
                        error_data = retry_response.json()
                        if debug:
                            self.stdout.write(f"Error details: {json.dumps(error_data, indent=2)}")
                    except Exception:
                        pass
            else:
                # Handle the original token response if we didn't need to retry
                if token_response.status_code == 200:
                    self.stdout.write(self.style.SUCCESS("✓ Successfully obtained token on first attempt!"))
                    token_json = token_response.json()
                    access_token = token_json.get("access_token")
                    expires_in = token_json.get("expires_in")
                    token_type = token_json.get("token_type", "DPoP")
                    
                    if debug:
                        self.stdout.write(f"Token type: {token_type}")
                        self.stdout.write(f"Expires in: {expires_in} seconds")
                        self.stdout.write(f"Access token: {access_token[:10]}...{access_token[-10:] if access_token else ''}")
                    
                    # Check what scopes we got in the token
                    scope = token_json.get("scope", "")
                    if debug:
                        self.stdout.write(f"Granted scopes: {scope}")
                    
                    # Get api_nonce from token response
                    api_nonce = token_response.headers.get("DPoP-Nonce") or dpop_nonce
                else:
                    self.stdout.write(self.style.ERROR(f"Token request failed: {token_response.text[:200]}"))
                    try:
                        error_data = token_response.json()
                        if debug:
                            self.stdout.write(f"Error details: {json.dumps(error_data, indent=2)}")
                    except Exception:
                        pass
            
            # Step 3: Fetch logs with pagination if we got a token successfully
            if access_token:
                self.stdout.write("\n========== FETCHING LOGS FROM OKTA API ==========")
                
                # Set up base URL and parameters for logs API
                logs_url = f"{org_url}/api/v1/logs"
                
                # Build query parameters
                query_params = {}
                
                # Add limit parameter
                query_params["limit"] = limit
                
                # Add since parameter (recommended by Okta API docs)
                query_params["since"] = since_iso
                
                # Add filter if specified
                if filter_query:
                    query_params["filter"] = filter_query
                
                # Create private key in PEM format for JWT signing
                private_key_pem = dpop_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                # Track pagination
                page_count = 0
                total_logs = 0
                has_more_pages = True
                next_url = None
                all_logs = []  # Collect all logs for later insertion
                
                # Continue fetching pages until we've reached the max or there are no more
                while has_more_pages and (max_pages == 0 or page_count < max_pages):
                    page_count += 1
                    self.stdout.write(f"\nFetching page {page_count} of logs...")
                    
                    # Use the next URL from Link header if we have one, otherwise use the base URL with params
                    url_to_fetch = next_url if next_url else logs_url
                    
                    # Create the DPoP proof for this specific request
                    access_token_hash = hashlib.sha256(access_token.encode()).digest()
                    ath = base64.urlsafe_b64encode(access_token_hash).decode('utf-8').rstrip('=')
                    
                    # For the first page, we need to add query params
                    if page_count == 1:
                        # Build the URL with query parameters
                        params_list = []
                        
                        for key, value in query_params.items():
                            encoded_value = quote(str(value))
                            params_list.append(f"{key}={encoded_value}")
                        
                        params_string = "&".join(params_list)
                        url_with_params = f"{url_to_fetch}?{params_string}"
                        
                        if debug:
                            self.stdout.write(f"First page URL: {url_with_params}")
                    else:
                        # Use the next URL directly
                        url_with_params = url_to_fetch
                        if debug:
                            self.stdout.write(f"Next page URL: {url_with_params}")
                    
                    # Create the payload with full URL for htu since that's what works
                    logs_proof_payload = {
                        "jti": str(uuid.uuid4()),
                        "htm": "GET",
                        "htu": logs_url,  # Use the base URL as per test.py's working approach
                        "iat": int(time.time()),
                        "exp": int(time.time()) + 60,
                        "ath": ath,  # Token binding
                    }
                    
                    # Add nonce if available
                    if api_nonce:
                        logs_proof_payload["nonce"] = api_nonce
                        if debug:
                            self.stdout.write(f"Including nonce in Logs API DPoP proof: {api_nonce}")
                    
                    # Create the header for JWT
                    header = {
                        "typ": "dpop+jwt",
                        "alg": "RS256",
                        "jwk": dpop_jwk
                    }
                    
                    # Sign the JWT
                    logs_proof = jwt.encode(
                        payload=logs_proof_payload,
                        key=private_key_pem,
                        algorithm="RS256",
                        headers=header
                    )
                    
                    # Set up headers for the request
                    logs_headers = {
                        "Authorization": f"DPoP {access_token}",
                        "Accept": "application/json",
                        "DPoP": logs_proof
                    }
                    
                    try:
                        # Make the request - use proper approach based on page
                        if page_count == 1:
                            # For first page, use query parameters
                            logs_response = requests.get(
                                url_with_params,
                                headers=logs_headers,
                                timeout=30
                            )
                        else:
                            # For pagination, just use the next URL directly
                            logs_response = requests.get(
                                url_with_params,
                                headers=logs_headers,
                                timeout=30
                            )
                        
                        self.stdout.write(f"Logs API status for page {page_count}: {logs_response.status_code}")
                        
                        if logs_response.status_code == 200:
                            # Extract logs from response
                            page_logs = logs_response.json()
                            page_log_count = len(page_logs)
                            total_logs += page_log_count
                            
                            self.stdout.write(self.style.SUCCESS(f"✓ Successfully retrieved {page_log_count} logs on page {page_count}"))
                            
                            # Add logs to our collection
                            all_logs.extend(page_logs)
                            
                            # Check if there are more pages via Link header
                            link_header = logs_response.headers.get('Link', '')
                            if debug:
                                self.stdout.write(f"Link header: {link_header}")
                            
                            # Extract next URL if there is one
                            next_url = None
                            if link_header:
                                # Parse the Link header to find the "next" link
                                links = link_header.split(',')
                                for link in links:
                                    if 'rel="next"' in link:
                                        url_match = re.search(r'<([^>]+)>', link)
                                        if url_match:
                                            next_url = url_match.group(1)
                                            if debug:
                                                self.stdout.write(f"Found next URL: {next_url}")
                                            break
                            
                            # Set has_more_pages based on whether we found a next URL
                            has_more_pages = next_url is not None
                            
                            # If this page had fewer logs than the limit, we're done
                            if page_log_count < limit:
                                has_more_pages = False
                                if debug:
                                    self.stdout.write("Fewer logs than limit returned, no more pages to fetch")
                            
                            # Update the nonce for the next request if needed
                            if "DPoP-Nonce" in logs_response.headers:
                                api_nonce = logs_response.headers.get("DPoP-Nonce")
                                if debug:
                                    self.stdout.write(f"Got new nonce for next page: {api_nonce}")
                        else:
                            self.stdout.write(self.style.ERROR(f"Failed to access logs API on page {page_count}. Status: {logs_response.status_code}"))
                            try:
                                error_details = logs_response.json()
                                self.stdout.write(self.style.ERROR(f"Error details: {json.dumps(error_details, indent=2)}"))
                            except Exception:
                                self.stdout.write(self.style.ERROR(f"Response content: {logs_response.text[:200]}"))
                            
                            # Stop pagination if we encounter an error
                            has_more_pages = False
                    except Exception as e:
                        self.stdout.write(self.style.ERROR(f"Error accessing logs API on page {page_count}: {str(e)}"))
                        has_more_pages = False
                
                # Summarize the results
                self.stdout.write(f"\nFetched a total of {total_logs} logs across {page_count} pages")
                
                # Store logs in MongoDB if not a dry run
                if not dry_run and all_logs:
                    self.stdout.write("\n========== STORING LOGS IN MONGODB ==========")
                    inserted_count = store_logs_in_mongodb(all_logs)
                    self.stdout.write(f"Operation complete: Stored {inserted_count} of {total_logs} logs in MongoDB")
                else:
                    self.stdout.write(self.style.WARNING("Dry run mode: logs were not stored in MongoDB"))
                
                # Provide a sample of the first log
                if all_logs:
                    self.stdout.write("\nSample log entry:")
                    sample_log = all_logs[0]
                    sample_display = {
                        "uuid": sample_log.get("uuid"),
                        "eventType": sample_log.get("eventType"),
                        "severity": sample_log.get("severity"),
                        "displayMessage": sample_log.get("displayMessage"),
                        "published": sample_log.get("published"),
                        "outcome": sample_log.get("outcome"),
                    }
                    for key, value in sample_display.items():
                        self.stdout.write(f"  {key}: {value}")
            else:
                self.stdout.write(self.style.ERROR("No access token available. Cannot fetch logs."))
                
        except Exception as e:
            error_msg = f"Error fetching Okta logs: {str(e)}"
            logger.error(error_msg)
            self.stdout.write(self.style.ERROR(error_msg))
            if debug:
                import traceback
                traceback.print_exc()
    
    def _calculate_start_time(self, days, hours, minutes):
        """Calculate the start time based on provided days, hours, and minutes"""
        # Calculate total minutes
        total_minutes = days * 24 * 60 + hours * 60 + minutes
        if total_minutes <= 0:
            total_minutes = 15  # Default to 15 minutes
        
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=total_minutes)
        
        self.stdout.write(f"Calculated time range: {total_minutes} minutes ({days} days, {hours} hours, {minutes} minutes)")
        return start_time