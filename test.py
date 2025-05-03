# Test script for connecting to Okta API using OAuth with DPoP and private_key_jwt
import requests
import base64
import time
import uuid
import jwt
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
import sys
import re
import hashlib
from datetime import datetime

from dotenv import load_dotenv
load_dotenv()   # <-- this reads and exports your .env keys into os.environ

# Try to get credentials from environment variables first
org_url = os.environ.get('OKTA_ORG_URL')
client_id = os.environ.get('OKTA_CLIENT_ID')
client_secret = os.environ.get('OKTA_CLIENT_SECRET')
token_endpoint = os.environ.get('OKTA_TOKEN_ENDPOINT')
print("Okta API OAuth with DPoP and private_key_jwt")
print("=========================================================")
print("Using environment variables for configuration:")
print(f"OKTA_ORG_URL: {org_url}")
print(f"OKTA_CLIENT_ID: {'*' * len(client_id) if client_id else 'Not set'}")
print(f"OKTA_CLIENT_SECRET: {'*' * 8 if client_secret else 'Not set'}")
print(f"OKTA_TOKEN_ENDPOINT: {token_endpoint or f'{org_url}/oauth2/v1/token'}")
print("=========================================================")

# If not set in environment, try Django settings
if not (org_url and client_id and token_endpoint):
    try:
        # Add the Django project root to the path so we can import settings
        sys.path.append('/home/drakon4ik/projects/Okta/okta-dashboard-back')
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'OktaDashboardBackend.settings')
        
        import django
        django.setup()
        from django.conf import settings
        
        # Get Okta settings from Django
        org_url = org_url or settings.OKTA_ORG_URL
        client_id = client_id or settings.OKTA_CLIENT_ID
        client_secret = client_secret or settings.OKTA_CLIENT_SECRET
        token_endpoint = token_endpoint or settings.OKTA_TOKEN_ENDPOINT
        
        print(f"Using Okta org URL from settings: {org_url}")
        print(f"Client ID from settings: {'*' * len(client_id) if client_id else 'Not set'}")
        print(f"Client Secret from settings: {'*' * 8 if client_secret else 'Not set'}")
        print(f"Token endpoint: {token_endpoint}")
        
    except Exception as e:
        print(f"Error loading Django settings: {e}")
        
        # Only prompt if required values are still not set
        if not org_url:
            org_url = input("Enter your Okta org URL (e.g., https://dev-12345.okta.com): ")
        if not client_id:
            client_id = input("Enter your Okta client ID: ")
        if not token_endpoint and org_url:
            token_endpoint = f"{org_url}/oauth2/v1/token"
else:
    print(f"Using Okta org URL from environment: {org_url}")
    print(f"Client ID from environment: {'*' * len(client_id) if client_id else 'Not set'}")
    print(f"Token endpoint: {token_endpoint or f'{org_url}/oauth2/v1/token'}")
    
# Set token endpoint if still not set
if not token_endpoint and org_url:
    token_endpoint = f"{org_url}/oauth2/v1/token"
    
# Validate required parameters
if not org_url or not client_id or not token_endpoint:
    print("ERROR: Missing required Okta configuration.")
    print("Please set OKTA_ORG_URL and OKTA_CLIENT_ID environment variables or configure Django settings.")
    sys.exit(1)

print("\nLoading registered private key from keys/private_key.pem...")
try:
    # Use the same private key that was registered with Okta
    private_key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'keys', 'private_key.pem')
    with open(private_key_path, 'rb') as key_file:
        private_key_data = key_file.read()
    
    private_key = serialization.load_pem_private_key(
        private_key_data,
        password=None
    )
    print("✅ Successfully loaded the registered private key!")
    
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
    
    # Also generate a new key for DPoP (separate from client authentication)
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
    print(f"❌ Error loading the registered private key: {e}")
    print("Generating a new key pair instead - IMPORTANT: This won't work with Okta unless registered")
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

print("RSA key pair setup completed")

# Function to create DPoP proof
def create_dpop_proof(http_method, url, nonce=None):
    # Create the private key in PEM format for JWT signing
    private_key_pem = dpop_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Parse the URL to extract components
    from urllib.parse import urlparse
    
    parsed_url = urlparse(url)
    
    # Debug info
    print(f"Original URL for DPoP: {url}")
    print(f"Parsed URL - scheme: {parsed_url.scheme}, netloc: {parsed_url.netloc}, path: {parsed_url.path}, query: {parsed_url.query}")
    
    # For Okta System Log API, use exactly '/api/v1/logs' as specified in documentation
    if '/api/v1/logs' in url:
        normalized_url = "/api/v1/logs"
        print(f"Using documented API path for logs API: {normalized_url}")
    elif 'oauth2/v1/token' in url:
        # For token endpoint, use full URL (this works)
        normalized_url = url
        print(f"Using full URL for token endpoint: {normalized_url}")
    else:
        # For other cases, use the full URL
        normalized_url = url
        print(f"Using full URL for endpoint: {normalized_url}")
    
    # Create DPoP proof JWT
    now = int(time.time())
    proof = {
        "jti": str(uuid.uuid4()),
        "htm": http_method,
        "htu": normalized_url,
        "iat": now,
        "exp": now + 60,  # Valid for 1 minute
    }
    
    # Add nonce if provided - THIS IS CRITICAL
    if nonce:
        proof["nonce"] = nonce
        print(f"Including nonce in DPoP proof: {nonce}")
    
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
    try:
        decoded = jwt.decode(dpop_proof, options={"verify_signature": False})
        print(f"DPoP proof payload: {json.dumps(decoded)}")
    except Exception as e:
        print(f"Error decoding JWT: {e}")
        
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
    
    # Sign the JWT
    client_assertion = jwt.encode(
        payload=payload,
        key=private_key_pem,
        algorithm="RS256"
    )
    
    print("Created private_key_jwt client assertion for authentication")
    return client_assertion

# First try to get a nonce via a minimal POST request
print("\nRequesting DPoP nonce via minimal POST request...")
token_url = token_endpoint or f"{org_url}/oauth2/v1/token"
initial_proof = create_dpop_proof("POST", token_url)

# Create client assertion for private_key_jwt
client_assertion = create_client_assertion(token_url)

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
        token_url,
        headers=minimal_headers,
        data=minimal_data,
        timeout=10
    )
    
    print(f"Minimal POST status: {minimal_response.status_code}")
    print(f"Response headers: {dict(minimal_response.headers)}")
    
    # Check for DPoP-Nonce header
    if "DPoP-Nonce" in minimal_response.headers:
        dpop_nonce = minimal_response.headers.get("DPoP-Nonce")
        print(f"✓ Got DPoP nonce from response: {dpop_nonce}")
    else:
        # Try to extract from error response
        try:
            error_data = minimal_response.json()
            print(f"Error response: {error_data}")
            
            # Check error description for nonce info
            error_desc = error_data.get("error_description", "")
            if "nonce" in error_desc.lower():
                print("Error indicates nonce issue")
                
                # Check WWW-Authenticate header
                www_auth = minimal_response.headers.get("WWW-Authenticate", "")
                if "nonce=" in www_auth:
                    nonce_match = re.search(r'nonce="([^"]+)"', www_auth)
                    if nonce_match:
                        dpop_nonce = nonce_match.group(1)
                        print(f"✓ Extracted nonce from WWW-Authenticate: {dpop_nonce}")
        except Exception as parse_error:
            print(f"Error parsing response: {parse_error}")
            print(f"Raw response: {minimal_response.text[:200]}")
            
except Exception as e:
    print(f"Error in minimal POST: {e}")

# Now try the token request with nonce (if we have one)
print("\nAttempting OAuth token request with private_key_jwt and DPoP...")

try:
    # Create client assertion using private_key_jwt
    client_assertion = create_client_assertion(token_url)

    # Create DPoP proof WITH the nonce
    dpop_proof = create_dpop_proof("POST", token_url, dpop_nonce)

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
        token_url,
        headers=headers,
        data=data,
        timeout=15
    )

    print(f"Token request status code: {token_response.status_code}")
    print(f"Token response headers: {dict(token_response.headers)}")

    # Check if we need to retry with a new nonce
    if token_response.status_code in [400, 401] and "DPoP-Nonce" in token_response.headers:
        print("Got a new nonce in the error response, retrying...")
        new_nonce = token_response.headers.get("DPoP-Nonce")
        print(f"New nonce: {new_nonce}")
        
        # Create a new proof with the new nonce
        new_proof = create_dpop_proof("POST", token_url, new_nonce)
        headers["DPoP"] = new_proof
        
        # Create a new client assertion
        client_assertion = create_client_assertion(token_url)
        data["client_assertion"] = client_assertion
        
        # Try again
        print("Retrying with new nonce...")
        retry_response = requests.post(
            token_url,
            headers=headers,
            data=data,
            timeout=15
        )
        
        print(f"Retry status code: {retry_response.status_code}")
        
        if retry_response.status_code == 200:
            print("✓ Successfully obtained token after retry!")
            token_json = retry_response.json()
            access_token = token_json.get("access_token")
            expires_in = token_json.get("expires_in")
            token_type = token_json.get("token_type", "DPoP")
            
            print(f"Token type: {token_type}")
            print(f"Expires in: {expires_in} seconds")
            print(f"Access token: {access_token[:10]}...{access_token[-10:] if access_token else ''}")
            
            # Check what scopes we got in the token
            scope = token_json.get("scope", "")
            print(f"Granted scopes: {scope}")
            
            # Decode the JWT access token to see what's inside
            try:
                # JWT typically has three parts separated by dots
                token_parts = access_token.split('.')
                if len(token_parts) == 3:
                    # Decode the payload (second part)
                    padded = token_parts[1] + '=' * (4 - len(token_parts[1]) % 4)
                    decoded_payload = base64.b64decode(padded).decode('utf-8')
                    token_payload = json.loads(decoded_payload)
                    print("\nAccess token payload:")
                    print(f"- Token issued for client: {token_payload.get('cid', 'unknown')}")
                    print(f"- Token scopes: {token_payload.get('scp', [])}") 
                    print(f"- Token expires at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(token_payload.get('exp', 0)))}")
            except Exception as e:
                print(f"Error decoding access token: {e}")
        else:
            print(f"Token request failed after retry: {retry_response.text[:200]}")
            try:
                error_data = retry_response.json()
                print(f"Error details: {json.dumps(error_data, indent=2)}")
            except Exception:
                pass
            
            # Set access_token to None to indicate failure
            access_token = None
    else:
        # Handle the original token response if we didn't need to retry
        if token_response.status_code == 200:
            print("✓ Successfully obtained token on first attempt!")
            token_json = token_response.json()
            access_token = token_json.get("access_token")
            expires_in = token_json.get("expires_in")
            token_type = token_json.get("token_type", "DPoP")
            
            print(f"Token type: {token_type}")
            print(f"Expires in: {expires_in} seconds")
            print(f"Access token: {access_token[:10]}...{access_token[-10:] if access_token else ''}")
            
            # Check what scopes we got in the token
            scope = token_json.get("scope", "")
            print(f"Granted scopes: {scope}")
            
            # Decode the JWT access token to see what's inside
            try:
                # JWT typically has three parts separated by dots
                token_parts = access_token.split('.')
                if len(token_parts) == 3:
                    # Decode the payload (second part)
                    padded = token_parts[1] + '=' * (4 - len(token_parts[1]) % 4)
                    decoded_payload = base64.b64decode(padded).decode('utf-8')
                    token_payload = json.loads(decoded_payload)
                    print("\nAccess token payload:")
                    print(f"- Token issued for client: {token_payload.get('cid', 'unknown')}")
                    print(f"- Token scopes: {token_payload.get('scp', [])}") 
                    print(f"- Token expires at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(token_payload.get('exp', 0)))}")
            except Exception as e:
                print(f"Error decoding access token: {e}")
        else:
            print(f"Token request failed: {token_response.text[:200]}")
            try:
                error_data = token_response.json()
                print(f"Error details: {json.dumps(error_data, indent=2)}")
            except Exception:
                pass
            
            # Set access_token to None to indicate failure
            access_token = None
    
    # Test API access if we got a token successfully
    if access_token:
        api_nonce = token_response.headers.get("dpop-nonce") or dpop_nonce
        
        # Create DPoP proof for API requests
        print("\nTesting API access with the obtained token...")
        
        # Create the private key in PEM format for JWT signing
        private_key_pem = dpop_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Create hash of the access token for the 'ath' claim (token binding)
        now = int(time.time())
        access_token_hash = hashlib.sha256(access_token.encode()).digest()
        ath = base64.urlsafe_b64encode(access_token_hash).decode('utf-8').rstrip('=')
        print(f"Generated access token hash (ath) for token binding: {ath[:10]}...")
        
        # Create header with JWK for all proofs
        header = {
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": dpop_jwk
        }
        
        # ========== TEST USERS API ==========
        print("\n========== TESTING USERS API ==========")
        users_url = f"{org_url}/api/v1/users?limit=1"
        print(f"Users API URL: {users_url}")
        
        # Create DPoP proof for users API
        users_proof_payload = {
            "jti": str(uuid.uuid4()),
            "htm": "GET",
            "htu": f"{org_url}/api/v1/users",
            "iat": now,
            "exp": now + 60,
            "ath": ath  # Token binding
        }
        
        # Add nonce if available
        if api_nonce:
            users_proof_payload["nonce"] = api_nonce
            print(f"Including nonce in Users API DPoP proof: {api_nonce}")
        
        # Sign the JWT
        users_proof = jwt.encode(
            payload=users_proof_payload,
            key=private_key_pem,
            algorithm="RS256",
            headers=header
        )
        
        # Set up headers for users request
        users_headers = {
            "Authorization": f"DPoP {access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "DPoP": users_proof
        }
        
        # Make the request
        try:
            users_response = requests.get(users_url, headers=users_headers, timeout=15)
            print(f"Users API status: {users_response.status_code}")
            
            if users_response.status_code == 200:
                print("✓ Successfully accessed users API!")
                users_data = users_response.json()
                print(f"Users data sample: {json.dumps(users_data[:1], indent=2) if isinstance(users_data, list) else 'Not a list'}")
            else:
                print(f"Failed to access users API. Status: {users_response.status_code}")
                try:
                    error_details = users_response.json()
                    print(f"Error details: {json.dumps(error_details, indent=2)}")
                except Exception:
                    print(f"Response content: {users_response.text[:200]}")
        except Exception as e:
            print(f"Error accessing users API: {str(e)}")
        
        # ========== TEST LOGS API (Regular Endpoint) ==========
        print("\n========== TESTING LOGS API (Regular Endpoint) ==========")
        logs_url = f"{org_url}/api/v1/logs?limit=1"
        print(f"Logs API URL: {logs_url}")
        
        # Create DPoP proof for logs API
        logs_proof_payload = {
            "jti": str(uuid.uuid4()),
            "htm": "GET",
            "htu": f"{org_url}/api/v1/logs",
            "iat": now,
            "exp": now + 60,
            "ath": ath  # Token binding
        }
        
        # Add nonce if available
        if api_nonce:
            logs_proof_payload["nonce"] = api_nonce
            print(f"Including nonce in Logs API DPoP proof: {api_nonce}")
        
        # Sign the JWT
        logs_proof = jwt.encode(
            payload=logs_proof_payload,
            key=private_key_pem,
            algorithm="RS256",
            headers=header
        )
        
        # Set up headers for logs request
        logs_headers = {
            "Authorization": f"DPoP {access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "DPoP": logs_proof
        }
        
        # Make the request
        try:
            logs_response = requests.get(logs_url, headers=logs_headers, timeout=15)
            print(f"Logs API status: {logs_response.status_code}")
            
            if logs_response.status_code == 200:
                print("✓ Successfully accessed logs API!")
                logs_data = logs_response.json()
                print(f"Logs data sample: {json.dumps(logs_data[:1], indent=2) if isinstance(logs_data, list) else 'Not a list'}")
            else:
                print(f"Failed to access regular logs API. Status: {logs_response.status_code}")
                try:
                    error_details = logs_response.json()
                    print(f"Error details: {json.dumps(error_details, indent=2)}")
                except Exception:
                    print(f"Response content: {logs_response.text[:200]}")
        except Exception as e:
            print(f"Error accessing logs API: {str(e)}")
        
        # Store logs in MongoDB (if not already done)
        print("\n========== TESTING MONGODB STORAGE ==========")
        
        # Import the improved DatabaseService with reset capability
        try:
            from OktaDashboardBackend.services.database import DatabaseService
            
            # Reset MongoDB connections properly using our new method
            print("Resetting MongoDB connections...")
            DatabaseService.reset()
            
            # Initialize MongoDB service with fresh connection
            db_service = DatabaseService()
            
            if db_service.is_connected():
                print("✓ Successfully connected to MongoDB")
                
                # Get collection for logs
                logs_collection = db_service.get_collection('okta_dashboard', 'okta_logs')
                
                # Create indexes if they don't exist
                try:
                    logs_collection.create_index("uuid", unique=True)
                    logs_collection.create_index("published")
                    logs_collection.create_index("eventType")
                    logs_collection.create_index([("actor.id", 1), ("published", -1)])
                    logs_collection.create_index([("target.id", 1), ("published", -1)])
                    print("✓ Successfully created MongoDB indexes for logs collection")
                except Exception as e:
                    print(f"Note about indexes: {str(e)}")
                
                # Process the logs for storage
                if 'logs_data' in locals() and logs_data:
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
                                print(f"Error parsing published date: {date_error}")
                    
                    try:
                        # Use bulk insert with unordered option to continue on duplicate key errors
                        result = logs_collection.insert_many(logs_data, ordered=False)
                        print(f"✓ Successfully stored {len(result.inserted_ids)} logs in MongoDB")
                    except Exception as e:
                        if "E11000 duplicate key error" in str(e):
                            print("Some logs were already in MongoDB (duplicate keys)")
                        else:
                            print(f"Error during MongoDB insertion: {str(e)}")
                else:
                    print("No logs data available to store in MongoDB")
            else:
                print("❌ Failed to connect to MongoDB")
        except Exception as e:
            print(f"Error with MongoDB integration: {str(e)}")

except Exception as e:
    print(f"Error during token request or API access: {e}")
    import traceback
    traceback.print_exc()
    
print("\nTest completed. Check the results above to see what succeeded and what failed.")
