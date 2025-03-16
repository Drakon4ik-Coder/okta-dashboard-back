import time
import jwt
import requests
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
from pathlib import Path
import logging
import environ
import os

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Load environment variables
env = environ.Env()
environ.Env.read_env(os.path.join(BASE_DIR, ".env"))

# Configure logging
logger = logging.getLogger(__name__)

# Okta Configuration - Consider using Django settings instead of hardcoding
OKTA_DOMAIN = env("OKTA_DOMAIN")
TOKEN_ENDPOINT = f"{OKTA_DOMAIN}/oauth2/v1/token"
LOGS_ENDPOINT = f"{OKTA_DOMAIN}/api/v1/logs"
CLIENT_ID = env("OKTA_CLIENT_ID")

# No hard-coded API token
USE_API_TOKEN = False

# Key file paths - you need to generate these keys
PRIVATE_KEY_PATH = os.path.join(BASE_DIR, "keys", "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(BASE_DIR, "keys", "public_key.pem")

def load_keys():
    """Load the private and public keys needed for JWT signing"""
    try:
        # Ensure the keys directory exists
        os.makedirs(os.path.dirname(PRIVATE_KEY_PATH), exist_ok=True)
        
        # Check if keys exist, generate them if they don't
        if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
            from cryptography.hazmat.primitives.asymmetric import rsa
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Save private key
            with open(PRIVATE_KEY_PATH, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Save public key
            public_key = private_key.public_key()
            with open(PUBLIC_KEY_PATH, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            
            logger.info("Generated new key pair for JWT signing")
        
        # Load the private key
        with open(PRIVATE_KEY_PATH, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        
        # Load the public key and create JWK
        with open(PUBLIC_KEY_PATH, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        
        # Create JWK from public key
        public_numbers = public_key.public_numbers()
        
        # Convert to base64url format
        def int_to_base64url(value):
            value_hex = format(value, 'x')
            if len(value_hex) % 2 == 1:
                value_hex = '0' + value_hex
            value_bytes = bytes.fromhex(value_hex)
            return base64.urlsafe_b64encode(value_bytes).decode('utf-8').rstrip('=')
        
        jwk = {
            "kty": "RSA",
            "e": int_to_base64url(public_numbers.e),
            "n": int_to_base64url(public_numbers.n),
            "alg": "RS256"
        }
        
        return private_key, jwk
    
    except Exception as e:
        logger.error(f"Error loading keys: {e}")
        return None, None

def create_dpop_proof(http_method, url, nonce=None):
    """Generate a DPoP proof JWT"""
    private_key, jwk = load_keys()
    if not private_key or not jwk:
        logger.error("Failed to load keys for DPoP proof")
        return None
    
    current_time = int(time.time())
    payload = {
        "iat": current_time,
        "exp": current_time + 300,
        "jti": str(uuid.uuid4()),
        "htm": http_method,
        "htu": url
    }
    if nonce:
        payload["nonce"] = nonce
        
    try:
        # Create the JWT using the private key
        dpop_token = jwt.encode(
            payload,
            private_key,
            algorithm="RS256",
            headers={"typ": "dpop+jwt", "alg": "RS256", "jwk": jwk}
        )
        
        return dpop_token
    except Exception as e:
        logger.error(f"Error creating DPoP proof: {e}")
        return None

def extract_dpop_nonce_from_error(response):
    """Extract DPoP nonce from response headers or error message"""
    # First check headers
    if "DPoP-Nonce" in response.headers:
        return response.headers["DPoP-Nonce"]

    # Check WWW-Authenticate header
    if "WWW-Authenticate" in response.headers:
        auth_header = response.headers["WWW-Authenticate"]
        import re
        nonce_match = re.search(r'DPoP nonce="([^"]+)"', auth_header)
        if nonce_match:
            return nonce_match.group(1)

    # Try to parse from error description
    try:
        error_data = response.json()
        error_desc = error_data.get("error_description", "")
        import re
        match = re.search(r'nonce=([^&"\s]+)', error_desc)
        if match:
            return match.group(1)
    except:
        pass

    return None

def authenticate_with_credentials(email, password):
    """Authenticate with Okta using email and password"""
    # First, get a DPoP nonce
    dpop_nonce = get_dpop_nonce()
    if not dpop_nonce:
        logger.error("Failed to retrieve DPoP nonce - cannot proceed")
        return None
    
    # Create DPoP proof with nonce
    dpop_jwt = create_dpop_proof("POST", TOKEN_ENDPOINT, dpop_nonce)
    if not dpop_jwt:
        logger.error("Failed to create DPoP proof with nonce")
        return None
    
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "DPoP": dpop_jwt
    }
    
    data = {
        "grant_type": "password",
        "username": email,
        "password": password,
        "scope": "okta.logs.read",
        "client_id": CLIENT_ID
    }
    
    try:
        response = requests.post(TOKEN_ENDPOINT, headers=headers, data=data)
        
        if response.status_code == 200:
            token_data = response.json()
            logger.info("Successfully authenticated with email/password")
            return token_data.get("access_token")
            
        # If we need a new nonce, try again
        if response.status_code in (400, 401):
            new_nonce = extract_dpop_nonce_from_error(response)
            if new_nonce:
                logger.info("Received new nonce during authentication, retrying")
                new_dpop_jwt = create_dpop_proof("POST", TOKEN_ENDPOINT, new_nonce)
                if new_dpop_jwt:
                    headers["DPoP"] = new_dpop_jwt
                    response = requests.post(TOKEN_ENDPOINT, headers=headers, data=data)
                    if response.status_code == 200:
                        token_data = response.json()
                        logger.info("Successfully authenticated with email/password after nonce refresh")
                        return token_data.get("access_token")
        
        logger.error(f"Authentication failed: {response.status_code} - {response.text}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error during authentication: {e}")
        return None

def get_dpop_nonce():
    """Retrieve the DPoP nonce from Okta"""
    # Create initial DPoP proof without nonce
    temp_dpop = create_dpop_proof("POST", TOKEN_ENDPOINT)
    if not temp_dpop:
        logger.error("Failed to create initial DPoP proof")
        return None

    # Create client assertion
    current_time = int(time.time())
    client_assertion_payload = {
        "iat": current_time,
        "exp": current_time + 300,
        "iss": CLIENT_ID,
        "sub": CLIENT_ID,
        "aud": TOKEN_ENDPOINT
    }

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "DPoP": temp_dpop
    }

    data = {
        "grant_type": "client_credentials",
        "scope": "okta.logs.read",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_id": CLIENT_ID
    }

    try:
        response = requests.post(TOKEN_ENDPOINT, headers=headers, data=data)

        # We expect a 401 or 400 with DPoP nonce requirement
        nonce = extract_dpop_nonce_from_error(response)

        if nonce:
            logger.info(f"Successfully obtained DPoP nonce")
            return nonce

        logger.error(f"Failed to get nonce. Response: {response.status_code} - {response.text}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error getting DPoP nonce: {e}")
        return None

def fetch_logs(access_token, since=None, filter_string=None, limit=1000):
    """
    Fetch logs from Okta using the obtained access token

    Parameters:
    - access_token: The DPoP access token
    - since: Optional timestamp to filter logs since a specific date
    - filter_string: Optional filter expression
    - limit: Maximum number of logs to retrieve (default 1000)
    """
    if not access_token:
        logger.error("No valid access token provided")
        return None

    # Get a fresh nonce for the logs request
    dpop_nonce = get_dpop_nonce()
    if not dpop_nonce:
        logger.error("Failed to get nonce for logs request")
        return None

    # Create DPoP proof with nonce for the logs request
    dpop_jwt = create_dpop_proof("GET", LOGS_ENDPOINT, dpop_nonce)
    if not dpop_jwt:
        logger.error("Failed to create DPoP proof for logs request")
        return None

    # Prepare query parameters
    params = {"limit": limit}
    if since:
        params["since"] = since
    if filter_string:
        params["filter"] = filter_string

    headers = {
        "Authorization": f"DPoP {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "DPoP": dpop_jwt
    }

    try:
        response = requests.get(LOGS_ENDPOINT, headers=headers, params=params)

        if response.status_code == 200:
            logs = response.json()
            logger.info(f"Successfully retrieved {len(logs)} logs")
            return logs

        # Check if we need a new nonce
        if response.status_code in (400, 401):
            new_nonce = extract_dpop_nonce_from_error(response)
            if new_nonce:
                logger.info("Received new nonce during logs request, retrying")
                # Create new DPoP proof with the new nonce
                new_dpop_jwt = create_dpop_proof("GET", LOGS_ENDPOINT, new_nonce)
                if new_dpop_jwt:
                    headers["DPoP"] = new_dpop_jwt
                    response = requests.get(LOGS_ENDPOINT, headers=headers, params=params)
                    if response.status_code == 200:
                        logs = response.json()
                        logger.info(f"Successfully retrieved {len(logs)} logs after nonce refresh")
                        return logs

        logger.error(f"Error fetching logs: {response.status_code} - {response.text}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error fetching logs: {e}")
        return None

def save_logs_to_database(logs):
    """Save logs to MongoDB database"""
    if not logs:
        logger.warning("No logs to save")
        return False

    try:
        # Import here to avoid circular imports
        from TrafficAnalysis.models import OktaLog
        import datetime
        
        saved_count = 0
        skipped_count = 0
        
        for log in logs:
            # Extract required fields
            event_id = log.get('uuid', '')
            
            # Skip if this log already exists
            if OktaLog.objects(event_id=event_id).first():
                skipped_count += 1
                continue
                
            # Parse the published datetime
            published_str = log.get('published', '')
            try:
                published = datetime.datetime.fromisoformat(published_str.replace('Z', '+00:00'))
            except:
                published = datetime.datetime.now()
                
            # Extract actor information
            actor = log.get('actor', {})
            
            # Create the log document
            okta_log = OktaLog(
                event_id=event_id,
                event_type=log.get('eventType', ''),
                published=published,
                actor_id=actor.get('id', ''),
                actor_type=actor.get('type', ''),
                actor_display_name=actor.get('displayName', ''),
                actor_alternate_id=actor.get('alternateId', ''),
                client_ip=log.get('client', {}).get('ipAddress', ''),
                outcome_result=log.get('outcome', {}).get('result', ''),
                outcome_reason=log.get('outcome', {}).get('reason', ''),
                target=log.get('target', []),
                raw_data=log
            )
            
            okta_log.save()
            saved_count += 1
            
        logger.info(f"Saved {saved_count} new logs to database, skipped {skipped_count} existing logs")
        return True
    except Exception as e:
        logger.error(f"Error saving logs to database: {e}")
        return False

def main(email=None, password=None):
    """Main function to fetch logs using credentials authentication"""
    logger.info("Starting log fetching process")

    logs = None
    
    if not email or not password:
        logger.error("Email and password are required")
        return False
        
    logger.info("Using email/password authentication")
    access_token = authenticate_with_credentials(email, password)
    
    if not access_token:
        logger.error("Failed to obtain access token with credentials")
        return False

    logger.info("Successfully obtained access token")
    logs = fetch_logs(access_token)

    if not logs:
        logger.error("Failed to fetch logs")
        return False

    logger.info(f"Successfully fetched {len(logs)} logs")
    
    # Save logs to database
    save_result = save_logs_to_database(logs)
    if save_result:
        logger.info("Successfully saved logs to database")
    else:
        logger.warning("Failed to save logs to database")

    # Process and display logs
    print(f"\nSystem Logs ({len(logs)} entries):")
    for log in logs:
        event_type = log.get('eventType', 'Unknown')
        published = log.get('published', 'Unknown time')
        actor = log.get('actor', {}).get('displayName', 'Unknown user')
        print(f"Event: {event_type}, Time: {published}, Actor: {actor}")

    return True

if __name__ == "__main__":
    # Prompt for credentials
    print("Okta Log Fetcher - Credential Authentication")
    
    # Email input
    email = "40628952@live.napier.ac.uk"
    
    # Password input - simplified approach
    import sys
    print("Enter your Okta password: ", end="", flush=True)
    password = "40628952@live.napier.ac.uk"

    print("Attempting authentication...")
    
    # Add timeout to requests to prevent hanging
    import requests.adapters

    # Configure requests with timeouts and retries

    adapter = requests.adapters.HTTPAdapter(max_retries=3)
    http = requests.Session()
    http.mount("https://", adapter)
    
    # Override the requests session to use timeouts
    old_post = requests.post
    old_get = requests.get
    
    def post_with_timeout(*args, **kwargs):
        if 'timeout' not in kwargs:
            kwargs['timeout'] = 30  # 30 seconds timeout
        return old_post(*args, **kwargs)
    
    def get_with_timeout(*args, **kwargs):
        if 'timeout' not in kwargs:
            kwargs['timeout'] = 30  # 30 seconds timeout
        return old_get(*args, **kwargs)
    
    requests.post = post_with_timeout
    requests.get = get_with_timeout
    
    try:
        logger.info("Starting main function")
        success = main(email=email, password=password)
        if success:
            print("Log fetching completed successfully")
        else:
            print("Log fetching failed")
    except Exception as e:
        logger.error(f"Error during log fetching: {e}")
        print(f"Error during log fetching: {e}")
    finally:
        # Restore original request functions
        requests.post = old_post
        requests.get = old_get
        logger.info("Restored original request functions")