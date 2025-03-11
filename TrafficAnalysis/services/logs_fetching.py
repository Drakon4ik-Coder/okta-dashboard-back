import time
import jwt
import requests
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import json
from django.conf import settings
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Okta Configuration - Consider using Django settings instead of hardcoding
OKTA_DOMAIN = "https://dev-72300026.okta.com"
TOKEN_ENDPOINT = f"{OKTA_DOMAIN}/oauth2/v1/token"
LOGS_ENDPOINT = f"{OKTA_DOMAIN}/api/v1/logs"
CLIENT_ID = "0oanrupix6Cq2plqX5d7"
KID = "CWtaTbmvqxOn0VvBaPgX8D1E4x5NTEHbppI_DAWZ4k0"

# Private Key (In production, use settings or environment variables)
PRIVATE_KEY = """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDCW0B9PKPGKR/W
TpgcbBilBxFSwu1skphijNc0dd10vdwxwbxK/RXN2psJM9+FElOfjum4Knrr2JGo
ZaQPhm2gYadSpv1p9Q9IFsXR4D4JgnJ0GPVI4cdGFm+ZRw9SodA6Hl5is/KyFnRQ
2+PzXpRSbpWB4vv8H9Nz1KYHcD0xuKHsKyx2XLJV+FTfMQibP9MJdgastGyMq/+y
Vz2zNJyrivUOFSiotGPzsZPU9b9wegaTqnaRsjHkZPJqBv+5h9BxupKgAJYorS2S
/hoxdnEeDkAyMdQoPUXAyZOuwG3Y9UlVTs3zpEoKDIxvgpSIiyOyYsyO2AWr7LP0
lz7x8LLHAgMBAAECggEAHJDt9xpRFgCYYdbWa6MFskfKJ4hn/iPDywRZYygJvy1i
rluD0d/F8yY00FL0AOqTKOoH9x4jSAPiUMZzqSaAeWiw/6h0qbyvnNBgDftwEtS9
/stmTeqFcAs/Jt+3ZFVNNiWdiNNbEgrT2MihBfW6Ri1jwx36HHIPEcDJEGHSVLrF
QCEcIjjNtlJnYVPn4U4fVLEh9NrXG9I0+pp3x+WGUjvQqQgrFd8cohxmEhFEfeEv
DxuIR2Rl9hAH9BCRB7dxtSSbFwVt+K/Jd3ubaudlUCiqBeIckcCCx9Wv18dnTpt6
u8DqOfSS3szCTzgxPLzA6ix8C4z3I7MGOYsOgwA5wQKBgQDsP0IgGRICg3BZQ8cC
WL4PPJqp+Y9stU5bDDAKXPmJriTkegq1sWJD/ancCHlzdNTnCqg2yjaJVvl22/Cv
qFhLvmcidBhH1vbYpQai2SiD2FkfA7So85vETs58LgJpBt4VqYgfcBacyYqBpU6I
Sl21da8DcQG+qosadD8bE2IDQQKBgQDSm1jL2p2l0BwQFAnFfJ3khWSj2/Vck4wG
WZmyLX5tUTD+cZobNXOthBGFGsjnDdhq9yPijNmjMsDwh6Dk+ASm9J3VW+C7VW0V
Ema+1gD7RtnXKgwL3KxVtEAsVwYKFSLR8Tr38uAOTNYMVPXObWeMv8SW7O+FKfWi
Qa6ouYecBwKBgQDEDqtd3/BmTZZLPkhF1kfEdVMVhJpWaRCh1rd3ojkk3XSYd/+z
UYZvTnBMvmusOWUGaH25Go+v4pIc5eIUpOzBzz3gBeCwneE1YZ7kPru0zzMG3hhr
rd+zRoNt4vD1IFHmQE9LZ8YcT9W2Se2mhbDHCuc3P+1mwjm2too4ehl5AQKBgEhO
FTpHoAAhZsEOYBxxIDQop9ip158k+NnlQSMvA0y8pzlz/xiATWqxAOLVw0uwMTDo
EGXjPYUOE7eAmPiDPfWj3dw2Yv1t4rltS+EQz911Aa0hPmmEJZZ2/+E5L1We1AmH
7FrcA5hlQMeTE6D/ZqGn5PJ7/e+V7EL8kd5Tc/9ZAoGATPgicFRBmlqccG2TOK00
OhAD+MsX5jJEUuctWValswXgs24yIR0A8dyFedVfxMq4UGhaQAuEA+/MCs8c7CtW
oA2GGPLapRAW8uYD1jCOHhYvPgugI1fAxSk0W3hk2f2o4z+4K5sj0gjuaIGZOHxv
YlGJUx8IUWeS3DUkd9ZJxH8=
-----END PRIVATE KEY-----
"""

API_TOKEN = "00wG4tmfJmSkPE3sDbOswQlSiNzEQc3I7pl8kN3tLJ"
USE_API_TOKEN = True

# Load Private Key
try:
    private_key_obj = serialization.load_pem_private_key(
        PRIVATE_KEY.encode(),
        password=None,
        backend=default_backend()
    )

    # Extract Public Key as JWK
    public_numbers = private_key_obj.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "e": base64.urlsafe_b64encode(
            public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode(
            'utf-8').rstrip('='),
        "kid": KID,
        "n": base64.urlsafe_b64encode(
            public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode(
            'utf-8').rstrip('=')
    }
except Exception as e:
    logger.error(f"Error loading private key: {e}")
    jwk = {
        "kty": "RSA",
        "e": "AQAB",
        "kid": KID,
        "n": "wltAfTyjxikf1k6YHGwYpQcRUsLtbJKYYozXNHXddL3cMcG8Sv0VzdqbCTPfhRJTn47puCp669iRqGWkD4ZtoGGnUqb9afUPSBbF0eA-CYJydBj1SOHHRhZvmUcPUqHQOh5eYrPyshZ0UNvj816UUm6VgeL7_B_Tc9SmB3A9Mbih7CssdlyyVfhU3zEImz_TCXYGrLRsjKv_slc9szScq4r1DhUoqLRj87GT1PW_cHoGk6p2kbIx5GTyagb_uYfQcbqSoACWKK0tkv4aMXZxHg5AMjHUKD1FwMmTrsBt2PVJVU7N86RKCgyMb4KUiIsjsmLMjtgFq-yz9Jc-8fCyxw"
    }


def create_dpop_proof(http_method, url, nonce=None):
    """Generate a DPoP proof JWT"""
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

    headers = {
        "alg": "RS256",
        "typ": "dpop+jwt",
        "jwk": jwk,
        "kid": KID
    }

    try:
        return jwt.encode(payload, private_key_obj, algorithm="RS256", headers=headers)
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

    try:
        client_assertion = jwt.encode(
            client_assertion_payload,
            private_key_obj,
            algorithm="RS256",
            headers={"alg": "RS256", "typ": "JWT", "kid": KID}
        )
    except Exception as e:
        logger.error(f"Error creating client assertion: {e}")
        return None

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "DPoP": temp_dpop
    }

    data = {
        "grant_type": "client_credentials",
        "scope": "okta.logs.read",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion,
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


def get_access_token():
    """Obtain an access token from Okta using DPoP"""
    dpop_nonce = get_dpop_nonce()
    if not dpop_nonce:
        logger.error("Failed to retrieve DPoP nonce - cannot proceed")
        return None

    # Create DPoP proof with nonce
    dpop_jwt = create_dpop_proof("POST", TOKEN_ENDPOINT, dpop_nonce)
    if not dpop_jwt:
        logger.error("Failed to create DPoP proof with nonce")
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

    try:
        client_assertion = jwt.encode(
            client_assertion_payload,
            private_key_obj,
            algorithm="RS256",
            headers={"alg": "RS256", "typ": "JWT", "kid": KID}
        )
    except Exception as e:
        logger.error(f"Error creating client assertion: {e}")
        return None

    data = {
        "grant_type": "client_credentials",
        "scope": "okta.logs.read",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion,
        "client_id": CLIENT_ID
    }

    headers = {
        "DPoP": dpop_jwt,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }

    try:
        response = requests.post(TOKEN_ENDPOINT, data=data, headers=headers)

        if response.status_code == 200:
            token_data = response.json()
            logger.info("Successfully obtained access token")
            return token_data.get("access_token")

        # If we get an error about needing a new nonce, we could retry once
        if response.status_code in (400, 401):
            new_nonce = extract_dpop_nonce_from_error(response)
            if new_nonce:
                logger.info("Received new nonce during token request, retrying")
                # Recursive call to retry with new nonce
                return get_access_token()

        logger.error(f"Error response: {response.status_code} - {response.text}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error getting access token: {e}")
        return None


def fetch_logs(access_token, since=None, filter_string=None, limit=1000):
    """
    Fetch logs from Okta using the obtained access token

    Parameters:
    - access_token: The DPoP access token
    - since: Optional timestamp to filter logs since a specific date
    - filter_string: Optional filter expression
    - limit: Maximum number of logs to retrieve (default 100)
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


def fetch_logs_with_api_token(since=None, filter_string=None, limit=1000):
    """
    Fetch logs from Okta using API token authentication

    Parameters:
    - since: Optional timestamp to filter logs since a specific date
    - filter_string: Optional filter expression
    - limit: Maximum number of logs to retrieve (default 100)
    """
    # Prepare query parameters
    params = {"limit": limit}
    if since:
        params["since"] = since
    if filter_string:
        params["filter"] = filter_string

    headers = {
        "Authorization": f"SSWS {API_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(LOGS_ENDPOINT, headers=headers, params=params)

        if response.status_code == 200:
            logs = response.json()
            logger.info(f"Successfully retrieved {len(logs)} logs using API token")
            return logs

        logger.error(f"Error fetching logs with API token: {response.status_code} - {response.text}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error fetching logs with API token: {e}")
        return None


def save_logs_to_database(logs):
    """
    Save logs to database (implement according to your model structure)
    """
    if not logs:
        logger.warning("No logs to save")
        return False

    try:
        # Implement saving to your MongoDB database
        # This is a placeholder - replace with your actual implementation
        logger.info(f"Would save {len(logs)} logs to database")
        return True
    except Exception as e:
        logger.error(f"Error saving logs to database: {e}")
        return False


def main():
    """Main function to fetch logs using either API token or DPoP authentication"""
    logger.info("Starting log fetching process")

    logs = None

    if USE_API_TOKEN:
        logger.info("Using API token authentication")
        logs = fetch_logs_with_api_token()
    else:
        logger.info("Using DPoP authentication")
        access_token = get_access_token()
        if not access_token:
            logger.error("Failed to obtain access token")
            return False

        logger.info("Successfully obtained access token")
        logs = fetch_logs(access_token)

    if not logs:
        logger.error("Failed to fetch logs")
        return False

    logger.info(f"Successfully fetched {len(logs)} logs")

    # Process and display logs
    print(f"\nSystem Logs ({len(logs)} entries):")
    for log in logs:
        event_type = log.get('eventType', 'Unknown')
        published = log.get('published', 'Unknown time')
        actor = log.get('actor', {}).get('displayName', 'Unknown user')
        print(f"Event: {event_type}, Time: {published}, Actor: {actor}")

    return True


if __name__ == "__main__":
    success = main()
    if success:
        print("Log fetching completed successfully")
    else:
        print("Log fetching failed")