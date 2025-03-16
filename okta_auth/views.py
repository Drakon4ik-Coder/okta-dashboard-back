import requests
import hashlib
import uuid
import time
import re
import jwt
import base64
import logging
from urllib.parse import urlencode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from django.shortcuts import redirect, render
from django.conf import settings
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_protect
from django.contrib import messages
from django.http import JsonResponse

# Configure logger for authentication operations
logger = logging.getLogger(__name__)

# Generate RSA key pair for DPoP proof (only generated once when module is loaded)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

def base64url_encode(data):
    """
    Base64url encode the given data
    
    Args:
        data: Data to encode (int, str, or bytes)
        
    Returns:
        str: Base64url encoded string
    """
    if isinstance(data, int):
        # Convert int to bytes first if needed
        data = data.to_bytes((data.bit_length() + 7) // 8, byteorder='big')
    elif not isinstance(data, bytes):
        # Convert str to bytes if needed
        data = str(data).encode('utf-8')
    
    encoded = base64.urlsafe_b64encode(data).rstrip(b'=')
    return encoded.decode('ascii')

def generate_dpop_proof(http_method, url, nonce=None):
    """
    Generate a DPoP proof JWT for authenticating requests
    
    Args:
        http_method (str): HTTP method (GET, POST, etc.)
        url (str): Target URL for the request
        nonce (str, optional): Server-provided nonce for preventing replay attacks
        
    Returns:
        str: DPoP proof JWT or None if generation fails
    """
    try:
        # Use the module-level private key for consistency
        global private_key
        
        # Get the public key in JWK format
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        
        # Create JWK from public key components
        e_bytes = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')
        n_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')
        
        jwk = {
            "kty": "RSA",
            "e": base64url_encode(e_bytes),
            "n": base64url_encode(n_bytes),
            "alg": "RS256"
        }
        
        # Create the DPoP header and payload
        headers = {
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": jwk
        }
        
        payload = {
            "jti": str(uuid.uuid4()),  # Unique identifier for this JWT
            "htm": http_method,        # HTTP method for the request
            "htu": url,                # Target URL
            "iat": int(time.time())    # Issued at timestamp
        }
        
        # Add nonce if provided
        if nonce:
            payload["nonce"] = nonce
        
        # Generate the JWT
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        dpop_proof = jwt.encode(
            payload=payload,
            key=private_key_pem,
            algorithm="RS256",
            headers=headers
        )
        
        logger.debug(f"Generated DPoP proof for {http_method} {url}")
        return dpop_proof
    except Exception as e:
        logger.exception(f"Error generating DPoP proof: {e}")
        return None

def extract_dpop_nonce_from_error(response):
    """
    Extract DPoP nonce from response headers or error message
    
    Args:
        response: HTTP response object
        
    Returns:
        str: Extracted nonce or None if not found
    """
    try:
        # First check headers
        if "DPoP-Nonce" in response.headers:
            return response.headers["DPoP-Nonce"]
    
        # Check WWW-Authenticate header
        if "WWW-Authenticate" in response.headers:
            auth_header = response.headers["WWW-Authenticate"]
            nonce_match = re.search(r'DPoP nonce="([^"]+)"', auth_header)
            if nonce_match:
                return nonce_match.group(1)
    
        # Try to parse from error description
        try:
            error_data = response.json()
            error_desc = error_data.get("error_description", "")
            match = re.search(r'nonce=([^&"\s]+)', error_desc)
            if match:
                return match.group(1)
        except:
            pass
    except Exception as e:
        logger.exception(f"Error extracting nonce: {e}")
    
    return None

def get_dpop_nonce(url):
    """
    Get a DPoP nonce from the authorization server
    
    Args:
        url (str): URL to send the request to
        
    Returns:
        str: DPoP nonce, "not_required" if DPoP is not needed, or None on failure
    """
    try:
        # Generate a temporary DPoP proof without nonce
        temp_dpop = generate_dpop_proof("POST", url)
        if not temp_dpop:
            logger.error("Failed to create temporary DPoP proof")
            return None
        
        # Make an initial request to get the nonce
        response = requests.post(
            url,
            data={
                'client_id': settings.OKTA_CLIENT_ID,
                'client_secret': settings.OKTA_CLIENT_SECRET,
                'grant_type': 'client_credentials',
                'scope': 'openid'
            },
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'DPoP': temp_dpop
            },
            timeout=10
        )
        
        # If the response is a success, we don't need DPoP
        if response.status_code == 200:
            logger.info("DPoP not required - server accepted standard OAuth")
            return "not_required"
            
        # Extract nonce from response
        nonce = extract_dpop_nonce_from_error(response)
        if nonce:
            logger.info("Successfully obtained DPoP nonce")
            return nonce
        
        logger.warning(f"Failed to extract DPoP nonce. Status: {response.status_code}")
        logger.debug(f"Response headers: {dict(response.headers)}")
        logger.debug(f"Response body: {response.text[:500]}")
    except Exception as e:
        logger.exception(f"Error getting DPoP nonce: {e}")
    
    return None

def get_user_info(access_token, request=None):
    """
    Helper function to get user info from Okta
    
    Args:
        access_token (str): OAuth access token
        request (HttpRequest, optional): Request object for session access
        
    Returns:
        dict: User info or None on failure
    """
    try:
        # First try standard Bearer token method
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
        }
        
        response = requests.get(
            settings.OKTA_USER_INFO_ENDPOINT,
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            logger.info("Successfully retrieved user info with standard Bearer token")
            return response.json()

        # Extract DPoP requirement and nonce from error
        auth_header = response.headers.get('www-authenticate', '')
        if 'DPoP proof' in auth_header or 'dpop' in auth_header.lower():
            logger.info("DPoP required for userinfo endpoint")
            
            # Extract nonce directly from www-authenticate header if available
            nonce_match = re.search(r'DPoP nonce="([^"]+)"', auth_header)
            nonce = nonce_match.group(1) if nonce_match else None
            
            if not nonce:
                # If no nonce was provided, we'll try without it
                logger.info("No nonce in www-authenticate header, trying without nonce")
            else:
                logger.info(f"Found nonce in www-authenticate header: {nonce}")
            
            # Generate DPoP proof with or without nonce
            dpop_proof = generate_dpop_proof("GET", settings.OKTA_USER_INFO_ENDPOINT, nonce)
            
            dpop_headers = {
                'Authorization': f'DPoP {access_token}',
                'Accept': 'application/json',
                'DPoP': dpop_proof
            }
            
            dpop_response = requests.get(
                settings.OKTA_USER_INFO_ENDPOINT,
                headers=dpop_headers,
                timeout=10
            )
            
            if dpop_response.status_code == 200:
                logger.info("Successfully retrieved user info with DPoP token")
                return dpop_response.json()
            
            # If that didn't work, try to get a specific nonce
            logger.info(f"DPoP user info request failed with status {dpop_response.status_code}")
            
            # Try to get a fresh DPoP nonce specifically for userinfo
            nonce = get_dpop_nonce(settings.OKTA_USER_INFO_ENDPOINT)
            if nonce and nonce != "not_required":
                logger.info(f"Got fresh nonce for userinfo: {nonce}")
                dpop_proof = generate_dpop_proof("GET", settings.OKTA_USER_INFO_ENDPOINT, nonce)
                dpop_headers['DPoP'] = dpop_proof
                
                retry_response = requests.get(
                    settings.OKTA_USER_INFO_ENDPOINT,
                    headers=dpop_headers,
                    timeout=10
                )
                
                if retry_response.status_code == 200:
                    logger.info("Successfully retrieved user info with fresh DPoP nonce")
                    return retry_response.json()
                    
                logger.error(f"Failed to get user info with fresh nonce: {retry_response.status_code}")
        
        # Fall back to extracting user info from ID token if available
        if request and 'okta_id_token' in request.session:
            try:
                id_token = request.session['okta_id_token']
                token_parts = id_token.split('.')
                if len(token_parts) == 3:
                    import base64
                    import json
                    padded = token_parts[1] + '=' * (4 - len(token_parts[1]) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(padded).decode('utf-8'))
                    
                    # Create user info from ID token claims
                    user_info = {
                        'sub': payload.get('sub'),
                        'email': payload.get('email'),
                        'given_name': payload.get('given_name', ''),
                        'family_name': payload.get('family_name', '')
                    }
                    
                    if user_info.get('email'):
                        logger.info("Extracted user info from ID token")
                        return user_info
            except Exception as e:
                logger.exception("Error extracting user info from ID token")
        
        logger.error(f"All user info retrieval methods failed")
        return None
    except Exception as e:
        logger.exception(f"Exception getting user info: {e}")
        return None

@csrf_protect
def login_view(request):
    """
    Handle standard login form
    
    Args:
        request (HttpRequest): Django request object
        
    Returns:
        HttpResponse: Rendered login page or redirect to dashboard
    """
    next_url = request.GET.get('next') or request.POST.get('next', '/dashboard')
    
    if request.user.is_authenticated:
        return redirect(next_url)
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return redirect(next_url)
        else:
            return render(request, 'traffic_analysis/login.html', {
                'error': 'Invalid credentials. Please try again.',
                'next': next_url
            })
    
    return render(request, 'traffic_analysis/login.html', {'next': next_url})

def okta_login(request):
    """
    Redirect to Okta for authentication
    
    Args:
        request (HttpRequest): Django request object
        
    Returns:
        HttpResponse: Redirect to Okta authorization endpoint
    """
    # Generate a secure state parameter
    state = str(uuid.uuid4())
    request.session['okta_state'] = state
    
    base_url = settings.OKTA_AUTHORIZATION_ENDPOINT
    params = {
        "client_id": settings.OKTA_CLIENT_ID,
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": settings.OKTA_REDIRECT_URI,
        "state": state
    }
    url = f"{base_url}?{urlencode(params)}"
    return redirect(url)

def okta_callback(request):
    """
    Handle the Okta OAuth callback
    
    Args:
        request (HttpRequest): Django request object
        
    Returns:
        HttpResponse: Redirect to dashboard on success or login on failure
    """
    code = request.GET.get('code')
    state = request.GET.get('state')
    stored_state = request.session.get('okta_state')
    
    # Clean up state from session
    if 'okta_state' in request.session:
        del request.session['okta_state']
    
    if not code:
        logger.error("No authorization code received from Okta")
        messages.error(request, "Authentication failed: No authorization code received")
        return redirect('login')
    
    if not state or state != stored_state:
        logger.error("Invalid state parameter")
        messages.error(request, "Authentication failed: State parameter mismatch")
        return redirect('login')
    
    try:
        # Initial token exchange attempt without DPoP
        token_response = requests.post(
            settings.OKTA_TOKEN_ENDPOINT,
            data={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': settings.OKTA_REDIRECT_URI,
                'client_id': settings.OKTA_CLIENT_ID,
                'client_secret': settings.OKTA_CLIENT_SECRET
            },
            headers={
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            timeout=10
        )
        
        # Check if DPoP is required
        dpop_required = False
        if token_response.status_code == 401 or token_response.status_code == 400:
            try:
                error_data = token_response.json()
                error = error_data.get("error")
                if error and "dpop" in error.lower():
                    dpop_required = True
            except:
                pass
        
        # Handle DPoP requirements if needed
        if dpop_required:
            logger.info("DPoP required for token exchange")
            
            # Get DPoP nonce
            nonce = get_dpop_nonce(settings.OKTA_TOKEN_ENDPOINT)
            
            if not nonce or nonce == "not_required":
                logger.error("Failed to get valid DPoP nonce for token exchange")
                messages.error(request, "Authentication failed: Unable to get DPoP nonce")
                return redirect('login')
                
            # Generate DPoP proof with the nonce
            dpop_proof = generate_dpop_proof("POST", settings.OKTA_TOKEN_ENDPOINT, nonce)
            
            if not dpop_proof:
                logger.error("Failed to generate DPoP proof")
                messages.error(request, "Authentication failed: Unable to generate DPoP proof")
                return redirect('login')
            
            # Exchange code for tokens with DPoP proof
            token_response = requests.post(
                settings.OKTA_TOKEN_ENDPOINT,
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': settings.OKTA_REDIRECT_URI,
                    'client_id': settings.OKTA_CLIENT_ID,
                    'client_secret': settings.OKTA_CLIENT_SECRET
                },
                headers={
                    'Accept': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'DPoP': dpop_proof
                },
                timeout=10
            )
        
        # Process token response
        if token_response.status_code != 200:
            logger.error(f"Token exchange failed: {token_response.status_code} - {token_response.text}")
            messages.error(request, "Authentication failed: Unable to exchange code for token")
            return redirect('login')
            
        tokens = token_response.json()
        access_token = tokens.get('access_token')
        id_token = tokens.get('id_token')
        
        # Store tokens in session
        request.session['okta_access_token'] = access_token
        if id_token:
            request.session['okta_id_token'] = id_token
        
        # Try to extract user info from tokens
        user_info = None
        
        if id_token:
            try:
                # Extract user info from ID token payload
                token_parts = id_token.split('.')
                if len(token_parts) == 3:
                    import base64
                    import json
                    padded = token_parts[1] + '=' * (4 - len(token_parts[1]) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(padded).decode('utf-8'))
                    
                    user_info = {
                        'sub': payload.get('sub'),
                        'email': payload.get('email'),
                        'given_name': payload.get('given_name', ''),
                        'family_name': payload.get('family_name', '')
                    }
                    
                    if user_info.get('email'):
                        logger.info("Successfully extracted user info from ID token")
            except Exception as e:
                logger.exception(f"Error extracting info from ID token: {e}")
        
        # If we don't have user info from ID token, get it from userinfo endpoint
        if not user_info or not user_info.get('email'):
            user_info = get_user_info(access_token, request)
        
        if not user_info:
            logger.error("Failed to get user info with token")
            messages.error(request, "Authentication failed: Unable to retrieve user information")
            return redirect('login')
        
        email = user_info.get('email')
        if not email:
            logger.error(f"No email found in user info: {user_info}")
            messages.error(request, "Authentication failed: No email found in user info")
            return redirect('login')
            
        # Get or create user with email as username
        user, created = User.objects.get_or_create(
            username=email,
            defaults={
                'email': email,
                'first_name': user_info.get('given_name', ''),
                'last_name': user_info.get('family_name', '')
            }
        )
        
        # Log the user in
        login(request, user)
        logger.info(f"User {email} successfully logged in")
        
        # Store access token in session for API calls
        request.session['okta_access_token'] = access_token
        if 'id_token' in tokens:
            request.session['okta_id_token'] = tokens['id_token']
        
        return redirect('dashboard')
        
    except requests.RequestException as e:
        logger.exception(f"Request failed during Okta callback: {e}")
        messages.error(request, "Authentication failed: Connection error")
        return redirect('login')
    except Exception as e:
        logger.exception(f"Unexpected error during Okta callback: {e}")
        messages.error(request, f"Authentication failed: {str(e)}")
        return redirect('login')

def logout_view(request):
    """
    Handle logout
    
    Args:
        request (HttpRequest): Django request object
        
    Returns:
        HttpResponse: Redirect to login page
    """
    logout(request)
    messages.success(request, "You have been successfully logged out.")
    return redirect('login')

def test(request):
    """
    Test view for authentication status
    
    Args:
        request (HttpRequest): Django request object
        
    Returns:
        JsonResponse: Authentication status and user details if authenticated
    """
    if request.user.is_authenticated:
        return JsonResponse({
            'authenticated': True,
            'user': {
                'username': request.user.username,
                'email': request.user.email,
                'first_name': request.user.first_name,
                'last_name': request.user.last_name,
            }
        })
    else:
        return JsonResponse({
            'authenticated': False
        }, status=401)