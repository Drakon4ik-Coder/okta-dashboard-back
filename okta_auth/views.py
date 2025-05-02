import json
import logging
import secrets
import uuid
import time
import base64
from typing import Dict
from base64 import b64encode, b64decode
from django.conf import settings
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse, JsonResponse, HttpResponseRedirect
from django.shortcuts import redirect, render
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_http_methods
from django.urls import reverse
from django.core.signing import TimestampSigner, SignatureExpired, BadSignature
from django.utils.crypto import get_random_string
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from OktaDashboardBackend.services.okta_oauth import OktaOAuthClient
from okta_auth.services.token_encryption import TokenEncryptor

logger = logging.getLogger(__name__)
oauth_client = OktaOAuthClient()

@ensure_csrf_cookie
def login_view(request: HttpRequest) -> HttpResponse:
    """
    Initiate OAuth flow with Okta
    """
    # Generate state parameter for CSRF protection
    state = secrets.token_urlsafe(32)
    
    # Make sure our session is created and saved before redirect
    if not request.session.session_key:
        request.session.create()
    
    # Store state in session and immediately save
    request.session['oauth_state'] = state
    request.session.modified = True
    
    # Log state for debugging
    logger.debug(f"Generated OAuth state: {state[:5]}... (Session ID: {request.session.session_key})")
    
    # Store the URL to redirect to after successful authentication
    next_url = request.GET.get('next', '/dashboard')
    request.session['next_url'] = next_url
    
    # Generate authorization URL and redirect user
    auth_url = oauth_client.get_authorization_url(state)
    return redirect(auth_url)


@require_http_methods(['GET'])
def oauth_callback(request: HttpRequest) -> HttpResponse:
    """
    Handle OAuth callback from Okta
    """
    # Log information about the request for debugging
    logger.debug(f"Callback received, session ID: {request.session.session_key}")
    
    # Validate state parameter to prevent CSRF
    state = request.GET.get('state')
    stored_state = request.session.get('oauth_state')
    
    if not state:
        logger.error("No state parameter received in callback")
        return render(request, 'traffic_analysis/errors.html', {
            'error': 'Authentication failed: Missing state parameter'
        })
    
    if not stored_state:
        logger.error("No stored state found in session")
        return render(request, 'traffic_analysis/errors.html', {
            'error': 'Authentication failed: No state found in session (session may have expired)'
        })
    
    if state != stored_state:
        logger.error(f"State mismatch: received {state[:5]}..., stored {stored_state[:5]}...")
        return render(request, 'traffic_analysis/errors.html', {
            'error': 'Authentication failed: Invalid state parameter (state mismatch)'
        })
    
    # Clear the state from session
    del request.session['oauth_state']
    request.session.modified = True
    logger.debug("State validation successful, proceeding with code exchange")
    
    # Get the authorization code
    code = request.GET.get('code')
    if not code:
        logger.error("No code parameter in OAuth callback")
        return render(request, 'traffic_analysis/errors.html', {
            'error': 'Authentication failed: No authorization code received'
        })
    
    # Log code details for diagnostics (without logging the full code)
    logger.debug(f"Authorization code received, length: {len(code)} characters")
    logger.debug(f"Configured redirect_uri: {settings.OKTA_REDIRECT_URI}")
    
    try:
        # Exchange code for tokens
        logger.debug("Attempting to exchange authorization code for tokens")
        token_response = oauth_client.exchange_code_for_tokens(code)
        
        logger.info("Token exchange successful")
        logger.debug(f"Token response contains fields: {', '.join(token_response.keys())}")
        
        # Get user info from the token
        access_token = token_response.get('access_token')
        id_token = token_response.get('id_token')  # Get ID token for fallback
        token_type = token_response.get('token_type')
        
        if not access_token:
            logger.error("No access token received in token response")
            return render(request, 'traffic_analysis/errors.html', {
                'error': 'Authentication failed: No access token received'
            })
            
        # Try to get user info, first with provided token_type, then with fallbacks
        user_info = None
        error_message = None
        
        # First attempt - use token as provided
        try:
            logger.debug(f"Attempting to get user info with access token (token type: {token_type})")
            user_info = oauth_client.get_user_info(access_token, token_type, id_token)
            logger.debug(f"User info received for subject: {user_info.get('sub', 'unknown')}")
        except Exception as e:
            error_message = str(e)
            logger.warning(f"Initial user info attempt failed: {error_message}")
            
            # Second attempt - try with explicit Bearer type
            try:
                logger.debug("Retrying user info with explicit Bearer token")
                user_info = oauth_client.get_user_info(access_token, "Bearer", id_token)
                logger.debug(f"User info received with Bearer token for subject: {user_info.get('sub', 'unknown')}")
            except Exception as e2:
                logger.error(f"All user info attempts failed. Original error: {error_message}, Bearer error: {str(e2)}")
                
                # Final attempt - try to extract info directly from ID token
                if id_token:
                    try:
                        logger.debug("Attempting to extract user info directly from ID token")
                        user_info = oauth_client._parse_id_token(id_token)
                        logger.info(f"Successfully extracted user info from ID token for subject: {user_info.get('sub', 'unknown')}")
                    except Exception as e3:
                        logger.error(f"All user info retrieval methods failed including ID token parsing: {str(e3)}")
                        return render(request, 'traffic_analysis/errors.html', {
                            'error': f'Authentication failed: Could not retrieve user information. Please contact support.'
                        })
                else:
                    return render(request, 'traffic_analysis/errors.html', {
                        'error': f'Authentication failed: Could not retrieve user information and no ID token available. Please contact support.'
                    })
        
        # Get or create a user in Django
        email = user_info.get('email')
        sub = user_info.get('sub')  # Okta user ID is always present
        
        # Handle case when email is missing
        if not email:
            logger.warning("No email found in user info, using alternative identifier")
            # Use preferred_username or sub as fallback
            preferred_username = user_info.get('preferred_username')
            if preferred_username and '@' in preferred_username:
                email = preferred_username
                logger.debug(f"Using preferred_username as email: {email}")
            else:
                # Generate a placeholder email using the user's sub (unique ID)
                email = f"{sub}@okta-user.local"
                logger.debug(f"Generated placeholder email: {email}")

        # Find or create the user - first try by email
        user = None
        try:
            user = User.objects.get(email=email)
            logger.debug(f"Found existing user by email: {user.username}")
        except User.DoesNotExist:
            # If not found by email, try by username that matches sub
            try:
                user = User.objects.get(username=sub)
                logger.debug(f"Found existing user by sub: {user.username}")
                # Update email if it was missing before
                if user.email != email:
                    user.email = email
                    user.save()
            except User.DoesNotExist:
                # Create a new user
                # Use preferred_username, name, or sub as the username
                username = (user_info.get('preferred_username') or 
                           user_info.get('name') or 
                           user_info.get('given_name', '') + user_info.get('family_name', '') or 
                           sub)
                
                # Ensure username is unique by appending sub if needed
                if User.objects.filter(username=username).exists():
                    username = f"{username}_{sub}"
                
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    first_name=user_info.get('given_name', ''),
                    last_name=user_info.get('family_name', '')
                )
                logger.info(f"Created new user: {username}")

        # Ensure user is active
        if not user.is_active:
            user.is_active = True
            user.save()
            logger.info(f"Activated user: {user.username}")

        # Log the user in
        login(request, user)
        logger.info(f"User {user.username} successfully authenticated")

        # Store Okta user ID in session for later use
        request.session['okta_user_id'] = sub
        
        # Generate a device ID if not present
        if not request.session.get('device_id'):
            request.session['device_id'] = str(uuid.uuid4())
        
        # Create a signed device token for token rotation security
        device_token = get_random_string(32)
        signer = TimestampSigner()
        signed_device_token = signer.sign(device_token)
        request.session['device_token'] = signed_device_token
        
        # Securely store tokens - encrypt with user-specific key
        # This isolates tokens per user and session
        if access_token:
            request.session['access_token'] = TokenEncryptor.encrypt_token(access_token, str(user.id))
        
        refresh_token = token_response.get('refresh_token')
        if refresh_token:
            request.session['refresh_token'] = TokenEncryptor.encrypt_token(refresh_token, str(user.id))
        
        id_token = token_response.get('id_token')
        if id_token:
            request.session['id_token'] = TokenEncryptor.encrypt_token(id_token, str(user.id))
        
        # Store token_type and expiration
        request.session['token_type'] = token_response.get('token_type', 'Bearer')
        if 'expires_in' in token_response:
            request.session['token_expires_at'] = int(time.time()) + int(token_response.get('expires_in', 3600))

        # Redirect to the next URL or dashboard
        next_url = request.session.get('next_url', '/dashboard')
        if 'next_url' in request.session:
            del request.session['next_url']
            
        return redirect(next_url)
        
    except Exception as e:
        # Log the error and determine the type of error
        logger.error(f"OAuth callback failed: {str(e)}", exc_info=True)
        
        # Prepare the error message based on the error type
        error_msg = str(e)
        error_details = "Unable to authenticate with Okta"
        
        # Check for known error types
        if "invalid_client" in error_msg.lower():
            error_details = "OAuth client credentials invalid (client_id/client_secret)"
            logger.error(error_details)
            error_msg = f"OAuth client credentials issue: {error_msg}"
        elif "code" in error_msg.lower() and ("expired" in error_msg.lower() or "invalid" in error_msg.lower()):
            error_details = "Authorization code may be expired or already used"
            logger.error(error_details)
            error_msg = f"OAuth code invalid or expired: {error_msg}"
        
        # Add diagnostic info for admin users
        debug_info = ""
        if settings.DEBUG:
            debug_info = (
                f"<br><br>Debug info: "
                f"<ul>"
                f"<li>Redirect URI: {settings.OKTA_REDIRECT_URI}</li>"
                f"<li>Token endpoint: {settings.OKTA_TOKEN_ENDPOINT}</li>"
                f"</ul>"
            )
        
        return render(request, 'traffic_analysis/errors.html', {
            'error': f'Authentication failed: {error_msg}{debug_info}'
        })


@require_http_methods(['GET'])
def refresh_token_view(request: HttpRequest) -> JsonResponse:
    """
    Refresh the access token using the refresh token
    """
    # Check if user is authenticated
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    
    # Get the encrypted refresh token from session
    encrypted_refresh_token = request.session.get('refresh_token')
    if not encrypted_refresh_token:
        return JsonResponse({'error': 'No refresh token available'}, status=400)
    
    try:
        # First verify device token to ensure token usage from same device
        device_token = request.session.get('device_token')
        if not device_token:
            logger.warning("Missing device token during refresh attempt")
            return JsonResponse({'error': 'Invalid session state'}, status=401)
        
        # Verify the device token signature and timestamp
        signer = TimestampSigner()
        try:
            signer.unsign(device_token, max_age=86400*30)  # 30 day max validity
        except (SignatureExpired, BadSignature):
            logger.warning("Invalid or expired device token detected during refresh")
            return JsonResponse({'error': 'Session expired'}, status=401)
        
        # Decrypt the refresh token
        user_id = str(request.user.id)
        refresh_token = TokenEncryptor.decrypt_token(encrypted_refresh_token, user_id)
        
        # Use the client to refresh the token
        token_response = oauth_client.refresh_access_token(refresh_token)
        
        # Encrypt and store the new tokens
        new_access_token = token_response.get('access_token')
        if new_access_token:
            request.session['access_token'] = TokenEncryptor.encrypt_token(new_access_token, user_id)
        
        new_refresh_token = token_response.get('refresh_token')
        if new_refresh_token:
            # Important: We always rotate the refresh token if provided
            request.session['refresh_token'] = TokenEncryptor.encrypt_token(new_refresh_token, user_id)
        
        # Update expiration
        if 'expires_in' in token_response:
            request.session['token_expires_at'] = int(time.time()) + int(token_response.get('expires_in', 3600))
        
        # Create a new device token for improved security
        device_token = get_random_string(32)
        signed_device_token = signer.sign(device_token)
        request.session['device_token'] = signed_device_token
        
        # Ensure session is saved
        request.session.modified = True
        
        # Return success without exposing token to JavaScript
        return JsonResponse({
            'success': True,
            'expires_in': token_response.get('expires_in', 3600)
        })
        
    except ValueError as ve:
        logger.error(f"Token decryption failed: {ve}")
        return JsonResponse({'error': 'Invalid token'}, status=400)
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        return JsonResponse({'error': 'Failed to refresh token'}, status=400)


def get_access_token(request: HttpRequest) -> str:
    """
    Helper function to get the current access token from the session
    
    Args:
        request: The HTTP request object
        
    Returns:
        Decrypted access token string or empty string if not available
    """
    if not request.user.is_authenticated:
        return ""
        
    encrypted_token = request.session.get('access_token')
    if not encrypted_token:
        return ""
        
    try:
        user_id = str(request.user.id)
        return TokenEncryptor.decrypt_token(encrypted_token, user_id)
    except Exception as e:
        logger.error(f"Failed to decrypt access token: {e}")
        return ""


@require_http_methods(['GET'])
def logout_view(request: HttpRequest) -> HttpResponse:
    """
    Log out the user and clear OAuth tokens
    """
    from django.contrib.auth import logout
    
    # Clear all OAuth-related session data
    for key in ['access_token', 'refresh_token', 'id_token', 'token_expires_at', 
               'token_type', 'okta_user_id', 'device_token']:
        if key in request.session:
            del request.session[key]
    
    # Django logout to clear session and auth
    logout(request)
    
    # Redirect to home directory instead of login page
    return redirect('/')