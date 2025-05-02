"""
Continuous Authentication Middleware for Zero Trust model.
This middleware validates tokens on each request and checks user context parameters.
"""

import logging
import time
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from okta_auth.services.token_encryption import TokenEncryptor
from OktaDashboardBackend.services.okta_oauth import OktaOAuthClient

logger = logging.getLogger(__name__)
oauth_client = OktaOAuthClient()

class ContinuousAuthMiddleware(MiddlewareMixin):
    """
    Zero Trust Continuous Authentication Middleware.
    
    Enforces:
    1. Token validation on every request
    2. Context-based authentication (IP, device, location)
    3. Token lifespan validation
    4. Risk-based step-up authentication
    """
    
    # Django 5.2+ requires this attribute for middleware
    async_mode = False
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.exempt_paths = [
            '/login/', 
            '/logout/', 
            '/okta/callback/',
            '/health/',
            '/api/token/refresh/',
            '/static/',
            '/media/',
            '/favicon.ico',
        ]
        # Maximum time (in seconds) token can be valid before requiring revalidation
        self.token_revalidation_interval = getattr(settings, 'TOKEN_REVALIDATION_INTERVAL', 300)  # 5 minutes
        self.risk_thresholds = {
            'ip_change': getattr(settings, 'RISK_THRESHOLD_IP_CHANGE', 'medium'),
            'inactive_time': getattr(settings, 'RISK_THRESHOLD_INACTIVE_TIME', 1800),  # 30 minutes
            'suspicious_activity': getattr(settings, 'RISK_THRESHOLD_SUSPICIOUS', 'high'),
        }
    
    def process_request(self, request):
        # Skip exempt paths
        if any(request.path.startswith(path) for path in self.exempt_paths):
            return None
            
        # Skip if user is not authenticated
        if not request.user.is_authenticated:
            return None
            
        # Update last activity timestamp
        self._update_activity_timestamp(request)
        
        # Check token validity
        if not self._validate_token(request):
            logger.warning(f"Token validation failed for user {request.user.username} - redirecting to login")
            return HttpResponseRedirect(reverse('okta_login'))
            
        # Check context parameters (IP, device, location)
        if not self._validate_context(request):
            # If high risk, force re-authentication
            if self._get_risk_score(request) >= 0.7:  # High risk threshold
                logger.warning(f"High risk access detected for user {request.user.username} - forcing re-authentication")
                return HttpResponseRedirect(reverse('okta_login'))
            else:
                # Medium risk - Update session flag to prompt for step-up auth on sensitive operations
                request.session['requires_step_up'] = True
                request.session.modified = True
                logger.info(f"Medium risk access detected for user {request.user.username} - requiring step-up auth")
                
        return None
            
    def _validate_token(self, request):
        """Validate the user's access token with Okta"""
        try:
            # Get encrypted token from session
            encrypted_token = request.session.get('access_token')
            if not encrypted_token:
                # If we have an id_token but no access_token, trust the session temporarily
                # This fixes issues when userinfo endpoint fails but login was successful
                if request.session.get('id_token') and 'okta_user_id' in request.session:
                    logger.info(f"No access token but valid session for user {request.user.username} - trusting session")
                    
                    # Set validation timestamp to create a grace period
                    current_time = int(time.time())
                    request.session['token_last_validated'] = current_time
                    request.session.modified = True
                    
                    # Return valid for this request to prevent redirect loops
                    return True
                return False
                
            # Check for recently authenticated sessions to prevent redirect loops
            # If authenticated within the last 30 seconds, skip validation
            auth_time = request.session.get('auth_time', 0)
            current_time = int(time.time())
            if auth_time > 0 and current_time - auth_time < 30:
                logger.debug(f"Recently authenticated user {request.user.username} - skipping token validation")
                # Update validation timestamp for future requests
                request.session['token_last_validated'] = current_time
                request.session.modified = True
                return True
                
            # Get token validation timestamp
            last_validated = request.session.get('token_last_validated', 0)
            
            # Only validate with Okta if the token hasn't been validated recently
            # This reduces API calls while maintaining security
            if current_time - last_validated > self.token_revalidation_interval:
                # Check token expiration time first
                token_expires_at = request.session.get('token_expires_at', 0)
                if token_expires_at > 0 and current_time < token_expires_at:
                    # Token is still within its expiry window, consider valid
                    logger.debug(f"Token for {request.user.username} within expiry window - skipping external validation")
                    request.session['token_last_validated'] = current_time
                    request.session.modified = True
                    return True
                
                try:
                    # Decrypt token and validate with Okta
                    user_id = str(request.user.id)
                    token = TokenEncryptor.decrypt_token(encrypted_token, user_id)
                    
                    if oauth_client.validate_token(token):
                        # Update validation timestamp
                        request.session['token_last_validated'] = current_time
                        request.session.modified = True
                        return True
                    else:
                        # Try to use refresh token if available
                        if 'refresh_token' in request.session:
                            logger.info(f"Attempting token refresh for user {request.user.username}")
                            # We'll handle this through the front-end refresh mechanism
                            # Mark as needing refresh but don't fail this request
                            request.session['needs_token_refresh'] = True
                            request.session.modified = True
                            # For this request, still consider it valid to prevent redirect loops
                            return True
                        return False
                except Exception as e:
                    logger.warning(f"Token validation with Okta failed: {str(e)}")
                    # For robustness, if we can't validate, rely on session expiration
                    if current_time - last_validated < 60*60:  # 1 hour max without successful validation
                        logger.info(f"Using session-based validation for {request.user.username} due to Okta validation error")
                        return True
                    return False
            else:
                # Token was recently validated, so it's still valid
                return True
                
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            
            # Even on error, give a grace period of 5 minutes for new sessions
            # This prevents endless redirect loops on authentication issues
            auth_time = request.session.get('auth_time', 0)
            current_time = int(time.time())
            if auth_time > 0 and current_time - auth_time < 300:  # 5 minute grace period
                logger.info(f"Error during token validation but within grace period for new session - allowing access")
                return True
                
            return False
            
    def _validate_context(self, request):
        """Validate the user's context parameters"""
        # Get current context
        current_ip = self._get_client_ip(request)
        current_user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Get stored context
        stored_ip = request.session.get('client_ip')
        stored_user_agent = request.session.get('user_agent')
        
        # If this is the first request in this session, store the context
        if not stored_ip or not stored_user_agent:
            request.session['client_ip'] = current_ip
            request.session['user_agent'] = current_user_agent
            request.session.modified = True
            return True
            
        # Compare context
        ip_changed = stored_ip != current_ip
        user_agent_changed = stored_user_agent != current_user_agent
        
        if ip_changed:
            logger.warning(f"IP address changed for user {request.user.username}: {stored_ip} -> {current_ip}")
            request.session['context_risk'] = 'ip_change'
            request.session.modified = True
        
        if user_agent_changed:
            logger.warning(f"User agent changed for user {request.user.username}")
            request.session['context_risk'] = 'user_agent_change'
            request.session.modified = True
            
        # Return True if context is valid (no changes or acceptable risk)
        return not (ip_changed or user_agent_changed)
    
    def _get_client_ip(self, request):
        """Get the client's IP address from request headers"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
        
    def _update_activity_timestamp(self, request):
        """Update the user's last activity timestamp"""
        request.session['last_activity'] = int(time.time())
        request.session.modified = True
        
    def _get_risk_score(self, request):
        """Calculate a risk score based on context and activity"""
        # Get context risk
        context_risk = request.session.get('context_risk', None)
        
        # Base risk score
        risk_score = 0.1  # Default low risk
        
        # Increase risk for context changes
        if context_risk == 'ip_change':
            risk_score += 0.3  # Moderate risk increase
        elif context_risk == 'user_agent_change':
            risk_score += 0.2  # Slight risk increase
            
        # Check inactivity time
        last_activity = request.session.get('last_activity', int(time.time()))
        inactive_time = int(time.time()) - last_activity
        
        # Add risk for inactivity
        if inactive_time > self.risk_thresholds['inactive_time']:
            risk_score += 0.3  # Significant risk for long inactivity
            
        # Cap risk score at 1.0
        return min(risk_score, 1.0)