"""
API Authorization Middleware for Zero Trust model.
This middleware implements the principle of least privilege using OAuth scopes.
"""

import logging
import re
import json
from typing import Dict, List, Set, Optional
from django.http import JsonResponse
from django.urls import resolve, Resolver404
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from okta_auth.services.token_encryption import TokenEncryptor
from OktaDashboardBackend.services.okta_oauth import OktaOAuthClient

logger = logging.getLogger(__name__)

class APIAuthorizationMiddleware(MiddlewareMixin):
    """
    Middleware that enforces API access control using OAuth scopes and permissions.
    
    Implements the Zero Trust principle of least privilege by ensuring that
    each API endpoint is accessible only with appropriate permissions.
    """
    
    # Django 5.2+ requires this attribute for middleware
    async_mode = False
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.oauth_client = OktaOAuthClient()
        
        # API endpoint regex pattern
        self.api_pattern = re.compile(r'^/api/')
        
        # Load API permissions mapping
        self.api_permissions = self._load_api_permissions()
        
        # Default scope required if not specified
        self.default_scope = getattr(settings, 'DEFAULT_API_SCOPE', 'okta.dashboard.read')
        
        # Exempt paths that don't require authorization
        self.exempt_paths = [
            '/api/health/',
            '/api/public/',
            '/api/token/refresh/',
            '/api/login-timing/avg/cached/',
            '/api/statistics/login-events/',
            '/api/statistics/failed-logins/',
            '/api/statistics/security-events/',
            '/api/statistics/total-events/',  # Added total events endpoint to exemptions
            '/api/statistics/avg-login-time',
        ]
        
    def process_request(self, request):
        """Process request to enforce API authorization"""
        # Skip if not an API request
        if not self._is_api_request(request.path):
            return None
            
        # Skip exempt paths
        if self._is_exempt_path(request.path):
            return None
            
        # Skip if user is not authenticated
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Authentication required'}, status=401)
            
        # Get endpoint permissions
        permissions_required = self._get_endpoint_permissions(request)
        
        # If no permissions defined, use defaults
        if not permissions_required:
            return None
            
        # Get user scopes from token
        user_permissions = self._get_user_permissions(request)
        
        # Check if user has required permissions
        if not self._has_required_permissions(user_permissions, permissions_required):
            logger.warning(
                f"Unauthorized API access attempt: User {request.user.username} "
                f"attempted to access {request.path} without required permissions."
            )
            return JsonResponse({'error': 'Insufficient permissions'}, status=403)
            
        # If we get here, authorization passed
        return None
            
    def _is_api_request(self, path: str) -> bool:
        """Check if this is an API request"""
        return bool(self.api_pattern.match(path))
        
    def _is_exempt_path(self, path: str) -> bool:
        """Check if path is exempt from authorization"""
        return any(path.startswith(exempt_path) for exempt_path in self.exempt_paths)
        
    def _load_api_permissions(self) -> Dict:
        """
        Load API permission mappings from settings
        
        Format in settings should be:
        API_PERMISSIONS = {
            'endpoint_pattern': ['required_scope1', 'required_scope2'],
            '/api/users/': ['okta.dashboard.users.read'],
            '/api/admin/': ['okta.dashboard.admin'],
        }
        """
        return getattr(settings, 'API_PERMISSIONS', {})
        
    def _get_endpoint_permissions(self, request) -> List[str]:
        """
        Get required permissions for an endpoint
        
        Returns a list of required permission scopes
        """
        path = request.path
        method = request.method
        
        # Try to resolve the view
        try:
            view_name = resolve(path).view_name
        except Resolver404:
            view_name = None
            
        # Check for path-specific permissions first
        for pattern, permissions in self.api_permissions.items():
            if path.startswith(pattern):
                # Check if method-specific permissions exist
                if isinstance(permissions, dict) and method in permissions:
                    return permissions[method]
                # Otherwise use common permissions
                elif isinstance(permissions, list):
                    return permissions
                    
        # Check for view-specific permissions if path not found
        if view_name and view_name in self.api_permissions:
            permissions = self.api_permissions[view_name]
            if isinstance(permissions, dict) and method in permissions:
                return permissions[method]
            elif isinstance(permissions, list):
                return permissions
        
        # Fall back to default scope for all API endpoints
        return [self.default_scope]
        
    def _get_user_permissions(self, request) -> Set[str]:
        """
        Extract permissions from the user's access token
        
        Returns a set of permission scopes the user has
        """
        # Get encrypted token from session
        encrypted_token = request.session.get('access_token')
        if not encrypted_token:
            return set()
            
        try:
            # Decrypt token
            user_id = str(request.user.id)
            token = TokenEncryptor.decrypt_token(encrypted_token, user_id)
            
            # Try to parse JWT to extract scopes
            scopes = self._extract_scopes_from_token(token)
            
            # If successful, return as set
            if scopes:
                return set(scopes)
                
        except Exception as e:
            logger.error(f"Failed to extract permissions from token: {str(e)}")
            
        # Default fallback - no scopes
        return set()
    
    def _extract_scopes_from_token(self, token: str) -> Optional[List[str]]:
        """Extract scopes from JWT token"""
        try:
            # Properly verify the token using Okta OAuth client
            import jwt
            from jwt.exceptions import DecodeError, ExpiredSignatureError
            
            # Use the OAuth client to verify the token
            payload = self.oauth_client.verify_token(token)
            
            # Get scopes - Okta typically uses 'scp' (array) or 'scope' (space-delimited string)
            if 'scp' in payload and isinstance(payload['scp'], list):
                return payload['scp']
            elif 'scope' in payload and isinstance(payload['scope'], str):
                return payload['scope'].split()
                
        except (DecodeError, ExpiredSignatureError) as e:
            logger.warning(f"Failed to decode token: {str(e)}")
        except Exception as e:
            logger.error(f"Error processing token: {str(e)}")
            
        return None
    
    def _has_required_permissions(self, user_permissions: Set[str], 
                                 required_permissions: List[str]) -> bool:
        """
        Check if user has the required permissions
        
        Args:
            user_permissions: Set of permissions the user has
            required_permissions: List of required permissions (any match is sufficient)
        
        Returns:
            True if user has at least one of the required permissions
        """
        # Admin scope always provides access
        if 'okta.dashboard.admin' in user_permissions:
            return True
            
        # Check for intersection between user permissions and required permissions
        return bool(user_permissions.intersection(required_permissions))