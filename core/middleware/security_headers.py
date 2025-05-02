import random, string, time
from django.utils.deprecation import MiddlewareMixin
from django.template.response import SimpleTemplateResponse
from django.conf import settings

class SecurityHeadersMiddleware(MiddlewareMixin):
    """Middleware that adds security headers and CSP nonce to requests and responses."""
    
    # Django 5.2+ requires this attribute for middleware
    async_mode = False
    
    def process_request(self, request):
        """Generate a single nonce for the entire request lifecycle."""
        # generate *one* nonce per request
        request.nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        request._start_time = time.time()
    
    def process_template_response(self, request, response):
        """
        Django calls this method specifically for TemplateResponse objects.
        We need to ensure the nonce is in the context here.
        """
        # Get the nonce from the request
        nonce = getattr(request, 'nonce', None)
        if not nonce:
            nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            request.nonce = nonce
        
        # Make sure the template context has the nonce
        if hasattr(response, 'context_data') and response.context_data is not None:
            response.context_data['nonce'] = nonce
        
        # Add security headers to the response
        self._add_security_headers(request, response)
        
        return response
    
    def process_response(self, request, response):
        """
        Process all responses, including non-template responses.
        For template responses, process_template_response will have already run.
        """
        # For non-template responses, add security headers
        if not isinstance(response, SimpleTemplateResponse):
            self._add_security_headers(request, response)
        
        # Add timing header
        if hasattr(request, "_start_time"):
            duration = (time.time() - request._start_time) * 1000
            response["Server-Timing"] = f"app;dur={duration:.0f}"
        
        return response
    
    def _add_security_headers(self, request, response):
        """Add all security headers to the response."""
        # Get the nonce from the request
        nonce = getattr(request, 'nonce', None)
        if not nonce:
            nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        
        # Define Content Security Policy
        csp = [
            # Default deny everything except what is explicitly allowed
            "default-src 'none'",
            
            # Allow scripts from self and with our nonce
            f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com",
            f"script-src-elem 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com",
            
            # Allow styles
            f"style-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdnjs.cloudflare.com https://unpkg.com",
            f"style-src-elem 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdnjs.cloudflare.com https://unpkg.com",
            
            # Allow images and fonts with restrictive sources
            "img-src 'self' data: https://cdn.jsdelivr.net https://images.unsplash.com https://randomuser.me",
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com https://cdnjs.cloudflare.com",
            
            # Restrict connections, frames and other elements
            "connect-src 'self'",
            "frame-src 'none'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "upgrade-insecure-requests",
            
            # Add new security directives
            "manifest-src 'self'",
            "media-src 'self'",
            "worker-src 'self'",
            "prefetch-src 'self'",
            
            # Block access to document.cookie from JavaScript
            "require-trusted-types-for 'script'",
            
            # Report CSP violations if a reporting URL is configured
            getattr(settings, 'CSP_REPORT_URI', False) and f"report-uri {settings.CSP_REPORT_URI}" or "",
            getattr(settings, 'CSP_REPORT_TO', False) and f"report-to {settings.CSP_REPORT_TO}" or "",
        ]
        
        # Filter out empty directives
        csp = [directive for directive in csp if directive]
        
        response["Content-Security-Policy"] = "; ".join(csp)
        
        # Basic security headers
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["X-XSS-Protection"] = "1; mode=block"
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Permissions policy - restrictive by default
        response["Permissions-Policy"] = (
            "accelerometer=(), "
            "camera=(), "
            "geolocation=(), "
            "gyroscope=(), "
            "magnetometer=(), "
            "microphone=(), "
            "payment=(), "
            "usb=(), "
            "interest-cohort=()"  # Block FLoC tracking
        )
        
        # Cross-Origin headers
        response["Cross-Origin-Embedder-Policy"] = "require-corp"
        response["Cross-Origin-Opener-Policy"] = "same-origin"
        response["Cross-Origin-Resource-Policy"] = "same-origin"
        
        # Add HSTS header - enforce HTTPS
        if not settings.DEBUG:
            response["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
            
        # Clear-Site-Data header for logout pages - logout is typically /logout/
        if request.path == '/logout/':
            response["Clear-Site-Data"] = '"cache", "cookies", "storage", "executionContexts"'
            
        # Zero Trust specific security headers
        
        # Feature-Policy (deprecated but still supported by some browsers)
        response["Feature-Policy"] = (
            "camera 'none'; "
            "microphone 'none'; "
            "geolocation 'none'; "
            "payment 'none'; "
            "usb 'none'"
        )
        
        # Add a request ID for traffic tracing in a Zero Trust network
        if not response.has_header('X-Request-ID') and hasattr(request, 'id'):
            response['X-Request-ID'] = getattr(request, 'id', '')
            
        # Add cache control headers to prevent sensitive data caching
        if request.path.startswith('/api/') or request.path.startswith('/dashboard/'):
            response["Cache-Control"] = "no-store, max-age=0"
            response["Pragma"] = "no-cache"
            
        return response
