import random, string, time
from django.utils.deprecation import MiddlewareMixin
from django.template.response import SimpleTemplateResponse

class SecurityHeadersMiddleware(MiddlewareMixin):
    """Middleware that adds security headers and CSP nonce to requests and responses."""
    
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
            "default-src 'self'",
            
            # allow inline scripts *with* our nonce, and CDN-loaded scripts
            f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net",
            # explicit fallback for <script> elements
            f"script-src-elem 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net",
            
            # allow inline styles *with* our nonce, CDN CSS, and Google Fonts
            f"style-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://fonts.googleapis.com",
            f"style-src-elem 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://fonts.googleapis.com",
            
            "img-src 'self' data: https://cdn.jsdelivr.net",
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com",
            "connect-src 'self'",
            "frame-src 'none'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "upgrade-insecure-requests",
        ]
        response["Content-Security-Policy"] = "; ".join(csp)
        
        # Other security headers
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["X-XSS-Protection"] = "1; mode=block"
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
