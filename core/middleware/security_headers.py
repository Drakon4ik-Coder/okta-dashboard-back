import random, string, time
from django.utils.deprecation import MiddlewareMixin

class SecurityHeadersMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # generate *one* nonce per request
        request.nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        request._start_time = time.time()

    def process_response(self, request, response):
        nonce = getattr(request, 'nonce', None)
        if not nonce:
            # fallback for non-Django-rendered responses
            nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

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

        # other security headers ...
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["X-XSS-Protection"] = "1; mode=block"
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"

        # inject nonce into template context if possible
        if hasattr(response, 'context_data') and response.context_data is not None:
            response.context_data['nonce'] = nonce

        # caching / Server-Timing logic …
        if hasattr(request, "_start_time"):
            duration = (time.time() - request._start_time) * 1000
            response["Server-Timing"] = f"app;dur={duration:.0f}"
        return response
