import time
from django.urls import reverse
from .models import LoginTiming
from .metrics import login_response_time

class LoginTimingMiddleware:
    """
    Middleware to time the login endpoint and store durations.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Record start time for any request to the login URL
        login_url = reverse('login')
        start = None
        if request.path == login_url:
            start = time.time()

        # Process the request
        response = self.get_response(request)

        # If timing was started, compute elapsed_ms and record
        if start is not None:
            elapsed_ms = (time.time() - start) * 1000.0
            try:
                # Save to DB
                LoginTiming.objects.create(duration_ms=elapsed_ms)
                # Export to Prometheus
                login_response_time.observe(elapsed_ms)
            except Exception:
                pass

        return response