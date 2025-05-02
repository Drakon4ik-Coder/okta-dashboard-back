from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from .models import LoginTiming

@receiver(user_logged_in)
def record_successful_login(sender, request, user, **kwargs):
    """
    Record a timing entry (zero ms) when a user successfully logs in.
    """
    try:
        LoginTiming.objects.create(duration_ms=0.0)
    except Exception:
        pass