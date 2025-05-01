# login_tracking/apps.py
from django.apps import AppConfig

class LoginTrackingConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'login_tracking'

    def ready(self):
        import login_tracking.signals