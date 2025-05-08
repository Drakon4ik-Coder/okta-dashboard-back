from django.apps import AppConfig


class OktaAuthConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'okta_auth'
    verbose_name = 'Okta Authentication'
    
    def ready(self):
        """
        Perform initialization when Django starts.
        """
        # Import any signals if needed
        pass