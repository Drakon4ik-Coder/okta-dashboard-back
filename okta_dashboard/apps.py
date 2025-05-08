from django.apps import AppConfig


class OktaDashboardConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'okta_dashboard'
    verbose_name = 'Okta Dashboard Core'

    def ready(self):
        """
        Perform initialization tasks when the app is ready.
        """
        # Import signals or perform other initialization here
        pass