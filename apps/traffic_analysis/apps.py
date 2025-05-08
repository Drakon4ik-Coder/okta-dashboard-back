"""
App configuration for traffic_analysis app.
"""
from django.apps import AppConfig


class TrafficAnalysisConfig(AppConfig):
    """
    Configuration class for the traffic_analysis application.
    """
    default_auto_field = "django.db.models.BigAutoField"
    name = "traffic_analysis"
    
    def ready(self):
        """
        Perform initialization when Django starts.
        Imports signals to ensure they're registered.
        """
        import traffic_analysis.signals  # noqa
        
        # Register post migration signal handler to set up scheduled tasks
        # This ensures database operations happen after app initialization
        from django.db.models.signals import post_migrate
        from traffic_analysis.scheduler import setup_scheduled_tasks
        
        # Connect the setup function to the post_migrate signal
        post_migrate.connect(setup_scheduled_tasks, sender=self)