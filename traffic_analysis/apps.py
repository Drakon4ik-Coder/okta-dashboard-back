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
        Registers scheduled tasks.
        """
        import traffic_analysis.signals  # noqa
        
        # Register scheduled tasks
        # Using try/except to handle potential database errors during app initialization
        try:
            from traffic_analysis.scheduler import register_scheduled_tasks
            register_scheduled_tasks()
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to register scheduled tasks: {str(e)}")
            # Don't raise the exception as it would prevent the app from starting