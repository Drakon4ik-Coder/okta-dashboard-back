from django.apps import AppConfig

class TrafficanalysisConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'TrafficAnalysis'

    def ready(self):
        """Run when the app is ready"""
        # Import signals to register them
        import TrafficAnalysis.signals