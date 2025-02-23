from django.apps import AppConfig
from django.conf import settings

class TrafficanalysisConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'TrafficAnalysis'

    def ready(self):
        """Initialize database connection when Django starts"""
        from OktaDashboardBackend.services.database import DatabaseService
        if not settings.DEBUG or ('test' not in settings.DATABASES):
            DatabaseService()