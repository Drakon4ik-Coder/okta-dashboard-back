from django_q.models import Schedule
from django_q.tasks import schedule
import logging

logger = logging.getLogger(__name__)

def setup_schedules():
    """Set up scheduled tasks"""
    logger.info("Setting up scheduled tasks")
    
    try:
        # Delete any existing schedule for log fetching to avoid duplicates
        Schedule.objects.filter(func='TrafficAnalysis.tasks.fetch_and_save_logs').delete()
        
        # Schedule log fetching every hour
        schedule(
            'TrafficAnalysis.tasks.fetch_and_save_logs',
            schedule_type='H',  # Hourly
            repeats=-1,  # Repeat forever
            name='Fetch Okta Logs'
        )
        
        logger.info("Successfully set up scheduled tasks")
    except Exception as e:
        logger.exception(f"Error setting up scheduled tasks: {e}")