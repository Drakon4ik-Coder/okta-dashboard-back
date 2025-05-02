import logging
from django_q.models import Schedule
from django_q.tasks import schedule

logger = logging.getLogger(__name__)

def register_scheduled_tasks():
    """
    Register scheduled tasks for the application
    """
    logger.info("Registering scheduled tasks...")
    
    # Delete any existing schedules with the same name to avoid duplicates
    Schedule.objects.filter(name="fetch_okta_logs").delete()
    
    # Schedule the task to run every minute
    schedule(
        'django.core.management.call_command',  # Function to call
        'fetch_okta_logs',                      # Command name
        name='fetch_okta_logs',                 # Schedule name
        minutes=1,                              # Run every 1 minute
        repeats=-1,                             # Repeat indefinitely
    )
    
    logger.info("Successfully registered task to fetch Okta logs every minute")

def setup_scheduled_tasks(sender, **kwargs):
    """
    Signal handler for post_migrate signal.
    This ensures database operations only happen after the app is fully initialized 
    and migrations are complete.
    
    Args:
        sender: The sender of the signal
        **kwargs: Additional arguments passed by the signal
    """
    # Only register tasks when running the main server process, not during tests or other commands
    import sys
    if 'runserver' in sys.argv or 'uvicorn' in sys.argv:
        try:
            register_scheduled_tasks()
        except Exception as e:
            logger.error(f"Failed to register scheduled tasks: {str(e)}")