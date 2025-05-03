import logging
from django_q.models import Schedule
from django_q.tasks import schedule, async_task
import sys
from OktaDashboardBackend.services.database import DatabaseService

logger = logging.getLogger(__name__)

def register_scheduled_tasks():
    """
    Register scheduled tasks for the application
    """
    logger.info("Registering scheduled tasks...")
    
    # Delete any existing schedules with the same name to avoid duplicates
    Schedule.objects.filter(name="fetch_okta_logs").delete()
    Schedule.objects.filter(name="update_login_time_cache").delete()
    
    # Schedule the task to run every minute
    schedule(
        'django.core.management.call_command',  # Function to call
        'fetch_okta_logs',                      # Command name
        name='fetch_okta_logs',                 # Schedule name
        minutes=1,                              # Run every 1 minute
        repeats=-1,                             # Repeat indefinitely
    )
    
    # Schedule the login time cache update task to run every 10 minutes
    schedule(
        'django.core.management.call_command',  # Function to call
        'update_login_time_cache',              # Command name
        name='update_login_time_cache',         # Schedule name
        minutes=10,                             # Run every 10 minutes
        repeats=-1,                             # Repeat indefinitely
    )
    
    logger.info("Successfully registered task to fetch Okta logs every minute")
    logger.info("Successfully registered task to update login time cache every 10 minutes")
    
    # Run an immediate fetch of Okta logs at startup
    if 'runserver' in sys.argv or 'uvicorn' in sys.argv:
        initial_fetch_logs()

def initial_fetch_logs():
    """
    Perform an initial fetch of Okta logs at server startup.
    This ensures we have fresh data immediately without waiting for the schedule.
    """
    try:
        # Make sure MongoDB is connected first
        db_service = DatabaseService()
        if not db_service.is_connected():
            logger.warning("MongoDB connection failed during startup, skipping initial log fetch")
            return
            
        logger.info("Performing initial Okta logs fetch at startup...")
        # Queue the fetch task to run immediately but asynchronously
        # This prevents delaying the server startup process
        async_task(
            'django.core.management.call_command',
            'fetch_okta_logs',
            '--minutes',
            '60',  # Fetch the last hour of logs on startup
            hook='traffic_analysis.scheduler.log_fetch_callback'
        )
    except Exception as e:
        logger.error(f"Error during initial Okta logs fetch: {str(e)}")

def log_fetch_callback(task):
    """
    Callback function for the async log fetch task
    """
    if task.success:
        logger.info("Initial Okta logs fetch completed successfully")
    else:
        logger.error(f"Initial Okta logs fetch failed: {task.result}")

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
            # Ensure MongoDB is connected
            db_service = DatabaseService()
            if db_service.is_connected():
                logger.info("MongoDB connection verified during server startup")
            else:
                logger.warning("MongoDB connection check failed during startup")
                
            register_scheduled_tasks()
        except Exception as e:
            logger.error(f"Failed to register scheduled tasks: {str(e)}")