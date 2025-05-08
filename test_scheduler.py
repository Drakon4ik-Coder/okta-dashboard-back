import os
import sys
import django
import time
import logging

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# Import after Django is set up
from traffic_analysis.scheduler import get_last_okta_log_timestamp, fetch_okta_logs_with_dpop
from django_q.models import Schedule

def test_get_last_timestamp():
    """Test if we can retrieve the last log timestamp"""
    timestamp = get_last_okta_log_timestamp()
    logger.info(f"Retrieved last timestamp: {timestamp}")
    return timestamp

def test_scheduler_registration():
    """Test if the scheduler task gets registered properly"""
    # Clear any existing tasks with the same name
    Schedule.objects.filter(name="fetch_okta_logs_dpop_test").delete()
    
    # Register a test task
    from django_q.tasks import schedule
    schedule(
        'traffic_analysis.scheduler.fetch_okta_logs_with_dpop',
        name='fetch_okta_logs_dpop_test',
        minutes=5,  # Using 5 minutes for test to avoid frequent runs
        repeats=-1
    )
    
    # Verify it was registered
    task = Schedule.objects.filter(name="fetch_okta_logs_dpop_test").first()
    if task:
        logger.info(f"Task registered successfully: {task.name}, next run: {task.next_run}")
        return True
    else:
        logger.error("Failed to register test task")
        return False

def test_direct_fetch():
    """Test direct execution of the log fetch function"""
    logger.info("Testing direct execution of fetch_okta_logs_with_dpop()")
    try:
        fetch_okta_logs_with_dpop()
        logger.info("Direct execution completed without errors")
        return True
    except Exception as e:
        logger.error(f"Error during direct execution: {str(e)}")
        return False

if __name__ == "__main__":
    logger.info("===== Testing Okta Logs DPoP Scheduler =====")
    
    logger.info("\n----- Testing timestamp retrieval -----")
    timestamp = test_get_last_timestamp()
    
    logger.info("\n----- Testing scheduler registration -----")
    registration_ok = test_scheduler_registration()
    
    logger.info("\n----- Testing direct fetch execution -----")
    direct_fetch_ok = test_direct_fetch()
    
    logger.info("\n===== Test Results =====")
    logger.info(f"Last timestamp: {timestamp}")
    logger.info(f"Scheduler registration: {'SUCCESS' if registration_ok else 'FAILED'}")
    logger.info(f"Direct fetch execution: {'SUCCESS' if direct_fetch_ok else 'FAILED'}")
    
    # If Django-Q cluster is running, the task should be picked up soon
    logger.info("\nNOTE: For complete testing, ensure Django-Q cluster is running")
    logger.info("Run in another terminal: python manage.py qcluster")