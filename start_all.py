#!/usr/bin/env python
"""
Start script for Okta Dashboard Backend that performs the following:
1. Sets up the Django environment
2. Starts the Django Q cluster for background tasks
3. Schedules the tasks (fetching_logs_dpop)
4. Runs the Django development server
"""

import os
import sys
import time
import logging
import subprocess
import threading
import signal
import argparse
from datetime import datetime

# Add the current directory to Python's path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)
# Also add the apps directory explicitly to ensure it's in the path
apps_dir = os.path.join(current_dir, 'apps')
if os.path.exists(apps_dir):
    sys.path.insert(0, apps_dir)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

try:
    import django
    django.setup()

    # Import after Django is set up
    from django_q.cluster import Cluster
    from traffic_analysis.scheduler import start_okta_logs_chain
except ImportError as e:
    logger.error(f"Failed to import Django modules: {str(e)}")
    logger.error("Make sure you have installed all requirements and are in the right directory.")
    sys.exit(1)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Start Okta Dashboard Backend services")
    parser.add_argument('--port', type=int, default=8000, help='Port for Django server (default: 8000)')
    parser.add_argument('--skip-q', action='store_true', help='Skip starting the Q cluster')
    parser.add_argument('--skip-server', action='store_true', help='Skip starting the Django server')
    return parser.parse_args()

def start_q_cluster():
    """Start the Django Q cluster in a separate thread."""
    logger.info("Starting Django Q cluster...")
    
    # Create a q cluster instance
    q = Cluster()
    
    # Start the cluster in a separate thread
    q_thread = threading.Thread(target=q.start)
    q_thread.daemon = True
    q_thread.start()
    
    # Give it time to initialize
    time.sleep(2)
    logger.info("Django Q cluster is running")
    
    return q, q_thread

def schedule_tasks():
    """Schedule the necessary tasks using traffic_analysis.scheduler."""
    logger.info("Scheduling tasks...")
    
    try:
        # First, clean up any existing scheduled tasks to prevent duplicates
        from django_q.models import Schedule
        
        # Remove all existing okta logs fetch schedules
        deleted_count = Schedule.objects.filter(
            func__contains='okta_logs'
        ).delete()[0]
        
        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} existing Okta logs fetch schedules")
        
        # Start the Okta logs fetching chain (only the self-perpetuating one)
        task_id = start_okta_logs_chain()
        
        if task_id:
            logger.info(f"Successfully scheduled Okta logs DPoP fetching task (ID: {task_id})")
        else:
            logger.warning("Failed to schedule Okta logs DPoP fetching task")
            
    except Exception as e:
        logger.error(f"Error scheduling tasks: {str(e)}")
        
    logger.info("Task scheduling completed")

def start_django_server(port):
    """Start the Django development server."""
    logger.info(f"Starting Django development server on port {port}...")
    
    try:
        # Use subprocess to run Django's runserver command
        server_process = subprocess.Popen(
            [sys.executable, "manage.py", "runserver", f"0.0.0.0:{port}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        # Monitor the output
        for line in server_process.stdout:
            print(line, end='')
            
        return server_process
    
    except Exception as e:
        logger.error(f"Failed to start Django server: {str(e)}")
        return None

def handle_shutdown(q=None, server_process=None):
    """Handle graceful shutdown of all services."""
    def shutdown_handler(signum, frame):
        logger.info("Received shutdown signal. Shutting down services...")
        
        if server_process:
            logger.info("Stopping Django server...")
            server_process.terminate()
            server_process.wait(timeout=5)
            
        if q:
            logger.info("Stopping Django Q cluster...")
            q.stop()
            
        logger.info("All services stopped. Exiting.")
        sys.exit(0)
    
    return shutdown_handler

def main():
    """Main function to orchestrate starting all services."""
    args = parse_arguments()
    
    logger.info(f"Starting Okta Dashboard Backend services at {datetime.now().isoformat()}")
    
    q = None
    server_process = None
    
    try:
        # Start Django Q cluster if not skipped
        if not args.skip_q:
            q, _ = start_q_cluster()
            
            # Schedule the tasks
            schedule_tasks()
        else:
            logger.info("Skipping Django Q cluster start as requested")
        
        # Start Django server if not skipped
        if not args.skip_server:
            server_process = start_django_server(args.port)
        else:
            logger.info("Skipping Django server start as requested")
            
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, handle_shutdown(q, server_process))
        signal.signal(signal.SIGTERM, handle_shutdown(q, server_process))
        
        # Keep the main thread alive if any services are running
        if server_process or (not args.skip_q):
            logger.info("All services started. Press Ctrl+C to stop.")
            while True:
                time.sleep(1)
                
    except KeyboardInterrupt:
        logger.info("Interrupted by user. Shutting down...")
        handle_shutdown(q, server_process)(None, None)
    
    except Exception as e:
        logger.error(f"Error in main: {str(e)}")
        handle_shutdown(q, server_process)(None, None)
        sys.exit(1)

if __name__ == "__main__":
    main()