from datetime import datetime, timedelta
import logging
from django.conf import settings
from .services.logs_fetching import main as fetch_logs_main
import requests
from TrafficAnalysis.models import OktaLog
from django.utils import timezone

logger = logging.getLogger(__name__)

def fetch_and_save_logs():
    """Task to fetch and save logs from Okta with proper error handling"""
    logger.info("Starting scheduled task: fetch_and_save_logs")
    
    try:
        # Check if required Okta credentials exist
        if not settings.OKTA_API_TOKEN or not settings.OKTA_ORG_URL:
            logger.error("Missing required Okta credentials in settings")
            return False
            
        # Set up API endpoint and headers
        url = f"{settings.OKTA_ORG_URL}/api/v1/logs"
        headers = {
            'Authorization': f"SSWS {settings.OKTA_API_TOKEN}",
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        # Calculate last 24 hours for filtering
        since = datetime.utcnow() - timedelta(hours=24)
        since_str = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        # Query parameters
        params = {
            'since': since_str,
            'limit': 100  # Okta's max limit
        }
        
        # Make request to Okta API
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code != 200:
            logger.error(f"Failed to fetch Okta logs: {response.status_code} - {response.text}")
            return False
        
        # Process and save logs
        logs = response.json()
        counter = 0
        
        for log in logs:
            # Check if log already exists
            existing = OktaLog.objects.filter(id=log.get('id')).first()
            if not existing:
                try:
                    # Create new log entry
                    OktaLog(
                        id=log.get('id'),
                        published=log.get('published'),
                        event_type=log.get('eventType'),
                        event_type_category=log.get('eventTypeCategory', 'Other'),
                        actor_display_name=log.get('actor', {}).get('displayName'),
                        actor=log.get('actor', {}),
                        client_ip=log.get('client', {}).get('ipAddress'),
                        client=log.get('client', {}),
                        outcome=log.get('outcome', {}),
                        target=log.get('target', []),
                        raw_data=log,
                        created_at=timezone.now()
                    ).save()
                    counter += 1
                except Exception as e:
                    logger.exception(f"Error saving log entry: {e}")
        
        logger.info(f"Successfully saved {counter} new logs")
        return True
        
    except Exception as e:
        logger.exception(f"Exception in fetch_and_save_logs task: {e}")
        return False

def test_mongodb_connection():
    """Task to test MongoDB connectivity"""
    import logging
    from mongoengine import connect
    from django.conf import settings
    
    logger = logging.getLogger(__name__)
    
    try:
        # Try listing all collections to test connection
        from mongoengine.connection import get_connection
        conn = get_connection()
        db_name = settings.MONGODB_SETTINGS["db"]
        db = conn[db_name]
        collections = db.list_collection_names()
        
        logger.info(f"MongoDB connection successful. Collections: {collections}")
        return f"Connected successfully to MongoDB. Found {len(collections)} collections."
    except Exception as e:
        logger.exception(f"MongoDB connection test failed: {e}")
        return f"Failed to connect to MongoDB: {str(e)}"

def fetch_okta_logs():
    """
    Task to fetch and save Okta logs
    This will be scheduled by django-q cluster
    """
    logger.info("Starting scheduled task: fetch_okta_logs")
    
    # Check if Okta credentials are configured
    if not settings.OKTA_API_TOKEN or not settings.OKTA_ORG_URL:
        logger.error("Missing required Okta credentials in settings")
        return False
    
    try:
        # Set up API endpoint and headers
        url = f"{settings.OKTA_ORG_URL}/api/v1/logs"
        headers = {
            'Authorization': f"SSWS {settings.OKTA_API_TOKEN}",
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        # Calculate last 24 hours for filtering
        since = datetime.utcnow() - timedelta(hours=24)
        since_str = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        # Query parameters
        params = {
            'since': since_str,
            'limit': 100  # Okta's max limit
        }
        
        # Make request to Okta API
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code != 200:
            logger.error(f"Failed to fetch Okta logs: {response.status_code} - {response.text}")
            return False
        
        # Process and save logs
        logs = response.json()
        counter = 0
        
        for log in logs:
            # Check if log already exists
            existing = OktaLog.objects.filter(id=log.get('id')).first()
            if not existing:
                try:
                    # Create new log entry
                    OktaLog(
                        id=log.get('id'),
                        published=log.get('published'),
                        event_type=log.get('eventType'),
                        event_type_category=log.get('eventTypeCategory', 'Other'),
                        actor_display_name=log.get('actor', {}).get('displayName'),
                        actor=log.get('actor', {}),
                        client_ip=log.get('client', {}).get('ipAddress'),
                        client=log.get('client', {}),
                        outcome=log.get('outcome', {}),
                        target=log.get('target', []),
                        raw_data=log
                    ).save()
                    counter += 1
                except Exception as e:
                    logger.exception(f"Error saving log entry: {e}")
        
        logger.info(f"Successfully fetched and saved {counter} new Okta logs")
        return True
        
    except Exception as e:
        logger.exception(f"Exception in fetch_okta_logs task: {e}")
        return False