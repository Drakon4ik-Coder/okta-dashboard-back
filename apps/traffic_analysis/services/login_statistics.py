import datetime
import logging
from okta_dashboard.services.database import DatabaseService  # Updated import path

logger = logging.getLogger(__name__)

def get_login_events_count(days=30):
    """
    Get the count of successful login events from the last specified number of days.
    
    Args:
        days (int): Number of days to look back (default: 30)
        
    Returns:
        int: Count of successful login events
    """
    try:
        # Get database connection
        db_service = DatabaseService()
        
        # Get the collection where Okta logs are stored
        collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
        
        # Get total count first to check if we have data at all
        total_events = collection.count_documents({})
        logger.info(f"Total events in collection: {total_events}")
        
        # If we have no documents, return 0
        if total_events == 0:
            return 0
        
        # Calculate the date threshold (N days ago from now)
        now = datetime.datetime.now(datetime.timezone.utc)
        threshold_date = now - datetime.timedelta(days=days)
        
        # Get all login events regardless of date to understand what we have
        all_login_events = collection.count_documents({
            'eventType': 'user.session.start',
            'outcome.result': 'SUCCESS'
        })
        logger.info(f"All successful login events (without date filtering): {all_login_events}")
        
        # Try different date query approaches
        # First try with datetime objects
        query1 = {
            'eventType': 'user.session.start', 
            'outcome.result': 'SUCCESS',
            '_published_date': {'$gte': threshold_date}
        }
        count1 = collection.count_documents(query1)
        logger.info(f"Query with datetime object: {count1}")
        
        # If above didn't work, try with ISO string
        query2 = {
            'eventType': 'user.session.start', 
            'outcome.result': 'SUCCESS',
            'published': {'$gte': threshold_date.isoformat()}
        }
        count2 = collection.count_documents(query2)
        logger.info(f"Query with ISO format on 'published': {count2}")
        
        # Try with string comparison on the original published field
        query3 = {
            'eventType': 'user.session.start', 
            'outcome.result': 'SUCCESS'
        }
        count3 = 0
        for doc in collection.find(query3):
            # Extract published date from document
            published_str = doc.get('published')
            if not published_str:
                continue
                
            try:
                # Parse the date and compare
                published_date = datetime.datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                if published_date >= threshold_date:
                    count3 += 1
            except (ValueError, AttributeError):
                logger.warning(f"Could not parse date: {published_str}")
        
        logger.info(f"Manual date comparison: {count3}")
        
        # Return the highest count from our different approaches
        final_count = max(count1, count2, count3, 0)
        
        # If we still have 0, just return all login events as a fallback
        if final_count == 0 and all_login_events > 0:
            logger.warning("Date filtering failed, returning all login events as fallback")
            return all_login_events
            
        return final_count
        
    except Exception as e:
        logger.error(f"Error getting login events count: {str(e)}", exc_info=True)
        return 0

def get_failed_login_count(days=30):
    """
    Get the count of failed login attempts from the last specified number of days.
    
    Args:
        days (int): Number of days to look back (default: 30)
        
    Returns:
        int: Count of failed login attempts
    """
    try:
        # Get database connection
        db_service = DatabaseService()
        
        # Get the collection where Okta logs are stored
        collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
        
        # Get total count first to check if we have data at all
        total_events = collection.count_documents({})
        logger.info(f"Total events in collection: {total_events}")
        
        # If we have no documents, return 0
        if total_events == 0:
            return 0
        
        # Calculate the date threshold (N days ago from now)
        now = datetime.datetime.now(datetime.timezone.utc)
        threshold_date = now - datetime.timedelta(days=days)
        
        # Get all failed login events regardless of date to understand what we have
        all_failed_logins = collection.count_documents({
            'eventType': 'user.session.start',
            'outcome.result': 'FAILURE'
        })
        logger.info(f"All failed login attempts (without date filtering): {all_failed_logins}")
        
        # Try different date query approaches
        # First try with datetime objects
        query1 = {
            'eventType': 'user.session.start', 
            'outcome.result': 'FAILURE',
            '_published_date': {'$gte': threshold_date}
        }
        count1 = collection.count_documents(query1)
        logger.info(f"Query with datetime object: {count1}")
        
        # If above didn't work, try with ISO string
        query2 = {
            'eventType': 'user.session.start', 
            'outcome.result': 'FAILURE',
            'published': {'$gte': threshold_date.isoformat()}
        }
        count2 = collection.count_documents(query2)
        logger.info(f"Query with ISO format on 'published': {count2}")
        
        # Try with string comparison on the original published field
        query3 = {
            'eventType': 'user.session.start', 
            'outcome.result': 'FAILURE'
        }
        count3 = 0
        for doc in collection.find(query3):
            # Extract published date from document
            published_str = doc.get('published')
            if not published_str:
                continue
                
            try:
                # Parse the date and compare
                published_date = datetime.datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                if published_date >= threshold_date:
                    count3 += 1
            except (ValueError, AttributeError):
                logger.warning(f"Could not parse date: {published_str}")
        
        logger.info(f"Manual date comparison: {count3}")
        
        # Return the highest count from our different approaches
        final_count = max(count1, count2, count3, 0)
        
        # If we still have 0, just return all failed login events as a fallback
        if final_count == 0 and all_failed_logins > 0:
            logger.warning("Date filtering failed, returning all failed login events as fallback")
            return all_failed_logins
            
        return final_count
        
    except Exception as e:
        logger.error(f"Error getting failed login count: {str(e)}", exc_info=True)
        return 0

def get_security_events_count(days=30):
    """
    Get the count of security events from the last specified number of days.
    
    Args:
        days (int): Number of days to look back (default: 30)
        
    Returns:
        int: Count of security events
    """
    try:
        # Get database connection
        db_service = DatabaseService()
        
        # Get the collection where Okta logs are stored
        collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
        
        # Get total count first to check if we have data at all
        total_events = collection.count_documents({})
        logger.info(f"Total events in collection: {total_events}")
        
        # If we have no documents, return 0
        if total_events == 0:
            return 0
        
        # Calculate the date threshold (N days ago from now)
        now = datetime.datetime.now(datetime.timezone.utc)
        threshold_date = now - datetime.timedelta(days=days)
        
        # Get all security events regardless of date to understand what we have
        all_security_events = collection.count_documents({
            'eventType': {'$regex': 'security|threat'},
        })
        logger.info(f"All security events (without date filtering): {all_security_events}")
        
        # Try different date query approaches
        # First try with datetime objects
        query1 = {
            'eventType': {'$regex': 'security|threat'},
            '_published_date': {'$gte': threshold_date}
        }
        count1 = collection.count_documents(query1)
        logger.info(f"Query with datetime object: {count1}")
        
        # If above didn't work, try with ISO string
        query2 = {
            'eventType': {'$regex': 'security|threat'},
            'published': {'$gte': threshold_date.isoformat()}
        }
        count2 = collection.count_documents(query2)
        logger.info(f"Query with ISO format on 'published': {count2}")
        
        # Try with string comparison on the original published field
        query3 = {
            'eventType': {'$regex': 'security|threat'}
        }
        count3 = 0
        for doc in collection.find(query3):
            # Extract published date from document
            published_str = doc.get('published')
            if not published_str:
                continue
                
            try:
                # Parse the date and compare
                published_date = datetime.datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                if published_date >= threshold_date:
                    count3 += 1
            except (ValueError, AttributeError):
                logger.warning(f"Could not parse date: {published_str}")
        
        logger.info(f"Manual date comparison: {count3}")
        
        # Return the highest count from our different approaches
        final_count = max(count1, count2, count3, 0)
        
        # If we still have 0, just return all security events as a fallback
        if final_count == 0 and all_security_events > 0:
            logger.warning("Date filtering failed, returning all security events as fallback")
            return all_security_events
            
        return final_count
        
    except Exception as e:
        logger.error(f"Error getting security events count: {str(e)}", exc_info=True)
        return 0

def get_total_events_count(days=30):
    """
    Get the total count of all events from the last specified number of days.
    
    Args:
        days (int): Number of days to look back (default: 30)
        
    Returns:
        int: Count of all events
    """
    try:
        # Get database connection
        db_service = DatabaseService()
        
        # Get the collection where Okta logs are stored
        collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
        
        # Get total count first to check if we have data at all
        total_events = collection.count_documents({})
        logger.info(f"Total events in collection (overall): {total_events}")
        
        # If we have no documents, return 0
        if total_events == 0:
            return 0
        
        # Calculate the date threshold (N days ago from now)
        now = datetime.datetime.now(datetime.timezone.utc)
        threshold_date = now - datetime.timedelta(days=days)
        
        # Try different date query approaches
        # First try with datetime objects
        query1 = {
            '_published_date': {'$gte': threshold_date}
        }
        count1 = collection.count_documents(query1)
        logger.info(f"Query with datetime object: {count1}")
        
        # If above didn't work, try with ISO string
        query2 = {
            'published': {'$gte': threshold_date.isoformat()}
        }
        count2 = collection.count_documents(query2)
        logger.info(f"Query with ISO format on 'published': {count2}")
        
        # Try with string comparison on the original published field
        count3 = 0
        # Use a sample subset to avoid excessive memory usage
        sample_size = min(5000, total_events)  # Limit sample size
        
        # Process sample documents in batches
        cursor = collection.find().limit(sample_size)
        for doc in cursor:
            # Extract published date from document
            published_str = doc.get('published')
            if not published_str:
                continue
                
            try:
                # Parse the date and compare
                published_date = datetime.datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                if published_date >= threshold_date:
                    count3 += 1
            except (ValueError, AttributeError):
                logger.warning(f"Could not parse date: {published_str}")
        
        # If we only processed a sample, extrapolate to full collection
        if total_events > sample_size:
            ratio = total_events / sample_size
            count3 = int(count3 * ratio)
            
        logger.info(f"Manual date comparison (extrapolated): {count3}")
        
        # Return the highest count from our different approaches
        final_count = max(count1, count2, count3, 0)
        
        # If we still have 0 but total_events > 0, use total_events as fallback
        if final_count == 0 and total_events > 0:
            logger.warning("Date filtering failed, returning all events as fallback")
            return total_events
            
        return final_count
        
    except Exception as e:
        logger.error(f"Error getting total events count: {str(e)}", exc_info=True)
        return 0