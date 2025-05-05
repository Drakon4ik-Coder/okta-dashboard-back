import datetime
import logging
from typing import Dict, List, Any, Optional, Union, Tuple
from OktaDashboardBackend.services.database import DatabaseService

logger = logging.getLogger(__name__)

def get_device_statistics(days: int = 30) -> Dict[str, int]:
    """
    Get device statistics from login events (user.session.start) from the last specified number of days.
    
    Args:
        days (int): Number of days to look back (default: 30)
        
    Returns:
        Dict[str, int]: Count of login events grouped by device type
    """
    try:
        # Get database connection
        db_service = DatabaseService()
        
        # Get the collection where Okta logs are stored
        collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
        
        # Calculate the date threshold (N days ago from now)
        now = datetime.datetime.now(datetime.timezone.utc)
        threshold_date = now - datetime.timedelta(days=days)
        
        # MongoDB aggregation pipeline
        pipeline = [
            # Match documents where eventType is user.session.start
            {"$match": {"eventType": "user.session.start"}},
            
            # Group by device
            {"$group": {
                "_id": "$client.device",
                "count": {"$sum": 1}
            }},
            
            # Sort by count descending
            {"$sort": {"count": -1}}
        ]
        
        # Execute the aggregation
        results = list(collection.aggregate(pipeline))
        
        # Convert the results to a dictionary
        device_stats = {}
        for result in results:
            device_type = result["_id"] if result["_id"] else "Unknown"
            device_stats[device_type] = result["count"]
        
        return device_stats
        
    except Exception as e:
        logger.error(f"Error getting device statistics: {str(e)}", exc_info=True)
        return {"Error": 0}

def get_operating_system_statistics(days: int = 30) -> Dict[str, int]:
    """
    Get operating system statistics from login events from the last specified number of days.
    
    Args:
        days (int): Number of days to look back (default: 30)
        
    Returns:
        Dict[str, int]: Count of login events grouped by operating system
    """
    try:
        # Get database connection
        db_service = DatabaseService()
        
        # Get the collection where Okta logs are stored
        collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
        
        # Calculate the date threshold (N days ago from now)
        now = datetime.datetime.now(datetime.timezone.utc)
        threshold_date = now - datetime.timedelta(days=days)
        
        # MongoDB aggregation pipeline
        pipeline = [
            # Match documents where eventType is user.session.start
            {"$match": {"eventType": "user.session.start"}},
            
            # Group by operating system
            {"$group": {
                "_id": "$client.userAgent.os",
                "count": {"$sum": 1}
            }},
            
            # Sort by count descending
            {"$sort": {"count": -1}}
        ]
        
        # Execute the aggregation
        results = list(collection.aggregate(pipeline))
        
        # Convert the results to a dictionary
        os_stats = {}
        for result in results:
            os_type = result["_id"] if result["_id"] else "Unknown"
            os_stats[os_type] = result["count"]
        
        return os_stats
        
    except Exception as e:
        logger.error(f"Error getting operating system statistics: {str(e)}", exc_info=True)
        return {"Error": 0}

def get_browser_statistics(days: int = 30) -> Dict[str, int]:
    """
    Get browser statistics from login events from the last specified number of days.
    
    Args:
        days (int): Number of days to look back (default: 30)
        
    Returns:
        Dict[str, int]: Count of login events grouped by browser
    """
    try:
        # Get database connection
        db_service = DatabaseService()
        
        # Get the collection where Okta logs are stored
        collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
        
        # Calculate the date threshold (N days ago from now)
        now = datetime.datetime.now(datetime.timezone.utc)
        threshold_date = now - datetime.timedelta(days=days)
        
        # MongoDB aggregation pipeline
        pipeline = [
            # Match documents where eventType is user.session.start
            {"$match": {"eventType": "user.session.start"}},
            
            # Group by browser
            {"$group": {
                "_id": "$client.userAgent.browser",
                "count": {"$sum": 1}
            }},
            
            # Sort by count descending
            {"$sort": {"count": -1}}
        ]
        
        # Execute the aggregation
        results = list(collection.aggregate(pipeline))
        
        # Convert the results to a dictionary
        browser_stats = {}
        for result in results:
            browser_type = result["_id"] if result["_id"] else "Unknown"
            browser_stats[browser_type] = result["count"]
        
        return browser_stats
        
    except Exception as e:
        logger.error(f"Error getting browser statistics: {str(e)}", exc_info=True)
        return {"Error": 0}

def get_application_statistics(days: int = 30) -> Dict[str, int]:
    """
    Get application statistics from login events from the last specified number of days.
    
    Args:
        days (int): Number of days to look back (default: 30)
        
    Returns:
        Dict[str, int]: Count of login events grouped by application
    """
    try:
        # Get database connection
        db_service = DatabaseService()
        
        # Get the collection where Okta logs are stored
        collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
        
        # Calculate the date threshold (N days ago from now)
        now = datetime.datetime.now(datetime.timezone.utc)
        threshold_date = now - datetime.timedelta(days=days)
        
        # MongoDB aggregation pipeline for application statistics
        pipeline = [
            # Match documents where eventType is user.session.start
            {"$match": {"eventType": "user.session.start"}},
            
            # Unwind the target array to access each target
            {"$unwind": "$target"},
            
            # Match targets of type AppInstance
            {"$match": {"target.type": "AppInstance"}},
            
            # Group by application display name
            {"$group": {
                "_id": "$target.displayName",
                "count": {"$sum": 1}
            }},
            
            # Sort by count descending
            {"$sort": {"count": -1}}
        ]
        
        # Execute the aggregation
        results = list(collection.aggregate(pipeline))
        
        # Convert the results to a dictionary
        app_stats = {}
        for result in results:
            app_name = result["_id"] if result["_id"] else "Unknown"
            app_stats[app_name] = result["count"]
        
        return app_stats
        
    except Exception as e:
        logger.error(f"Error getting application statistics: {str(e)}", exc_info=True)
        return {"Error": 0}

def get_login_location_statistics(days: int = 30) -> Dict[str, int]:
    """
    Get login location statistics from login events from the last specified number of days.
    
    Args:
        days (int): Number of days to look back (default: 30)
        
    Returns:
        Dict[str, int]: Count of login events grouped by location (country)
    """
    try:
        # Get database connection
        db_service = DatabaseService()
        
        # Get the collection where Okta logs are stored
        collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
        
        # Calculate the date threshold (N days ago from now)
        now = datetime.datetime.now(datetime.timezone.utc)
        threshold_date = now - datetime.timedelta(days=days)
        
        # MongoDB aggregation pipeline
        pipeline = [
            # Match documents where eventType is user.session.start
            {"$match": {"eventType": "user.session.start"}},
            
            # Group by country
            {"$group": {
                "_id": "$client.geographicalContext.country",
                "count": {"$sum": 1}
            }},
            
            # Sort by count descending
            {"$sort": {"count": -1}}
        ]
        
        # Execute the aggregation
        results = list(collection.aggregate(pipeline))
        
        # Convert the results to a dictionary
        location_stats = {}
        for result in results:
            country = result["_id"] if result["_id"] else "Unknown"
            location_stats[country] = result["count"]
        
        return location_stats
        
    except Exception as e:
        logger.error(f"Error getting location statistics: {str(e)}", exc_info=True)
        return {"Error": 0}

def get_login_outcome_statistics(days: int = 30) -> Dict[str, int]:
    """
    Get login outcome statistics from login events from the last specified number of days.
    
    Args:
        days (int): Number of days to look back (default: 30)
        
    Returns:
        Dict[str, Dict[str, int]]: Count of login events grouped by outcome result and reason
    """
    try:
        # Get database connection
        db_service = DatabaseService()
        
        # Get the collection where Okta logs are stored
        collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
        
        # Calculate the date threshold (N days ago from now)
        now = datetime.datetime.now(datetime.timezone.utc)
        threshold_date = now - datetime.timedelta(days=days)
        
        # MongoDB aggregation pipeline
        pipeline = [
            # Match documents where eventType is user.session.start
            {"$match": {"eventType": "user.session.start"}},
            
            # Group by outcome result and reason
            {"$group": {
                "_id": {
                    "result": "$outcome.result",
                    "reason": "$outcome.reason"
                },
                "count": {"$sum": 1}
            }},
            
            # Sort by count descending
            {"$sort": {"count": -1}}
        ]
        
        # Execute the aggregation
        results = list(collection.aggregate(pipeline))
        
        # Convert the results to a dictionary
        outcome_stats = {"results": {}, "reasons": {}}
        
        # Process results to separate outcomes and reasons
        for result in results:
            outcome_result = result["_id"]["result"] if result["_id"]["result"] else "Unknown"
            outcome_reason = result["_id"]["reason"] if result["_id"]["reason"] else "Unknown"
            
            # Add to results dictionary
            if outcome_result in outcome_stats["results"]:
                outcome_stats["results"][outcome_result] += result["count"]
            else:
                outcome_stats["results"][outcome_result] = result["count"]
                
            # Add to reasons dictionary
            if outcome_reason in outcome_stats["reasons"]:
                outcome_stats["reasons"][outcome_reason] += result["count"]
            else:
                outcome_stats["reasons"][outcome_reason] = result["count"]
        
        return outcome_stats
        
    except Exception as e:
        logger.error(f"Error getting outcome statistics: {str(e)}", exc_info=True)
        return {"results": {"Error": 0}, "reasons": {"Error": 0}}

def get_all_statistics(days: int = 30) -> Dict[str, Any]:
    """
    Get all statistics from login events from the last specified number of days.
    
    Args:
        days (int): Number of days to look back (default: 30)
        
    Returns:
        Dict[str, Any]: All statistics in one dictionary
    """
    return {
        "devices": get_device_statistics(days),
        "operating_systems": get_operating_system_statistics(days),
        "browsers": get_browser_statistics(days),
        "applications": get_application_statistics(days),
        "locations": get_login_location_statistics(days),
        "outcomes": get_login_outcome_statistics(days)
    }