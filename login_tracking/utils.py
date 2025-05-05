import logging
from typing import Dict, Any, Optional
import os
import re
import time
from datetime import datetime, timedelta
from django.core.cache import cache
from django.conf import settings
from OktaDashboardBackend.services.database import DatabaseService

# Use Django settings or default fallback
LOG_FILE_PATH = getattr(settings, 'LOGIN_TIME_LOG_PATH', os.getenv('LOGIN_TIME_LOG_PATH', 'logs/django.log'))

# Cache keys
AVG_LOGIN_TIME_CACHE_KEY = 'avg_login_time'
PREVIOUS_AVG_LOGIN_TIME_CACHE_KEY = 'previous_avg_login_time'
TOTAL_LOGIN_EVENTS_CACHE_KEY = 'total_login_events'

def parse_login_times_from_log(days: int = 1):
    """Parse authenticationElapsedTime values from the log file within the last `days`."""
    elapsed_time_pattern = re.compile(r'authenticationElapsedTime[\'"]?\s*[:=]\s*([0-9.]+)')
    timestamp_pattern = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')
    cutoff = datetime.utcnow() - timedelta(days=days)
    times = []

    try:
        # Using 'errors="replace"' to handle encoding issues by replacing invalid characters
        with open(LOG_FILE_PATH, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                timestamp_match = timestamp_pattern.search(line)
                if timestamp_match:
                    try:
                        log_time = datetime.strptime(timestamp_match.group(1), '%Y-%m-%dT%H:%M:%S')
                        if log_time < cutoff:
                            continue
                    except ValueError:
                        continue  # Skip lines with malformed timestamp

                elapsed_match = elapsed_time_pattern.search(line)

                # Only process lines that show successful authentication
                if "authenticated successfully" in line and elapsed_match:
                    try:
                        times.append(float(elapsed_match.group(1)))
                    except ValueError:
                        continue  # Skip if value isn't a proper float
    except FileNotFoundError:
        # If log file doesn't exist, return empty list
        return []
    except Exception as e:
        # Log other errors but continue with empty list
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error reading login times from log: {str(e)}")
        return []

    return times

def compute_avg_okta_login_time(days: int = 1) -> float | None:
    durations = parse_login_times_from_log(days)
    if not durations:
        return None
    return sum(durations) / len(durations)

def calculate_and_cache_avg_login_time(days: int = 1) -> float | None:
    avg = compute_avg_okta_login_time(days)
    if avg is None:
        return None

    current = cache.get(AVG_LOGIN_TIME_CACHE_KEY)
    if current and 'avg_ms' in current:
        cache.set(PREVIOUS_AVG_LOGIN_TIME_CACHE_KEY,
                  current['avg_ms'],
                  timeout=24 * 3600)

    avg_rounded = round(avg, 2)
    cache.set(AVG_LOGIN_TIME_CACHE_KEY, {
        'avg_ms': avg_rounded,
        'timestamp': int(time.time()),
    }, timeout=610)
    return avg_rounded

def get_cached_avg_login_time(days: int = 1):
    data = cache.get(AVG_LOGIN_TIME_CACHE_KEY)
    if data is None:
        avg = calculate_and_cache_avg_login_time(days)
        # Return 0 instead of None for avg_ms to ensure JavaScript can process it
        return {'avg_ms': 0 if avg is None else avg, 'timestamp': int(time.time()), 'trend_value': 0}

    # Ensure avg_ms is not None before calculating trend
    if data.get('avg_ms') is None:
        data['avg_ms'] = 0
        
    prev = cache.get(PREVIOUS_AVG_LOGIN_TIME_CACHE_KEY)
    trend = 0
    if prev:
        try:
            trend = ((data['avg_ms'] - prev) / prev) * 100
        except ZeroDivisionError:
            trend = 0
    data['trend_value'] = round(trend, 2)
    return data

def calculate_total_login_events(days: int = 30) -> int:
    """
    Calculate the total number of login events (user.session.start) from MongoDB
    for the specified number of days.
    
    Args:
        days: Number of days to look back (default: 30)
        
    Returns:
        Total count of login events
    """
    try:
        # Check cache first to avoid frequent database queries
        cache_key = f"{TOTAL_LOGIN_EVENTS_CACHE_KEY}_{days}"
        cached_data = cache.get(cache_key)
        if cached_data is not None:
            return cached_data
        
        # Get MongoDB collection
        db_service = DatabaseService()
        db_name = settings.MONGODB_SETTINGS.get('db', 'okta_dashboard')
        logs_collection = db_service.get_collection(db_name, 'okta_logs')
        
        # Calculate the date threshold
        date_threshold = datetime.utcnow() - timedelta(days=days)
        
        # Create the query filter
        query_filter = {
            'eventType': 'user.session.start',
            'published': {'$gte': date_threshold.isoformat() + 'Z'}
        }
        
        # Count documents matching the filter
        total_count = logs_collection.count_documents(query_filter)
        
        # Cache the result for 1 hour (3600 seconds)
        cache.set(cache_key, total_count, timeout=3600)
        
        return total_count
    except Exception as e:
        # Log the error but don't crash
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error calculating total login events: {str(e)}")
        return 0

def compute_avg_okta_login_time_from_mongo(days=1):
    db = DatabaseService().get_collection(settings.MONGODB_SETTINGS['db'], 'okta_logs')
    cutoff = datetime.utcnow() - timedelta(days=days)

    query_filter = {
        "eventType": {"$in": ["app.oauth2.authorize.code", "user.session.start"]},
        "outcome.result": "SUCCESS",
        "_published_date": {"$gte": cutoff}
    }

    logs = list(db.find(query_filter).sort([("actor.id", 1), ("_published_date", 1)]))

    last_auth_time = {}
    durations = []

    for log in logs:
        actor_id = log.get("actor", {}).get("id")
        ts = log.get("_published_date")

        if not actor_id or not ts:
            continue

        if log["eventType"] == "app.oauth2.authorize.code":
            last_auth_time[actor_id] = ts
        elif log["eventType"] == "user.session.start" and actor_id in last_auth_time:
            delta = (ts - last_auth_time[actor_id]).total_seconds() * 1000
            if 0 < delta <= 300000:
                durations.append(delta)
            last_auth_time.pop(actor_id, None)

    return round(sum(durations) / len(durations), 2) if durations else None

def calculate_and_cache_okta_avg_login_time(days: int = 1) -> Dict[str, Any]:
    """
    Calculate average Okta login time and store it in cache with trend tracking.

    Args:
        days: Lookback period for calculation.

    Returns:
        Dict containing current average, previous average, and trend.
    """
    current_avg = compute_avg_okta_login_time_from_mongo(days)

    if current_avg is None:
        return {"avg_ms": None, "trend_value": None, "message": "No valid login pairs"}

    # Save current value in cache
    cache.set("okta_avg_login_time", {
        "avg_ms": current_avg,
        "timestamp": int(time.time())
    }, timeout=3600)

    # Load previous value
    previous_avg = cache.get("okta_previous_avg_login_time")

    # Store current as "previous" for next cycle
    cache.set("okta_previous_avg_login_time", current_avg, timeout=86400)

    trend = 0.0
    if previous_avg:
        trend = round(((current_avg - previous_avg) / previous_avg) * 100, 2)

    return {
        "avg_ms": current_avg,
        "trend_value": trend,
        "timestamp": int(time.time())
    }