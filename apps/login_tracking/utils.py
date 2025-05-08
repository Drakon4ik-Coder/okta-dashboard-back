import logging
from typing import Dict, Any
import os
import re
import time
from datetime import datetime, timedelta
from django.core.cache import cache
from django.conf import settings
from okta_dashboard.services.database import DatabaseService

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
                if "authenticated successfully" in line and elapsed_match:
                    try:
                        times.append(float(elapsed_match.group(1)))
                    except ValueError:
                        continue  # Skip if value isn't a proper float
    except FileNotFoundError:
        return []
    except Exception as e:
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
        logger = logging.getLogger(__name__)
        logger.error(f"Error calculating total login events: {str(e)}")
        return 0


def compute_avg_okta_login_time_from_mongo(days: int = 1) -> float | None:
    """Average time (ms) from first authentication event to session start, grouped by rootSessionId."""
    db = DatabaseService().get_collection(settings.MONGODB_SETTINGS['db'], 'okta_logs')
    cutoff = datetime.utcnow() - timedelta(days=days)

    cursor = db.find({
        'published': {'$gte': cutoff.isoformat() + 'Z'},
        'eventType': {'$in': [
            'user.authentication.auth_via_mfa',
            'user.authentication.sso',
            'user.session.start'
        ]}
    }, {
        'authenticationContext.rootSessionId': 1,
        'eventType': 1,
        'published': 1
    }).sort([
        ('authenticationContext.rootSessionId', 1),
        ('published', 1)
    ])

    sessions = {}
    durations = []
    for log in cursor:
        sid = log.get('authenticationContext', {}).get('rootSessionId')
        et = log.get('eventType')
        ts_str = log.get('published')
        if not sid or not ts_str:
            continue
        try:
            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        except ValueError:
            continue

        if et in ('user.authentication.auth_via_mfa', 'user.authentication.sso'):
            if sid not in sessions:
                sessions[sid] = ts
        elif et == 'user.session.start' and sid in sessions:
            delta = (ts - sessions.pop(sid)).total_seconds() * 1000
            if 0 < delta <= 300_000:
                durations.append(delta)

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
        return {'avg_ms': None, 'trend_value': None, 'message': 'No valid login pairs'}

    cache.set('okta_avg_login_time', {'avg_ms': current_avg, 'timestamp': int(time.time())}, timeout=3600)
    prev = cache.get('okta_previous_avg_login_time')
    cache.set('okta_previous_avg_login_time', current_avg, timeout=86400)

    trend = 0.0
    if prev:
        trend = round(((current_avg - prev) / prev) * 100, 2)

    return {'avg_ms': current_avg, 'trend_value': trend, 'timestamp': int(time.time())}
