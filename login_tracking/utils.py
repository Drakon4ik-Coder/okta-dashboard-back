import os
import re
import time
from datetime import datetime, timedelta
from django.core.cache import cache
from django.conf import settings

# Use Django settings or default fallback
LOG_FILE_PATH = getattr(settings, 'LOGIN_TIME_LOG_PATH', os.getenv('LOGIN_TIME_LOG_PATH', 'logs/django.log'))

# Cache keys
AVG_LOGIN_TIME_CACHE_KEY = 'avg_login_time'
PREVIOUS_AVG_LOGIN_TIME_CACHE_KEY = 'previous_avg_login_time'

def parse_login_times_from_log(days: int = 1):
    """Parse authenticationElapsedTime values from the log file within the last `days`."""
    elapsed_time_pattern = re.compile(r'authenticationElapsedTime[\'"]?\s*[:=]\s*([0-9.]+)')
    timestamp_pattern = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')
    cutoff = datetime.utcnow() - timedelta(days=days)
    times = []

    try:
        with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f:
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
        return {'avg_ms': avg, 'timestamp': int(time.time()), 'trend_value': 0}

    prev = cache.get(PREVIOUS_AVG_LOGIN_TIME_CACHE_KEY)
    trend = 0
    if prev:
        try:
            trend = ((data['avg_ms'] - prev) / prev) * 100
        except ZeroDivisionError:
            trend = 0
    data['trend_value'] = round(trend, 2)
    return data
