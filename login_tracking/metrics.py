import time
from django.core.cache import cache
from django.db.models import Avg
from .models import LoginTiming
from prometheus_client import Histogram

# Histogram for login response times (ms)
login_response_time = Histogram(
    'login_response_time_ms',
    'Histogram of login response times in milliseconds',
    buckets=(50, 100, 200, 500, 1000, 2000, float('inf'))
)

# Cache keys
AVG_LOGIN_TIME_CACHE_KEY = 'avg_login_time'
PREVIOUS_AVG_LOGIN_TIME_CACHE_KEY = 'previous_avg_login_time'

def calculate_and_cache_avg_login_time():
    """
    Calculate average login time and store in cache with a 10-minute expiration.
    Returns the calculated average.
    """
    # Save the current value as previous before calculating new value
    current_cache_data = cache.get(AVG_LOGIN_TIME_CACHE_KEY)
    if current_cache_data is not None and 'avg_ms' in current_cache_data:
        # Store the current value as the previous value
        cache.set(PREVIOUS_AVG_LOGIN_TIME_CACHE_KEY, current_cache_data['avg_ms'], timeout=86400)  # 24 hours

    avg = LoginTiming.objects.aggregate(avg_ms=Avg('duration_ms'))['avg_ms'] or 0.0
    avg_rounded = round(avg, 2)
    
    # Store in cache with a timestamp
    cache_data = {
        'avg_ms': avg_rounded,
        'timestamp': int(time.time()),
    }
    
    # Cache for just over 10 minutes to ensure no gaps
    cache.set(AVG_LOGIN_TIME_CACHE_KEY, cache_data, timeout=610)  # 10 minutes + 10 seconds
    return avg_rounded

def get_cached_avg_login_time():
    """
    Get the cached average login time.
    If not in cache, calculate and cache it.
    """
    cache_data = cache.get(AVG_LOGIN_TIME_CACHE_KEY)
    if cache_data is None:
        # Not in cache, calculate and store
        avg = calculate_and_cache_avg_login_time()
        return {'avg_ms': avg, 'timestamp': int(time.time())}

    # Get the previous value for trend calculation
    previous_avg = cache.get(PREVIOUS_AVG_LOGIN_TIME_CACHE_KEY)
    
    # Calculate trend value
    trend_value = 0
    if previous_avg is not None and previous_avg > 0:
        trend_value = ((cache_data['avg_ms'] - previous_avg) / previous_avg) * 100

    # Add trend to returned data
    cache_data['trend_value'] = trend_value
    
    return cache_data
