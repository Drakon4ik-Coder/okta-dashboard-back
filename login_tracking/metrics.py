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
    Calculate average login time and store in cache with a 10‑minute expiration.
    Returns the calculated average (rounded to 2 decimals).
    """
    # Before overwriting, move current → previous
    current = cache.get(AVG_LOGIN_TIME_CACHE_KEY)
    if current and 'avg_ms' in current:
        cache.set(PREVIOUS_AVG_LOGIN_TIME_CACHE_KEY,
                  current['avg_ms'],
                  timeout=24 * 3600)  # keep previous for 24 h

    # Compute fresh average
    avg = LoginTiming.objects.aggregate(avg_ms=Avg('duration_ms'))['avg_ms'] or 0.0
    avg_rounded = round(avg, 2)

    # Cache new value + timestamp
    cache_data = {
        'avg_ms': avg_rounded,
        'timestamp': int(time.time()),
    }
    cache.set(AVG_LOGIN_TIME_CACHE_KEY, cache_data, timeout=610)  # 10 min + 10 s

    return avg_rounded

def get_cached_avg_login_time():
    """
    Return cached average login time plus trend. If missing, recalculate.
    """
    data = cache.get(AVG_LOGIN_TIME_CACHE_KEY)
    if data is None:
        # no cached value → compute & cache
        avg = calculate_and_cache_avg_login_time()
        return {'avg_ms': avg, 'timestamp': int(time.time()), 'trend_value': 0}

    # calculate trend vs previous
    prev = cache.get(PREVIOUS_AVG_LOGIN_TIME_CACHE_KEY)
    trend = 0
    if prev is not None and prev > 0:
        trend = ((data['avg_ms'] - prev) / prev) * 100

    data['trend_value'] = round(trend, 2)
    return data
