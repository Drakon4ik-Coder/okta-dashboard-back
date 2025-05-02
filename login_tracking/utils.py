# login_tracking/utils.py
from datetime import datetime, timedelta
from traffic_analysis.models import OktaEvent
import time
from django.core.cache import cache

# cache keys
AVG_LOGIN_TIME_CACHE_KEY = 'avg_login_time'
PREVIOUS_AVG_LOGIN_TIME_CACHE_KEY = 'previous_avg_login_time'

def compute_avg_okta_login_time(days: int = 1) -> float | None:
    now   = datetime.utcnow()
    start = now - timedelta(days=days)

    events = OktaEvent.objects(
        event_type="user.authentication.auth_via_primary_auth",
        published__gte=start,
        published__lte=now
    )

    durations = [
        e.debug_context.get("debugData", {}).get("elapsedTime")
        for e in events
        if isinstance(e.debug_context.get("debugData", {}).get("elapsedTime"), (int, float))
    ]

    if not durations:
        return None
    return sum(durations) / len(durations)

def calculate_and_cache_avg_login_time(days: int = 1) -> float | None:
    avg = compute_avg_okta_login_time(days)
    if avg is None:
        return None

    # shift current → previous
    current = cache.get(AVG_LOGIN_TIME_CACHE_KEY)
    if current and 'avg_ms' in current:
        cache.set(PREVIOUS_AVG_LOGIN_TIME_CACHE_KEY,
                  current['avg_ms'],
                  timeout=24*3600)

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
        trend = ((data['avg_ms'] - prev) / prev) * 100
    data['trend_value'] = round(trend, 2)
    return data
