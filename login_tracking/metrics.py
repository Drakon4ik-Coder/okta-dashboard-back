from prometheus_client import Histogram

# Histogram for login response times (ms)
login_response_time = Histogram(
    'login_response_time_ms',
    'Histogram of login response times in milliseconds',
    buckets=(50, 100, 200, 500, 1000, 2000, float('inf'))
)
