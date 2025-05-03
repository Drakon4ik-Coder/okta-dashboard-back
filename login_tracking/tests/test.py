import unittest
import time

from unittest.mock import mock_open, patch
from datetime import datetime

from login_tracking.utils import parse_login_times_from_log, compute_avg_okta_login_time
from login_tracking.utils import get_cached_avg_login_time, calculate_and_cache_avg_login_time
from django.core.cache import cache

SAMPLE_LOG_CONTENT = """
2025-05-02T10:15:30 INFO User Stepan authenticated successfully. authenticationElapsedTime: 120.5
2025-05-02T11:45:02 INFO User Stepan authenticated successfully. authenticationElapsedTime: 150.0
2025-04-30T09:12:10 INFO User Stepan authenticated successfully. authenticationElapsedTime: 200.2
2025-05-02T12:01:55 WARNING Failed login attempt for username 'Stepan'. authenticationElapsedTime: 110.3
"""

class TestLoginTimeParsing(unittest.TestCase):
    @patch('login_tracking.utils.open', new_callable=mock_open, read_data=SAMPLE_LOG_CONTENT)
    @patch('login_tracking.utils.datetime')
    def test_parse_and_compute_avg(self, mock_datetime, mock_file):
        mock_datetime.utcnow.return_value = datetime(2025, 5, 3)
        mock_datetime.strptime = datetime.strptime

        durations = parse_login_times_from_log(days=1)
        self.assertEqual(len(durations), 2)
        self.assertIn(120.5, durations)
        self.assertIn(150.0, durations)
        self.assertNotIn(110.3, durations)

        avg = compute_avg_okta_login_time(days=1)
        expected_avg = round((120.5 + 150.0) / 2, 2)
        self.assertEqual(round(avg, 2), expected_avg)

class TestLoginTimeCaching(unittest.TestCase):
    @patch('login_tracking.utils.open', new_callable=mock_open, read_data=SAMPLE_LOG_CONTENT)
    @patch('login_tracking.utils.datetime')
    def test_cached_avg_login_time(self, mock_datetime, mock_file):
        mock_datetime.utcnow.return_value = datetime(2025, 5, 3)
        mock_datetime.strptime = datetime.strptime

        # Clear the cache
        cache.clear()

        # First call should compute and store in cache
        result = get_cached_avg_login_time(days=1)
        self.assertIn('avg_ms', result)
        self.assertIn('trend_value', result)
        self.assertAlmostEqual(result['avg_ms'], round((120.5 + 150.0) / 2, 2))
        self.assertEqual(result['trend_value'], 0)

        # Simulate a future average to test trend
        cache.set('avg_login_time', {'avg_ms': 100.0, 'timestamp': int(time.time())})
        cache.set('previous_avg_login_time', 125.0)

        result = get_cached_avg_login_time(days=1)
        self.assertIn('trend_value', result)
        self.assertAlmostEqual(result['trend_value'], ((100.0 - 125.0) / 125.0) * 100, places=2)