from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
import pytz
from login_tracking.utils import compute_avg_okta_login_time_from_mongo

def test_compute_avg_login_time():
    mock_logs = [
        # First actor's auth + session
        {"eventType": "app.oauth2.authorize.code", "actor": {"id": "user1"}, "_published_date": datetime(2025, 5, 1, 12, 0, 0, tzinfo=pytz.UTC)},
        {"eventType": "user.session.start", "actor": {"id": "user1"}, "_published_date": datetime(2025, 5, 1, 12, 0, 3, tzinfo=pytz.UTC)},

        # Second actor's auth + session
        {"eventType": "app.oauth2.authorize.code", "actor": {"id": "user2"}, "_published_date": datetime(2025, 5, 1, 13, 0, 0, tzinfo=pytz.UTC)},
        {"eventType": "user.session.start", "actor": {"id": "user2"}, "_published_date": datetime(2025, 5, 1, 13, 0, 2, tzinfo=pytz.UTC)},
    ]

    with patch('login_tracking.utils.DatabaseService') as mock_db_service:
        mock_db_instance = MagicMock()
        mock_db_instance.get_collection.return_value.find.return_value.sort.return_value = mock_logs
        mock_db_service.return_value = mock_db_instance

        avg = compute_avg_okta_login_time_from_mongo(days=1)

        # Expected: (3s + 2s) / 2 = 2.5s = 2500ms
        assert avg == 2500.0
