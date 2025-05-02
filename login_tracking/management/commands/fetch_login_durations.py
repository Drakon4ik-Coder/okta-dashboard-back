import os, requests
from django.core.management.base import BaseCommand
from django.conf import settings
from login_tracking.models import LoginTiming
from datetime import datetime, timedelta

class Command(BaseCommand):
    help = "Fetch recent Okta login events and store durations"

    def handle(self, *args, **opts):
        # 1) get token via client‑credentials (Service app)
        token_resp = requests.post(
            settings.OKTA_TOKEN_ENDPOINT,
            data={"grant_type": "client_credentials", "scope": "okta.systemLogs.read"},
            auth=(settings.OKTA_CLIENT_ID, settings.OKTA_CLIENT_SECRET),
            timeout=10,
        )
        token_resp.raise_for_status()
        token = token_resp.json()["access_token"]

        # 2) fetch last 5 minutes of logs filtered to authentication
        since = (datetime.utcnow() - timedelta(minutes=5)).isoformat() + "Z"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        params = {
            "filter": 'eventType eq "user.authentication.authenticate"',
            "since": since,
            "limit": 200
        }
        resp = requests.get(
            settings.OKTA_ORG_URL + "/api/v1/logs", headers=headers, params=params, timeout=10
        )
        resp.raise_for_status()
        events = resp.json()

        count = 0
        for e in events:
            dbg = e.get("debugContext", {}).get("debugData", {})
            if "authenticationElapsedTime" in dbg:
                ms = float(dbg["authenticationElapsedTime"])
                ts = datetime.fromisoformat(e["published"].rstrip("Z"))
                LoginTiming.objects.create(timestamp=ts, duration_ms=ms)
                count += 1

        self.stdout.write(f"Stored {count} login durations.")
