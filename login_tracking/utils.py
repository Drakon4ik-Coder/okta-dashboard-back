from datetime import datetime, timedelta
from traffic_analysis.models import OktaEvent

def compute_avg_okta_login_time(days: int = 1) -> float | None:
    now = datetime.utcnow()
    start = now - timedelta(days=days)

    events = OktaEvent.objects(
        event_type="user.authentication.auth_via_primary_auth",
        published__gte=start,
        published__lte=now
    )

    durations = []
    for e in events:
        et = e.debug_context.get("debugData", {}).get("elapsedTime")
        if isinstance(et, (int, float)):
            durations.append(et)

    if not durations:
        return None
    return sum(durations) / len(durations)
