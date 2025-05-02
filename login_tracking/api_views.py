import hmac
import hashlib

from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.response import Response

from traffic_analysis.models import OktaEvent
from login_tracking.utils import compute_avg_okta_login_time


@api_view(['POST'])
@permission_classes([AllowAny])
def okta_event_hook(request):
    # 1) Verify the HMAC signature header matches our shared secret
    signature = request.headers.get('X-Okta-Event-Hook-Signature', '')
    expected = hmac.new(
        settings.OKTA_EVENT_HOOK_SECRET.encode(),
        request.body,
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return Response(status=401)

    # 2) Persist each incoming event into Mongo via OktaEvent
    for raw in request.data.get('events', []):
        evt = OktaEvent.from_syslog(raw)
        evt.save()

    return Response(status=204)

@api_view(['GET'])
@permission_classes([IsAdminUser])
def okta_login_time(request):
    """
    Returns the average login time (ms) over the past N days,
    computed from your OktaEvent collection.
    """
    days = int(request.query_params.get('days', 1))
    avg  = compute_avg_okta_login_time(days)
    if avg is None:
        return Response({'avg_login_ms': None, 'message': 'No events found.'}, status=204)
    return Response({'avg_login_ms': round(avg, 1)})
