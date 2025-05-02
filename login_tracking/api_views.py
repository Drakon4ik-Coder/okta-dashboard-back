import hmac
import hashlib

from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.response import Response

from traffic_analysis.models import OktaEvent
from login_tracking.models import LoginTiming
from login_tracking.utils import compute_avg_okta_login_time, get_cached_avg_login_time


@api_view(['POST'])
@permission_classes([AllowAny])
def okta_event_hook(request):
    """
    Webhook endpoint for Okta to POST authentication events.
    Verifies HMAC signature, persists events into Mongo.
    """
    signature = request.headers.get('X-Okta-Event-Hook-Signature', '')
    expected = hmac.new(
        settings.OKTA_EVENT_HOOK_SECRET.encode(),
        request.body,
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return Response(status=401)

    for raw in request.data.get('events', []):
        evt = OktaEvent.from_syslog(raw)
        evt.save()
    return Response(status=204)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def okta_login_time(request):
    """
    Compute average login time (ms) over the past N days from OktaEvent.
    Admin only.
    """
    days = int(request.query_params.get('days', 1))
    avg = compute_avg_okta_login_time(days)
    if avg is None:
        return Response({'avg_login_ms': None, 'message': 'No events found.'}, status=204)
    return Response({'avg_login_ms': round(avg, 1)})


@api_view(['GET'])
@permission_classes([IsAdminUser])
def avg_login_time(request):
    """
    Returns the average login timing (ms) stored in SQL from LoginTiming model.
    Admin only.
    """
    from django.db.models import Avg
    avg = LoginTiming.objects.aggregate(avg_ms=Avg('duration_ms'))['avg_ms'] or 0.0
    return Response({'avg_login_ms': round(avg, 2)})


@api_view(['GET'])
@permission_classes([AllowAny])
def cached_avg_login_time(request):
    """
    Returns the cached average login time and trend data.
    Public endpoint.
    """
    cache_data = get_cached_avg_login_time()
    return Response({
        'avg_login_ms': cache_data['avg_ms'],
        'last_updated': cache_data['timestamp'],
        'trend_value': cache_data.get('trend_value', 0)
    })
