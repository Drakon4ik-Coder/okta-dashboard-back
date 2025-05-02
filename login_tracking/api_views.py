# login_tracking/api_views.py
import hmac, hashlib
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.response import Response
from traffic_analysis.models import OktaEvent
from .utils import compute_avg_okta_login_time, get_cached_avg_login_time

@api_view(['POST'])
@permission_classes([AllowAny])
def okta_event_hook(request):
    sig = request.headers.get('X-Okta-Event-Hook-Signature', '')
    expected = hmac.new(
        settings.OKTA_EVENT_HOOK_SECRET.encode(),
        request.body,
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return Response(status=401)

    for raw in request.data.get('events', []):
        evt = OktaEvent.from_syslog(raw)
        evt.save()
    return Response(status=204)

@api_view(['GET'])
@permission_classes([IsAdminUser])
def okta_login_time(request):
    days = int(request.query_params.get('days', 1))
    avg = compute_avg_okta_login_time(days)
    if avg is None:
        return Response({'avg_login_ms': None, 'message': 'No events found.'}, status=204)
    return Response({'avg_login_ms': round(avg, 1)})

@api_view(['GET'])
@permission_classes([AllowAny])
def cached_okta_login_time(request):
    days = int(request.query_params.get('days', 1))
    data = get_cached_avg_login_time(days)
    return Response({
        'avg_login_ms': data['avg_ms'],
        'last_updated': data['timestamp'],
        'trend_value': data['trend_value'],
    })
