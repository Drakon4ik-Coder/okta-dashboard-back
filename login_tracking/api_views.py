# login_tracking/api_views.py
import hmac, hashlib
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.response import Response
from traffic_analysis.models import OktaEvent
from .utils import compute_avg_okta_login_time, get_cached_avg_login_time

@api_view(['GET'])
@permission_classes([IsAdminUser])
def okta_login_time(request):
    days = int(request.query_params.get('days', 1))
    avg = compute_avg_okta_login_time(days)
    if avg is None:
        return Response({'avg_ms': None, 'message': 'No events found.'}, status=204)
    return Response({'avg_ms': round(avg, 1)})

@api_view(['GET'])
@permission_classes([AllowAny])
def cached_okta_login_time(request):
    days = int(request.query_params.get('days', 1))
    data = get_cached_avg_login_time(days)
    return Response({
        'avg_ms': data['avg_ms'],
        'last_updated': data['timestamp'],
        'trend_value': data['trend_value'],
    })
