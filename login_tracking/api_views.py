from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser, IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.db.models import Avg
from .models import LoginTiming
from .metrics import get_cached_avg_login_time

@api_view(['GET'])
@permission_classes([IsAdminUser])
def avg_login_time(request):
    """
    Returns the average login timing in milliseconds.
    """
    avg = LoginTiming.objects.aggregate(avg_ms=Avg('duration_ms'))['avg_ms'] or 0.0
    return Response({'avg_login_ms': round(avg, 2)})

@api_view(['GET'])
@permission_classes([AllowAny])  # Allow access to all users, authenticated or not
def cached_avg_login_time(request):
    """
    Returns the cached average login time data.
    This endpoint is available to all users as it contains non-sensitive dashboard data.
    """
    cache_data = get_cached_avg_login_time()
    
    # Return data including the trend value
    return Response({
        'avg_login_ms': cache_data['avg_ms'],
        'last_updated': cache_data['timestamp'],
        'trend_value': cache_data.get('trend_value', 0)
    })