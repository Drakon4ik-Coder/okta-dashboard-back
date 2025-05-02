from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from django.db.models import Avg
from .models import LoginTiming

@api_view(['GET'])
@permission_classes([IsAdminUser])
def avg_login_time(request):
    """
    Returns the average login timing in milliseconds.
    """
    avg = LoginTiming.objects.aggregate(avg_ms=Avg('duration_ms'))['avg_ms'] or 0.0
    return Response({'avg_login_ms': round(avg, 2)})