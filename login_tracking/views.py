from django.http import JsonResponse
from login_tracking.utils import get_cached_avg_login_time

def avg_login_time_api(request):
    return JsonResponse(get_cached_avg_login_time())
