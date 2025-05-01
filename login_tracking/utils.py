from django.db.models import Avg
from .models import LoginRecord

def get_avg_login_time(user):
    avg_time = LoginRecord.objects.filter(user=user).aggregate(avg_time=Avg('login_time'))['avg_time']
    return avg_time