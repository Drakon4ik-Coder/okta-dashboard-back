from django.urls import path
from . import api_views

urlpatterns = [
    path('api/login-timing/avg/', api_views.avg_login_time, name='avg_login_time'),
    path('api/login-timing/avg/cached/', api_views.cached_avg_login_time, name='cached_avg_login_time'),
]