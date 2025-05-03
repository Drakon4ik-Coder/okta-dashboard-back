# login_tracking/urls.py
from django.urls import path
from . import api_views
from login_tracking.views import avg_login_time_api

urlpatterns = [
    path('api/login-timing/avg/cached/', avg_login_time_api),
    path('api/v1/metrics/okta_login_time/', api_views.okta_login_time, name='okta_login_time'),
    path('api/v1/metrics/okta_login_time/cached/', api_views.cached_okta_login_time, name='cached_okta_login_time'),
]
