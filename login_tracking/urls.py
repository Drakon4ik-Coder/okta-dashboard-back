# login_tracking/urls.py
from django.urls import path
from . import api_views

urlpatterns = [
    path('api/v1/hooks/okta-events/', api_views.okta_event_hook, name='okta_event_hook'),
    path('api/v1/metrics/okta_login_time/', api_views.okta_login_time, name='okta_login_time'),
    path('api/v1/metrics/okta_login_time/cached/', api_views.cached_okta_login_time, name='cached_okta_login_time'),
]
