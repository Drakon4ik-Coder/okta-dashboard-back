from django.urls import path
from . import views

urlpatterns = [
    path('event-type-stats/', views.EventTypeStatsView.as_view(), name='event-type-stats'),
    path('logs/', views.OktaLogsView.as_view(), name='okta-logs'),
    path('logs/<str:event_id>/', views.OktaLogDetailView.as_view(), name='okta-log-detail'),
    path('fetch-logs-now/', views.FetchLogsNowView.as_view(), name='fetch-logs-now'),
    path('', views.landing_page, name='landing'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('health/', views.health_check, name='health-check'),
]