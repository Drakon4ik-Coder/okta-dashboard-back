"""
URL patterns for the traffic_analysis app.

This module defines URL routes for traffic analysis endpoints.
"""
from django.urls import path

from traffic_analysis.views.event_views import (
    EventsPageView,
    EventListView,
    EventDetailView,
    EventMetricsView
)
from traffic_analysis.views.log_views import (
    LogDashboardView,
    LogStatisticsAPIView,
    LogComparisonView,
    log_trends
)
from traffic_analysis.views.home_views import HomePageView, DashboardHomeView
from traffic_analysis.views.user_views import UserDashboardView
from traffic_analysis.views.alert_views import (
    AlertDashboardView,
    AlertListView,
    AlertDetailView
)
from traffic_analysis.views.metric_views import (
    MetricsDashboardView,
    login_events_stats,
    failed_login_stats,
    security_events_stats,
    total_events_stats
)
from traffic_analysis.views.report_views import ReportDashboardView
from traffic_analysis.views.setting_views import SettingsDashboardView
from traffic_analysis.views.diagnostic_views import mongodb_status

app_name = "traffic_analysis"

urlpatterns = [
    # Public pages
    path('', HomePageView.as_view(), name='home'),
    
    # Dashboard for authenticated users
    path('dashboard/', DashboardHomeView.as_view(), name='dashboard'),
    
    # HTML UI endpoints
    path('events/', EventsPageView.as_view(), name='events_page'),
    path('events/detail/<str:event_id>/', EventDetailView.as_view(), name='event_detail_page'),
    path('logs/', LogDashboardView.as_view(), name='logs_dashboard'),
    path('users/', UserDashboardView.as_view(), name='users_dashboard'),
    path('alerts/', AlertDashboardView.as_view(), name='alerts_dashboard'),
    path('metrics/', MetricsDashboardView.as_view(), name='metrics_dashboard'),
    path('reports/', ReportDashboardView.as_view(), name='reports_dashboard'),
    path('settings/', SettingsDashboardView.as_view(), name='settings_dashboard'),
    
    # API endpoints
    path('api/events/', EventListView.as_view(), name='event_list'),
    path('api/events/<str:event_id>/', EventDetailView.as_view(), name='event_detail'),
    path('api/metrics/', EventMetricsView.as_view(), name='event_metrics'),
    
    # Alert API endpoints
    path('api/alerts/', AlertListView.as_view(), name='alert_list'),
    path('api/alerts/<str:alert_id>/', AlertDetailView.as_view(), name='alert_detail'),
    
    # Log API endpoints
    path('api/logs/statistics/', LogStatisticsAPIView.as_view(), name='log_statistics'),
    path('api/logs/comparison/', LogComparisonView.as_view(), name='log_comparison'),
    path('api/logs/trends/', log_trends, name='log_trends'),
    
    # Login statistics endpoint
    path('api/statistics/login-events/', login_events_stats, name='login_events_stats'),
    path('api/statistics/failed-logins/', failed_login_stats, name='failed_login_stats'),
    path('api/statistics/security-events/', security_events_stats, name='security_events_stats'),
    path('api/statistics/total-events/', total_events_stats, name='total_events_stats'),
    
    # Diagnostic endpoints
    path('api/diagnostic/mongodb-status/', mongodb_status, name='mongodb_status'),
]