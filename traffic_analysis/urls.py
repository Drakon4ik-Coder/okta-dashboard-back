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

app_name = "traffic_analysis"

urlpatterns = [
    # Public pages
    path('', HomePageView.as_view(), name='home'),
    
    # Dashboard for authenticated users
    path('dashboard/', DashboardHomeView.as_view(), name='dashboard'),
    
    # HTML UI endpoints
    path('events/', EventsPageView.as_view(), name='events_page'),
    path('logs/', LogDashboardView.as_view(), name='logs_dashboard'),
    
    # API endpoints
    path('api/events/', EventListView.as_view(), name='event_list'),
    path('api/events/<str:event_id>/', EventDetailView.as_view(), name='event_detail'),
    path('api/metrics/', EventMetricsView.as_view(), name='event_metrics'),
    
    # Log API endpoints
    path('api/logs/statistics/', LogStatisticsAPIView.as_view(), name='log_statistics'),
    path('api/logs/comparison/', LogComparisonView.as_view(), name='log_comparison'),
    path('api/logs/trends/', log_trends, name='log_trends'),
]