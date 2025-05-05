"""
Views for displaying metrics and analytics about Okta activity.

This module contains views for metrics visualizations and trend analysis.
"""
from django.views.generic import TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.http import JsonResponse
from django.views import View
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django_ratelimit.decorators import ratelimit

from traffic_analysis.services.login_statistics import get_login_events_count, get_failed_login_count, get_security_events_count, get_total_events_count

import logging

logger = logging.getLogger(__name__)


class MetricsDashboardView(LoginRequiredMixin, TemplateView):
    """
    View for displaying advanced metrics and analytics.
    Shows usage patterns, authentication statistics, and security metrics.
    """
    template_name = 'traffic_analysis/metrics/metrics_dashboard.html'
    login_url = '/login/'
    
    def dispatch(self, request, *args, **kwargs):
        # Store request in the instance for later use in get_context_data
        self.request = request
        return super().dispatch(request, *args, **kwargs)
    
    @method_decorator(cache_page(60 * 5))  # Cache for 5 minutes
    def get(self, request, *args, **kwargs):
        """Handle GET requests: instantiate a template response"""
        return super().get(request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        """Add metrics data to context for dashboard display"""
        context = super().get_context_data(**kwargs)
        
        # Use the nonce from the request (set by SecurityHeadersMiddleware)
        # instead of generating a new one
        if hasattr(self.request, 'nonce'):
            context['nonce'] = self.request.nonce
        
        # Add sample data for initial template rendering
        # In a real implementation, these would be fetched from services
        context.update({
            'auth_success_rate': 98.5,
            'mfa_usage_rate': 68.0,
            'avg_session_time': 35,
            'peak_usage_hour': 10,
            'usage_by_app': [],
            'usage_by_location': [],
            'usage_by_device': [],
            'auth_methods': []
        })
        
        return context


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='30/m', method='GET', block=True)
@cache_page(60 * 5)  # Cache for 5 minutes
def login_events_stats(request):
    """
    API endpoint for getting login events statistics.
    Returns the count of successful login events from the last 30 days.
    """
    try:
        days = int(request.query_params.get('days', 30))
        count = get_login_events_count(days)
        
        return Response({
            'login_events_count': count,
            'period_days': days
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Error retrieving login events stats: {str(e)}")
        return Response({
            'error': 'Failed to retrieve login events statistics',
            'detail': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='30/m', method='GET', block=True)
@cache_page(60 * 5)  # Cache for 5 minutes
def failed_login_stats(request):
    """
    API endpoint for getting failed login statistics.
    Returns the count of failed login attempts from the last 30 days.
    """
    try:
        days = int(request.query_params.get('days', 30))
        count = get_failed_login_count(days)
        
        return Response({
            'failed_login_count': count,
            'period_days': days
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Error retrieving failed login stats: {str(e)}")
        return Response({
            'error': 'Failed to retrieve failed login statistics',
            'detail': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='30/m', method='GET', block=True)
@cache_page(60 * 5)  # Cache for 5 minutes
def security_events_stats(request):
    """
    API endpoint for getting security events statistics.
    Returns the count of security events from the last 30 days.
    """
    try:
        days = int(request.query_params.get('days', 30))
        count = get_security_events_count(days)
        
        return Response({
            'security_events_count': count,
            'period_days': days
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Error retrieving security events stats: {str(e)}")
        return Response({
            'error': 'Failed to retrieve security events statistics',
            'detail': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='30/m', method='GET', block=True)
@cache_page(60 * 5)  # Cache for 5 minutes
def total_events_stats(request):
    """
    API endpoint for getting total events statistics.
    Returns the count of all events from the last 30 days.
    """
    try:
        days = int(request.query_params.get('days', 30))
        count = get_total_events_count(days)
        
        return Response({
            'total_events_count': count,
            'period_days': days
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Error retrieving total events stats: {str(e)}")
        return Response({
            'error': 'Failed to retrieve total events statistics',
            'detail': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)