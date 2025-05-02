"""
Views for handling alerts and notifications in the Okta dashboard.

This module contains views for alert management and configuration.
"""
from datetime import datetime, timedelta
from typing import Dict, Any, List

from django.views.generic import ListView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.db.models import Count, Q
from django.utils import timezone
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination

from traffic_analysis.models import ForensicEvent
import secrets

import logging

logger = logging.getLogger(__name__)


class StandardResultsSetPagination(PageNumberPagination):
    """
    Standard pagination for alert listing endpoints.
    """
    page_size = 25
    page_size_query_param = 'page_size'
    max_page_size = 100


class AlertDashboardView(LoginRequiredMixin, ListView):
    """
    View for displaying and filtering security alerts in a user-friendly UI.
    """
    template_name = 'traffic_analysis/alerts/alert_dashboard.html'
    context_object_name = 'alerts'
    paginate_by = 20
    login_url = '/login/'
    
    def get_queryset(self):
        """Get filtered alerts based on request parameters"""
        # Get filter parameters
        alert_type = self.request.GET.get('alert_type', '')
        severity = self.request.GET.get('severity', '')
        days = int(self.request.GET.get('days', 7))
        search = self.request.GET.get('search', '')
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Base queryset with time range - use Forensic events with high severity as alerts
        queryset = ForensicEvent.objects(
            timestamp__gte=start_date,
            timestamp__lte=end_date,
            severity__in=['critical', 'high']
        )
        
        # Apply additional filters if provided
        if alert_type:
            queryset = queryset.filter(event_type=alert_type)
        
        if severity:
            queryset = queryset.filter(severity=severity)
        
        if search:
            queryset = queryset.filter(
                Q(event_type__icontains=search) |
                Q(username__icontains=search) |
                Q(ip_address__icontains=search)
            )
        
        return queryset.order_by('-timestamp')
    
    def get_context_data(self, **kwargs):
        """Add extra context data for template rendering"""
        context = super().get_context_data(**kwargs)
        
        # Use the nonce from the request (set by SecurityHeadersMiddleware)
        # instead of generating a new one
        if hasattr(self.request, 'nonce'):
            context['nonce'] = self.request.nonce
        
        # Get all alerts for statistics (with same filters except pagination)
        queryset = self.get_queryset()
        
        # Get filter parameters to add to context
        context['selected_alert_type'] = self.request.GET.get('alert_type', '')
        context['selected_severity'] = self.request.GET.get('severity', '')
        context['days'] = int(self.request.GET.get('days', 7))
        context['search_query'] = self.request.GET.get('search', '')
        context['date_range_days'] = context['days']
        
        # Add statistics for the filter results
        context['total_alerts'] = queryset.count()
        context['critical_alerts'] = queryset.filter(severity='critical').count()
        context['high_alerts'] = queryset.filter(severity='high').count()
        context['medium_alerts'] = queryset.filter(severity='medium').count()
        context['low_alerts'] = queryset.filter(severity='low').count()
        
        # Get available filter options
        context['available_alert_types'] = self._get_alert_types()
        context['available_severities'] = ['critical', 'high', 'medium', 'low']
        
        return context
    
    def _get_alert_types(self):
        """Get list of available alert types"""
        # Get unique event types from forensic events that could be considered alerts
        pipeline = [
            {'$match': {'severity': {'$in': ['critical', 'high']}}},
            {'$group': {'_id': '$event_type'}},
            {'$sort': {'_id': 1}}
        ]
        result = ForensicEvent.objects.aggregate(pipeline)
        return [doc['_id'] for doc in result]


class AlertListView(APIView):
    """
    API view for listing security alerts with filtering and pagination.
    """
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    
    def get(self, request):
        """
        Handle GET requests for alert listing.
        
        Supports filtering by time range, alert type, and severity.
        
        Args:
            request: HTTP request object
            
        Returns:
            Response with serialized alerts or error message
        """
        # Get filtering parameters from query string
        days = int(request.query_params.get('days', 7))
        alert_type = request.query_params.get('alert_type')
        severity = request.query_params.get('severity')
        
        # Calculate time range
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        
        try:
            # Get page parameters
            page = int(request.query_params.get('page', 1))
            page_size = int(request.query_params.get('page_size', 25))
            
            # Build query filters
            query_filters = {
                "timestamp__gte": start_date,
                "timestamp__lte": end_date,
                "severity__in": ['critical', 'high'] if not severity else [severity]
            }
            
            if alert_type:
                query_filters["event_type"] = alert_type
            
            # Execute query with pagination
            skip = (page - 1) * page_size
            alerts = ForensicEvent.objects(**query_filters).order_by('-timestamp').skip(skip).limit(page_size)
            
            # Count total for pagination
            total_alerts = ForensicEvent.objects(**query_filters).count()
            total_pages = (total_alerts + page_size - 1) // page_size
            
            # Prepare result data manually since we're not using a serializer class
            alert_data = []
            for alert in alerts:
                alert_data.append({
                    'id': str(alert.id),
                    'event_id': alert.event_id,
                    'timestamp': alert.timestamp,
                    'event_type': alert.event_type,
                    'severity': alert.severity,
                    'username': alert.username,
                    'ip_address': alert.ip_address,
                    'resource': alert.resource,
                    'action': alert.action,
                    'status': alert.status,
                })
            
            # Construct paginated response
            result = {
                'count': total_alerts,
                'total_pages': total_pages,
                'current_page': page,
                'next': page + 1 if page < total_pages else None,
                'previous': page - 1 if page > 1 else None,
                'results': alert_data
            }
            
            return Response(result)
        
        except Exception as e:
            logger.error(f"Error in AlertListView: {str(e)}")
            return Response(
                {"error": f"Failed to fetch alerts: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AlertDetailView(APIView):
    """
    API view for retrieving details of a specific security alert.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, alert_id):
        """
        Handle GET request for a specific alert by ID.
        
        Args:
            request: HTTP request object
            alert_id: ID of the alert to retrieve
            
        Returns:
            Response with alert data or error message
        """
        try:
            alert = ForensicEvent.objects(event_id=alert_id).first()
            
            if not alert:
                return Response(
                    {"error": f"Alert with ID {alert_id} not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Convert alert to dictionary for response
            alert_data = {
                'id': str(alert.id),
                'event_id': alert.event_id,
                'source_event_id': alert.source_event_id,
                'timestamp': alert.timestamp,
                'event_type': alert.event_type,
                'severity': alert.severity,
                'user_id': alert.user_id,
                'username': alert.username,
                'ip_address': alert.ip_address,
                'user_agent': alert.user_agent,
                'device_info': alert.device_info,
                'session_id': alert.session_id,
                'geo_location': alert.geo_location,
                'resource': alert.resource,
                'action': alert.action,
                'status': alert.status,
                'attributes': alert.attributes,
                'context': alert.context
            }
            
            return Response(alert_data)
            
        except Exception as e:
            logger.error(f"Error in AlertDetailView: {str(e)}")
            return Response(
                {"error": f"Failed to fetch alert details: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )