"""
Views for displaying metrics and analytics about Okta activity.

This module contains views for metrics visualizations and trend analysis.
"""
from django.views.generic import TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page

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