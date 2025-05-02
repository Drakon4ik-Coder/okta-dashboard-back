"""
Views for displaying and analyzing metrics from Okta data.

This module contains views for metrics visualization, analysis, and reporting.
"""
from django.views.generic import TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page

import logging

logger = logging.getLogger(__name__)


class MetricsDashboardView(LoginRequiredMixin, TemplateView):
    """
    View for displaying and analyzing metrics.
    Shows key performance indicators, trends, and analytical visualizations.
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
            'authentication_metrics': {
                'total_logins': 15234,
                'successful_logins': 14562,
                'failed_logins': 672,
                'login_success_rate': 95.6,
                'mfa_usage_rate': 78.3
            },
            'user_metrics': {
                'total_users': 1245,
                'active_users': 985,
                'inactive_users': 260,
                'new_users_last_30_days': 87,
                'user_growth_rate': 7.5
            },
            'application_metrics': {
                'total_apps': 42,
                'most_used_apps': [
                    {'name': 'Office 365', 'users': 934},
                    {'name': 'Salesforce', 'users': 823},
                    {'name': 'Google Workspace', 'users': 756},
                    {'name': 'Slack', 'users': 698},
                    {'name': 'Jira', 'users': 536}
                ]
            },
            'security_metrics': {
                'suspicious_activities': 24,
                'policy_violations': 18,
                'location_anomalies': 12,
                'device_anomalies': 9,
                'time_anomalies': 7
            },
            'time_periods': [
                {'id': '7d', 'name': 'Last 7 Days'},
                {'id': '30d', 'name': 'Last 30 Days'},
                {'id': '90d', 'name': 'Last 90 Days'}
            ],
            'current_period': '30d'
        })
        
        return context