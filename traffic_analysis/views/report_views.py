"""
Views for generating and managing reports from Okta data.

This module contains views for report generation, scheduling, and management.
"""
from django.views.generic import TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page

import logging

logger = logging.getLogger(__name__)


class ReportDashboardView(LoginRequiredMixin, TemplateView):
    """
    View for displaying and managing reports.
    Shows available reports, scheduled reports, and report history.
    """
    template_name = 'traffic_analysis/reports/report_dashboard.html'
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
        """Add report data to context for dashboard display"""
        context = super().get_context_data(**kwargs)
        
        # Use the nonce from the request (set by SecurityHeadersMiddleware)
        # instead of generating a new one
        if hasattr(self.request, 'nonce'):
            context['nonce'] = self.request.nonce
        
        # Add sample data for initial template rendering
        # In a real implementation, these would be fetched from services
        context.update({
            'available_reports': [
                {'name': 'User Activity Report', 'description': 'Summary of user login and app usage activity', 'type': 'user'},
                {'name': 'Security Compliance Report', 'description': 'Analysis of security policy compliance', 'type': 'security'},
                {'name': 'MFA Usage Report', 'description': 'Detail of MFA enrollment and usage across organization', 'type': 'security'},
                {'name': 'Application Usage Report', 'description': 'Summary of application access and usage', 'type': 'application'},
                {'name': 'Administrative Changes Report', 'description': 'Log of all administrative changes', 'type': 'admin'}
            ],
            'scheduled_reports': [],
            'recent_reports': []
        })
        
        return context