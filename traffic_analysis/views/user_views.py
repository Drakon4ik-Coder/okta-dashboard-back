"""
Views for handling Okta user data and displaying user dashboard.

This module contains views for user management and analytics.
"""
from django.views.generic import TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page

import logging

logger = logging.getLogger(__name__)


@method_decorator(cache_page(60 * 5), name='dispatch')  # Cache entire view for 5 minutes
class UserDashboardView(LoginRequiredMixin, TemplateView):
    """
    View for displaying user analytics dashboard.
    Shows user activity, risk scores, and authentication patterns.
    """
    template_name = 'traffic_analysis/users/user_dashboard.html'
    login_url = '/login/'
    
    def get_context_data(self, **kwargs):
        """Add user statistics to context for dashboard display"""
        context = super().get_context_data(**kwargs)
        
        # Use the nonce from the request (set by SecurityHeadersMiddleware)
        # instead of generating a new one
        if hasattr(self.request, 'nonce'):
            context['nonce'] = self.request.nonce
        
        # Add sample data for initial template rendering
        # In a real implementation, these would be fetched from services
        context.update({
            'total_users': 125,
            'active_users': 98,
            'inactive_users': 27,
            'users_with_mfa': 85,
            'user_risk_high': 5,
            'user_risk_medium': 15,
            'user_risk_low': 105,
            'recent_users': [],
            'top_active_users': [],
            'suspicious_users': []
        })
        
        return context