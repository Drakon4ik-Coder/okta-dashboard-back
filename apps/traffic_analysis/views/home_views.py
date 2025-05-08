"""
Home views for the traffic analysis dashboard.

This module contains the views for the landing page and other public-facing pages.
"""
import logging
from datetime import datetime, timedelta
from django.shortcuts import render
from django.views.generic import View, TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils import timezone
from django.conf import settings

from traffic_analysis.models import OktaEvent, OktaMetrics
from traffic_analysis.services.login_statistics import get_login_events_count, get_failed_login_count, get_security_events_count, get_total_events_count
from okta_dashboard.services.database import DatabaseService

logger = logging.getLogger(__name__)

# Simple function-based view for the home page to avoid async/sync issues
def home_page_view(request):
    """
    Simple function-based view for the home page.
    This avoids any async/sync compatibility issues.
    """
    # Set device trust level to 1 to avoid high risk in ContinuousAuthMiddleware
    if request.user.is_authenticated:
        request.session['device_trust_level'] = 1
    return render(request, 'traffic_analysis/landing_page.html')

# Legacy class-based view, kept for reference but not used
class HomePageView(TemplateView):
    template_name = 'traffic_analysis/landing_page.html'

class DashboardHomeView(LoginRequiredMixin, TemplateView):
    template_name = 'traffic_analysis/dashboard/index.html'
    login_url = '/login/'
    
    def get_context_data(self, **kwargs):
        # Set device trust level to 1 to avoid high risk in ContinuousAuthMiddleware
        if self.request.user.is_authenticated:
            self.request.session['device_trust_level'] = 1
        context = super().get_context_data(**kwargs)
        
        # Use the DatabaseService singleton for MongoDB connection
        try:
            # Get the database service instance
            db_service = DatabaseService()
            
            if not db_service.is_connected():
                logger.warning("Database not connected. Attempting to reconnect...")
                db_service.connect()
            
            # Get MongoDB client
            client = db_service.get_client()
            mongo_db = settings.MONGODB_SETTINGS.get('db', 'OktaDashboardDB')
            db = client[mongo_db]
            events_collection = db.okta_events
            
            # Log connection status
            logger.info(f"MongoDB connection status: {db_service.is_connected()}")
            
            # Calculate time ranges
            now = timezone.now()
            thirty_days_ago = now - timedelta(days=30)
            seven_days_ago = now - timedelta(days=7)
            
            # Get total count of events using our improved statistics service
            context['total_events'] = get_total_events_count(30)
            logger.info(f"Total events from statistics service: {context['total_events']}")
            
            # Get login events count using our improved statistics service
            context['login_events'] = get_login_events_count(30)
            logger.info(f"Login events from statistics service: {context['login_events']}")
            
            # Get failed login attempts using our improved statistics service
            context['failed_events'] = get_failed_login_count(30)
            logger.info(f"Failed login events from statistics service: {context['failed_events']}")
            
            # Get security events count using our improved statistics service
            context['security_events'] = get_security_events_count(30)
            logger.info(f"Security events from statistics service: {context['security_events']}")
            
            # Get recent events for display (limit to 10)
            recent_events = list(events_collection.find(
                {}, 
                sort=[('published', -1)]
            ).limit(10))
            
            # Prepare data for event activity chart
            date_range = [now - timedelta(days=x) for x in range(7, 0, -1)]
            chart_dates = [date.strftime('%b %d') for date in date_range]
            
            # Get successful logins per day for the last 7 days
            successful_logins = []
            failed_logins = []
            security_events = []
            
            for date in date_range:
                day_start = date.replace(hour=0, minute=0, second=0)
                day_end = date.replace(hour=23, minute=59, second=59)
                
                # Successful logins
                successful_count = events_collection.count_documents({
                    'event_type': {'$regex': 'user.session.start|user.authentication.sso'},
                    'outcome.result': 'SUCCESS',
                    'published': {'$gte': day_start, '$lte': day_end}
                })
                successful_logins.append(successful_count)
                
                # Failed logins
                failed_count = events_collection.count_documents({
                    'event_type': {'$regex': 'user.authentication'},
                    'outcome.result': 'FAILURE',
                    'published': {'$gte': day_start, '$lte': day_end}
                })
                failed_logins.append(failed_count)
                
                # Security events
                security_count = events_collection.count_documents({
                    'event_type': {'$regex': 'security|threat'},
                    'published': {'$gte': day_start, '$lte': day_end}
                })
                security_events.append(security_count)
            
            # Get event distribution
            event_distribution = []
            event_types = [
                {'name': 'Login', 'regex': 'user.session.start|user.authentication.sso'},
                {'name': 'Logout', 'regex': 'user.session.end'},
                {'name': 'Password Change', 'regex': 'user.credential.password'},
                {'name': 'MFA', 'regex': 'user.mfa|factor'},
                {'name': 'App Access', 'regex': 'application'},
                {'name': 'Admin Actions', 'regex': 'admin'},
                {'name': 'Other', 'regex': '.*'}
            ]
            
            distribution_labels = []
            distribution_data = []
            
            for event_type in event_types:
                count = events_collection.count_documents({
                    'event_type': {'$regex': event_type['regex']},
                })
                if count > 0:  # Only add non-zero values
                    distribution_labels.append(event_type['name'])
                    distribution_data.append(count)
            
            # Calculate metrics trends
            login_trend = 0
            failed_trend = 0
            security_trend = 0
            
            # Compare last 7 days to previous 7 days
            current_period_logins = events_collection.count_documents({
                'event_type': {'$regex': 'user.session.start|user.authentication.sso'},
                'published': {'$gte': seven_days_ago}
            })
            
            previous_period_start = now - timedelta(days=14)
            previous_period_end = seven_days_ago
            previous_period_logins = events_collection.count_documents({
                'event_type': {'$regex': 'user.session.start|user.authentication.sso'},
                'published': {'$gte': previous_period_start, '$lt': previous_period_end}
            })
            
            if previous_period_logins > 0:
                login_trend = ((current_period_logins - previous_period_logins) / previous_period_logins) * 100
                
            # Calculate failed login trend
            current_period_failed = events_collection.count_documents({
                'event_type': {'$regex': 'user.authentication'},
                'outcome.result': 'FAILURE',
                'published': {'$gte': seven_days_ago}
            })
            
            previous_period_failed = events_collection.count_documents({
                'event_type': {'$regex': 'user.authentication'},
                'outcome.result': 'FAILURE',
                'published': {'$gte': previous_period_start, '$lt': previous_period_end}
            })
            
            if previous_period_failed > 0:
                failed_trend = ((current_period_failed - previous_period_failed) / previous_period_failed) * 100
                
            # Calculate security events trend
            current_period_security = events_collection.count_documents({
                'event_type': {'$regex': 'security|threat'},
                'published': {'$gte': seven_days_ago}
            })
            
            previous_period_security = events_collection.count_documents({
                'event_type': {'$regex': 'security|threat'},
                'published': {'$gte': previous_period_start, '$lt': previous_period_end}
            })
            
            if previous_period_security > 0:
                security_trend = ((current_period_security - previous_period_security) / previous_period_security) * 100

            # Add all data to context
            context['recent_events'] = recent_events
            context['chart_dates'] = chart_dates
            context['successful_logins'] = successful_logins
            context['failed_logins'] = failed_logins
            context['security_events_chart'] = security_events
            context['distribution_labels'] = distribution_labels
            context['distribution_data'] = distribution_data
            context['login_trend'] = login_trend
            context['failed_trend'] = failed_trend
            context['security_trend'] = security_trend
            
            logger.info(f"Successfully loaded dashboard data with {context['total_events']} total events")
            
        except Exception as e:
            logger.error(f"Error fetching dashboard data from MongoDB: {str(e)}")
            context['error'] = "Could not fetch dashboard data from database"
            context['total_events'] = 0
            context['login_events'] = 0
            context['failed_events'] = 0
            context['security_events'] = 0
            context['recent_events'] = []
        
        return context