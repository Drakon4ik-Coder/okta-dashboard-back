"""
Home views for the traffic analysis dashboard.

This module contains the views for the landing page and other public-facing pages.
"""
import logging
from datetime import datetime, timedelta
from django.shortcuts import render
from django.views.generic import TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils import timezone
from pymongo import MongoClient
from django.conf import settings

from traffic_analysis.models import OktaEvent, OktaMetrics

logger = logging.getLogger(__name__)

class HomePageView(TemplateView):
    template_name = 'traffic_analysis/landing_page.html'

class DashboardHomeView(LoginRequiredMixin, TemplateView):
    template_name = 'traffic_analysis/dashboard/index.html'
    login_url = '/login/'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Connect to MongoDB directly for more efficient aggregation queries
        try:
            # Get MongoDB connection details from settings
            mongo_host = settings.MONGODB_SETTINGS.get('host', 'localhost')
            mongo_port = settings.MONGODB_SETTINGS.get('port', 27017)
            mongo_db = settings.MONGODB_SETTINGS.get('db', 'OktaDashboardDB')
            mongo_user = settings.MONGODB_SETTINGS.get('username')
            mongo_pass = settings.MONGODB_SETTINGS.get('password')
            
            # Create connection string
            connection_string = f"mongodb://"
            if mongo_user and mongo_pass:
                connection_string += f"{mongo_user}:{mongo_pass}@"
            connection_string += f"{mongo_host}:{mongo_port}/{mongo_db}"
            
            # Connect to MongoDB
            client = MongoClient(connection_string)
            db = client[mongo_db]
            events_collection = db.okta_events
            
            # Calculate time ranges
            now = timezone.now()
            thirty_days_ago = now - timedelta(days=30)
            seven_days_ago = now - timedelta(days=7)
            
            # Get total count of events
            context['total_events'] = events_collection.count_documents({})
            
            # Get login events count
            context['login_events'] = events_collection.count_documents({
                'event_type': {'$regex': 'user.session.start|user.authentication.sso'},
            })
            
            # Get failed login attempts
            context['failed_events'] = events_collection.count_documents({
                'event_type': {'$regex': 'user.authentication'},
                'outcome.result': 'FAILURE'
            })
            
            # Get security events count
            context['security_events'] = events_collection.count_documents({
                'event_type': {'$regex': 'security|threat'},
            })
            
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