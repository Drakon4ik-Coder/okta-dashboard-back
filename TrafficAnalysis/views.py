from django.shortcuts import render
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from datetime import datetime
from rest_framework.permissions import AllowAny
from django.utils.dateparse import parse_datetime
from TrafficAnalysis.models import OktaLog
from TrafficAnalysis.serializers import OktaLogSerializer, OktaLogDetailSerializer
import logging
from collections import Counter
from django.contrib.auth.decorators import login_required
from django_ratelimit.decorators import ratelimit

logger = logging.getLogger(__name__)

@login_required
def dashboard(request):
    """Render the dashboard page."""
    return render(request, 'traffic_analysis/dashboard.html')

@ratelimit(key='ip', rate='10/m')
def landing_page(request):
    """Render the default landing page."""
    return render(request, 'traffic_analysis/landing.html')

@ratelimit(key='ip', rate='10/m')
def health_check(request):
    """Health check endpoint for Docker/Kubernetes"""
    return Response({"status": "healthy"}, status=200)

class OktaLogPagination(PageNumberPagination):
    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 1000

class OktaLogsView(APIView):
    """API endpoint for retrieving Okta logs"""
    pagination_class = OktaLogPagination
    
    def get_paginated_response(self, data):
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(data, self.request, view=self)
        serialized_data = OktaLogSerializer(page, many=True).data
        return paginator.get_paginated_response(serialized_data)
    
    def get(self, request):
        """Get logs with optional filtering"""
        try:
            # Get filter parameters
            event_type = request.query_params.get('event_type')
            actor_name = request.query_params.get('actor')
            client_ip = request.query_params.get('ip')
            start_date_str = request.query_params.get('start_date')
            end_date_str = request.query_params.get('end_date')
            
            # Parse dates
            start_date = parse_datetime(start_date_str) if start_date_str else None
            end_date = parse_datetime(end_date_str) if end_date_str else None
            
            # Build filters
            filters = {}
            if event_type:
                filters['event_type'] = event_type
            if actor_name:
                filters['actor_display_name'] = actor_name
            if client_ip:
                filters['client_ip'] = client_ip
            
            # Get logs with pagination
            logs = OktaLog.get_logs(
                filters=filters,
                start_date=start_date,
                end_date=end_date
            )
            
            # Convert to list for serialization
            log_list = list(logs)
            
            # Return paginated response
            return self.get_paginated_response(log_list)
        except Exception as e:
            logger.error(f"Error retrieving logs: {e}")
            return Response(
                {"error": "Error retrieving logs", "detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class OktaLogDetailView(APIView):
    """API endpoint for retrieving details of a specific Okta log"""
    
    def get(self, request, event_id):
        """Get detail for a specific log by ID"""
        try:
            log = OktaLog.objects.get(event_id=event_id)
            serializer = OktaLogDetailSerializer(log)
            return Response(serializer.data)
        except OktaLog.DoesNotExist:
            return Response(
                {"error": "Log not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error retrieving log detail: {e}")
            return Response(
                {"error": "Error retrieving log detail", "detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class FetchLogsNowView(APIView):
    """API endpoint for manually triggering log fetching"""
    permission_classes = [AllowAny]  # Allow access without authentication

    def post(self, request):
        """Trigger immediate log fetching"""
        try:
            from django_q.tasks import async_task
            task_id = async_task('TrafficAnalysis.tasks.fetch_and_save_logs')
            return Response({
                "message": "Log fetch task scheduled", 
                "task_id": task_id
            })
        except Exception as e:
            logger.error(f"Error scheduling log fetch task: {e}")
            return Response(
                {"error": "Error scheduling log fetch task", "detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class EventTypeStatsView(APIView):
    """API endpoint for retrieving event type statistics"""
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Get event type actor statistics for visualization"""
        try:
            # Fetch all event types from logs
            logs = OktaLog.objects.all().only('event_type')
            
            # Extract actor part from event_type (first part before dot)
            event_actors = []
            for log in logs:
                if log.event_type and isinstance(log.event_type, str) and '.' in log.event_type:
                    actor = log.event_type.split('.')[0]
                    event_actors.append(actor)
            
            # Count occurrences of each event actor
            actor_counts = Counter(event_actors)
            
            # Format data for pie chart
            chart_data = [
                {"name": actor, "value": count} 
                for actor, count in actor_counts.most_common(10)  # Limit to top 10
            ]
            
            return Response({
                "data": chart_data,
                "total": len(event_actors)
            })
        except Exception as e:
            logger.error(f"Error retrieving event type stats: {str(e)}", exc_info=True)  # Log full traceback
            return Response(
                {"error": "Error retrieving event type statistics", "detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )