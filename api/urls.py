from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views

# Create a router for ViewSets
router = DefaultRouter()

# Register ViewSets here
# router.register(r'yourmodel', views.YourModelViewSet)

urlpatterns = [
    # Include the router URLs
    path('', include(router.urls)),

    # Base API view
    path('base/', views.BaseAPIView.as_view(), name='base'),

    # Okta API endpoints
    path('security/user-events/', views.UserSecurityEventsView.as_view(), name='user_security_events'),
    path('security/dashboard/', views.AdminSecurityDashboardView.as_view(), name='admin_security_dashboard'),
    path('security/user-logs/', views.UserLogsView.as_view(), name='user_logs'),
]