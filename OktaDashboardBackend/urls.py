from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse
from traffic_analysis.views.event_views import EventListView
from traffic_analysis.views.home_views import HomePageView
from okta_auth.views import oauth_callback, login_view, logout_view

<<<<<<< Updated upstream
The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from TrafficAnalysis import views
from TrafficAnalysis.views import health_check
from django.urls import path, include, re_path
from okta_auth import views as auth_views
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="OKTA Dashboard API",
        default_version='v1',
        description="API documentation for OKTA Dashboard",
        terms_of_service="https://www.example.com/terms/",
        contact=openapi.Contact(email="contact@mongo.db"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)
=======
# Health check view for monitoring services
def health_check(request):
    return JsonResponse({"status": "ok", "service": "okta-dashboard-backend"})
>>>>>>> Stashed changes

urlpatterns = [
    path('admin/', admin.site.urls),
    
<<<<<<< Updated upstream
    # Authentication URLs
    path('login/', auth_views.login_view, name='login'),
    path('logout/', auth_views.logout_view, name='logout'),
    path('okta/login/', auth_views.okta_login, name='okta_login'),
    path('okta/callback', auth_views.okta_callback, name='okta_callback'),
    path('okta/test/', auth_views.test, name='test_auth'),

    re_path(r'^docs(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('docs/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
=======
    # API endpoints
    path('api/', include('api.urls')),
    
    # Okta OAuth routes
    path('okta/login/', include('okta_auth.urls')),
    path('okta/callback/', oauth_callback, name='okta_callback'),
    
    # Login and logout URLs - use proper authentication views
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    
    # Traffic Analysis app - updated to use new app
    path('', include('traffic_analysis.urls')),
    
    # Monitoring and health check endpoints
    path('health/', health_check, name='health-check'),
    path('health/', health_check, name='health_check'),
    path('metrics/', include('django_prometheus.urls')),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# Add handler for errors - updated to use new app
handler404 = 'traffic_analysis.views.error_views.handler404'
handler500 = 'traffic_analysis.views.error_views.handler500'
>>>>>>> Stashed changes
