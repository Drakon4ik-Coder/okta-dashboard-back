from django.contrib import admin
from django.urls import path, include
"""
URL configuration for OktaDashboardBackend project.

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

urlpatterns = [
    path('admin/', admin.site.urls),
    path('metrics/', include('django_prometheus.urls')),
    path('', views.landing_page, name='landing_page'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('health/', health_check, name="health_check"),
    path('api-auth/', include('rest_framework.urls')),
    path('api/', include('TrafficAnalysis.urls')),
    
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