from django.urls import path
from . import views

urlpatterns = [
    # Use the direct login as the main login page
    path('', views.login_view, name='login'),
    
    # Keep the Okta OAuth options available but with different paths
    path('okta/', views.okta_login_view, name='okta_login'),
    path('callback/', views.oauth_callback, name='okta_callback'),
    path('refresh/', views.refresh_token_view, name='refresh_token'),
]