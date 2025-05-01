from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='okta_login'),
    path('callback/', views.oauth_callback, name='okta_callback'),
    path('refresh/', views.refresh_token_view, name='refresh_token'),
]