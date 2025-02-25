# Create your views here.
from django.shortcuts import render


def dashboard(request):
    """Render the dashboard page."""
    return render(request, 'traffic_analysis/dashboard.html', context={'title': 'Dashboard'})

def landing_page(request):
    """Render the default landing page."""
    return render(request, 'traffic_analysis/landing.html', context={'title': 'Welcome to Traffic Analysis'})
