from django.urls import path, include
from rest_framework.routers import DefaultRouter
# Import your viewsets here
# from .views import YourModelViewSet

router = DefaultRouter()
# Register your viewsets like this:
# router.register(r'items', YourModelViewSet)

urlpatterns = [
    path('', include(router.urls)),
    # Add any custom API views here
    # path('custom/', YourCustomView.as_view()),
]