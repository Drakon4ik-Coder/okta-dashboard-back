from rest_framework import viewsets
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status


# Example ViewSet - replace YourModel with your actual model
class BaseModelViewSet(viewsets.ModelViewSet):
    """
    A viewset for viewing and editing model instances.
    """
    # Override these in child classes
    serializer_class = None
    queryset = None

    def get_queryset(self):
        """
        This view should return a list of all models
        for the currently authenticated user.
        """
        # You can customize this based on your needs
        return super().get_queryset()


# Example basic APIView
class BaseAPIView(APIView):
    """
    Base API view with common methods.
    """

    def get(self, request, format=None):
        """
        Return a response.
        """
        return Response({"message": "Method not implemented"},
                        status=status.HTTP_501_NOT_IMPLEMENTED)
