# users/auth_views.py
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from drf_spectacular.utils import extend_schema
from .serializers import CustomTokenObtainPairSerializer # Corrected typo

@extend_schema(
    summary='Obtain JWT Access and Refresh Tokens',
    description='Authenticates a user and returns JWT access and refresh tokens. '
                'Returns a generic "No active account found with the given credentials" for security reasons '
                'if credentials are invalid or account is inactive (prevents user enumeration).',
    request=CustomTokenObtainPairSerializer,
    responses={
        200: CustomTokenObtainPairSerializer,
        401: {'description': 'No active account found with the given credentials'},
    },
    tags=['Authentication']
)
class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Handles obtaining JWT access and refresh tokens for user authentication.
    """
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request):
        """
        Processes authentication request to issue JWT tokens.

        token_serializer = self.get_serializer(data=request.data)
        # is_valid will raise AuthenticationFailed (which results in 401)
        # if user is inactive or credentials are bad, handled by CustomTokenObtainPairSerializer
        token_serializer.is_valid(raise_exception=True)
        return Response(token_serializer.validated_data, status=status.HTTP_200_OK)
        """
        serializer = self.get_serializer(data=request.data)
        # is_valid will raise AuthenticationFailed (which results in 401)
        # if user is inactive or credentials are bad, handled by CustomTokenObtainPairSerializer
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)