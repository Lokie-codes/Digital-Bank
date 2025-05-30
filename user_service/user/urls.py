# users/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import UserViewSet
from . import auth_views

router = DefaultRouter()
# If UserViewSet remained in users/views.py, then:
router.register(r'users', UserViewSet, basename='user')


urlpatterns = [
    path('', include(router.urls)),
    path('auth/token/', auth_views.CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    # ... any other specific paths ...
]