from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView

urlpatterns = [
    path('admin/', admin.site.urls),
    # Include your app's URLs under a common API prefix
    path('api/v1/', include('user.urls')), # Make sure 'user' matches your app name
    # OpenAPI schema generation
    path('api/v1/schema/', SpectacularAPIView.as_view(), name='schema'),
    # Swagger UI
    path('api/v1/swagger/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    # ReDoc UI
    path('api/v1/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]