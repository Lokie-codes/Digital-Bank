# user_service/user_core/urls.py
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('user.urls')), # All user service endpoints under /api/auth/
]