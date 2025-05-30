from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    # Include your app's URLs under a common API prefix
    path('api/', include('user.urls')), # Make sure 'user' matches your app name
]