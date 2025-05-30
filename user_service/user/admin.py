from django.contrib import admin
from .models import CustomUser


admin.site.register(CustomUser, list_display=('email', 'username', 'first_name', 'last_name', 'is_staff', 'is_active'))
