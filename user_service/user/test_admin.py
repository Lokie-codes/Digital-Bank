import pytest
from django.contrib import admin
from user.admin import CustomUser
from user import admin as user_admin

def test_customuser_registered_with_admin():
    # Find the ModelAdmin registered for CustomUser
    model_admin = admin.site._registry.get(CustomUser)
    assert model_admin is not None, "CustomUser is not registered with admin site"
    # Check that list_display is set as expected
    expected_fields = ('email', 'username', 'first_name', 'last_name', 'is_staff', 'is_active')
    assert hasattr(model_admin, 'list_display')
    assert model_admin.list_display == expected_fields