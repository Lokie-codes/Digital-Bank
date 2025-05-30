import pytest
from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError
from django.contrib.auth import get_user_model

CustomUser = get_user_model()

@pytest.mark.django_db
def test_create_user_success():
    user = CustomUser.objects.create_user(
        email="test@example.com",
        password="securepassword123",
        first_name="Test",
        last_name="User"
    )
    assert user.email == "test@example.com"
    assert user.check_password("securepassword123")
    assert user.is_active
    assert user.role == "user"

@pytest.mark.django_db
def test_create_user_email_normalization():
    user = CustomUser.objects.create_user(
        email="Test@Example.COM",
        password="password"
    )
    assert user.email == "Test@example.com"

@pytest.mark.django_db
def test_create_user_without_email_raises_value_error():
    with pytest.raises(ValueError) as excinfo:
        CustomUser.objects.create_user(email=None, password="password")
    assert "The Email field must be set" in str(excinfo.value)

@pytest.mark.django_db
def test_create_user_duplicate_email_raises_integrity_error():
    CustomUser.objects.create_user(email="unique@example.com", password="password")
    with pytest.raises(IntegrityError):
        CustomUser.objects.create_user(email="unique@example.com", password="password2")