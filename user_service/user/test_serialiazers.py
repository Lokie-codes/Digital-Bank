import pytest
from django.contrib.auth import get_user_model
from user.serialiazers import CustomUserCreateSerializer

User = get_user_model()

@pytest.mark.django_db
def test_create_user_with_username():
    data = {
        "username": "testuser",
        "email": "testuser@example.com",
        "password": "strongpassword123",
        "password2": "strongpassword123",
        "first_name": "Test",
        "last_name": "User",
        "role": "user"
    }
    serializer = CustomUserCreateSerializer(data=data)
    assert serializer.is_valid(), serializer.errors
    user = serializer.save()
    assert user.username == "testuser"
    assert user.email == "testuser@example.com"
    assert user.first_name == "Test"
    assert user.last_name == "User"
    assert user.role == "user"
    assert user.check_password("strongpassword123")
    assert not hasattr(user, "password2")

@pytest.mark.django_db
def test_create_user_without_username_uses_email_as_username():
    data = {
        "email": "nousername@example.com",
        "password": "anotherstrongpassword",
        "password2": "anotherstrongpassword",
        "first_name": "No",
        "last_name": "Username",
        "role": "admin"
    }
    serializer = CustomUserCreateSerializer(data=data)
    assert serializer.is_valid(), serializer.errors
    user = serializer.save()
    assert user.username == "nousername@example.com"
    assert user.email == "nousername@example.com"
    assert user.first_name == "No"
    assert user.last_name == "Username"
    assert user.role == "admin"
    assert user.check_password("anotherstrongpassword")

@pytest.mark.django_db
def test_create_user_password_is_hashed():
    data = {
        "username": "hashuser",
        "email": "hashuser@example.com",
        "password": "plainpassword",
        "password2": "plainpassword",
        "first_name": "Hash",
        "last_name": "User",
        "role": "user"
    }
    serializer = CustomUserCreateSerializer(data=data)
    assert serializer.is_valid(), serializer.errors
    user = serializer.save()
    assert user.password != "plainpassword"
    assert user.check_password("plainpassword")

@pytest.mark.django_db
def test_create_user_passwords_do_not_match():
    data = {
        "username": "failuser",
        "email": "failuser@example.com",
        "password": "password1",
        "password2": "password2",
        "first_name": "Fail",
        "last_name": "User",
        "role": "user"
    }
    serializer = CustomUserCreateSerializer(data=data)
    assert not serializer.is_valid()
    assert "non_field_errors" in serializer.errors or "Passwords do not match." in str(serializer.errors)