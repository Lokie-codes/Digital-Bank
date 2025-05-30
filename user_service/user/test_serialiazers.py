import pytest
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIRequestFactory

from user.serialiazers import (
    CustomUserCreateSerializer,
    CustomUserDetailSerializer,
    CustomUserListSerializer,
    CustomTokenObtainPairSerializer,
    PasswordChangeSerializer,
)

User = get_user_model()

@pytest.mark.django_db
class TestCustomUserCreateSerializer:
    def test_valid_data_creates_user(self):
        data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "strongpassword123",
            "password2": "strongpassword123",
            "first_name": "Test",
            "last_name": "User",
        }
        serializer = CustomUserCreateSerializer(data=data)
        assert serializer.is_valid(), serializer.errors
        user = serializer.save()
        assert user.username == data["username"]
        assert user.email == data["email"]
        assert user.check_password(data["password"])
        assert user.role == "user"

    def test_passwords_do_not_match(self):
        data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "password1",
            "password2": "password2",
            "first_name": "Test",
            "last_name": "User",
        }
        serializer = CustomUserCreateSerializer(data=data)
        assert not serializer.is_valid()
        assert "non_field_errors" in serializer.errors or "password" in serializer.errors

@pytest.mark.django_db
class TestCustomUserDetailSerializer:
    def test_update_user(self):
        user = User.objects.create_user(
            username="testuser", email="test@example.com", password="pass"
        )
        data = {"first_name": "Updated", "last_name": "Name"}
        serializer = CustomUserDetailSerializer(user, data=data, partial=True)
        assert serializer.is_valid(), serializer.errors
        updated_user = serializer.save()
        assert updated_user.first_name == "Updated"
        assert updated_user.last_name == "Name"

    def test_password_not_updated(self):
        user = User.objects.create_user(
            username="testuser", email="test@example.com", password="pass"
        )
        data = {"password": "newpassword"}
        serializer = CustomUserDetailSerializer(user, data=data, partial=True)
        assert serializer.is_valid(), serializer.errors
        updated_user = serializer.save()
        assert not updated_user.check_password("newpassword")

@pytest.mark.django_db
class TestCustomUserListSerializer:
    def test_list_serializer_fields(self):
        user = User.objects.create_user(
            username="testuser", email="test@example.com", password="pass"
        )
        serializer = CustomUserListSerializer(user)
        data = serializer.data
        expected_fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'is_active', 'is_staff', 'date_joined', 'role'
        ]
        for field in expected_fields:
            assert field in data

@pytest.mark.django_db
class TestCustomTokenObtainPairSerializer:
    def test_token_contains_custom_claims(self):
        user = User.objects.create_user(
            username="testuser", email="test@example.com", password="pass", role="admin", is_staff=True, is_superuser=True
        )
        token = CustomTokenObtainPairSerializer.get_token(user)
        assert token["email"] == user.email
        assert token["username"] == user.username
        assert token["role"] == user.role
        assert token["is_staff"] is True
        assert token["is_superuser"] is True

@pytest.mark.django_db
class TestPasswordChangeSerializer:
    def test_passwords_do_not_match(self):
        user = User.objects.create_user(username="testuser", email="test@example.com", password="oldpass")
        factory = APIRequestFactory()
        request = factory.post("/")
        request.user = user
        data = {
            "old_password": "oldpass",
            "new_password": "newpass1",
            "new_password2": "newpass2",
        }
        serializer = PasswordChangeSerializer(data=data, context={"request": request})
        assert not serializer.is_valid()
        assert "non_field_errors" in serializer.errors or "new_password" in serializer.errors

    def test_old_password_incorrect(self):
        user = User.objects.create_user(username="testuser", email="test@example.com", password="oldpass")
        factory = APIRequestFactory()
        request = factory.post("/")
        request.user = user
        data = {
            "old_password": "wrongpass",
            "new_password": "newpass",
            "new_password2": "newpass",
        }
        serializer = PasswordChangeSerializer(data=data, context={"request": request})
        assert not serializer.is_valid()
        assert "old_password" in serializer.errors

    def test_valid_password_change(self):
        user = User.objects.create_user(username="testuser", email="test@example.com", password="oldpass")
        factory = APIRequestFactory()
        request = factory.post("/")
        request.user = user
        data = {
            "old_password": "oldpass",
            "new_password": "newpass",
            "new_password2": "newpass",
        }
        serializer = PasswordChangeSerializer(data=data, context={"request": request})
        assert serializer.is_valid(), serializer.errors