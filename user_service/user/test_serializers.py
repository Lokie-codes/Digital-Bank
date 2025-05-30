import pytest
from django.contrib.auth import get_user_model
from .serializers import CustomUserCreateSerializer
from django.contrib.auth.models import Group, AnonymousUser
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIRequestFactory
from .serializers import (
        GroupManagementSerializer,
        StaffStatusSerializer,
        CustomUserCreateSerializer,
        CustomUserDetailSerializer,
        CustomUserListSerializer,
        PasswordChangeSerializer,
        CustomTokenObtainPairSerializer,
    )


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


@pytest.mark.parametrize("group_name", ["Managers", "Staff", "Users"])
def test_group_management_serializer_valid(group_name):
    serializer = GroupManagementSerializer(data={"group_name": group_name})
    assert serializer.is_valid(), serializer.errors
    assert serializer.validated_data["group_name"] == group_name


def test_group_management_serializer_missing_group_name():
    serializer = GroupManagementSerializer(data={})
    assert not serializer.is_valid()
    assert "group_name" in serializer.errors


@pytest.mark.parametrize("is_staff", [True, False])
def test_staff_status_serializer_valid(is_staff):
    serializer = StaffStatusSerializer(data={"is_staff": is_staff})
    assert serializer.is_valid(), serializer.errors
    assert serializer.validated_data["is_staff"] is is_staff


def test_staff_status_serializer_missing_is_staff():
    serializer = StaffStatusSerializer(data={})
    assert not serializer.is_valid()
    assert "is_staff" in serializer.errors


@pytest.mark.django_db
def test_custom_user_detail_serializer_read_only_fields():
    user = User.objects.create_user(
        username="readonlyuser",
        email="readonly@example.com",
        password="readonlypass",
        first_name="Read",
        last_name="Only",
        role="user",
        is_staff=True,
        is_superuser=True,
    )
    group = Group.objects.create(name="TestGroup")
    user.groups.add(group)
    serializer = CustomUserDetailSerializer(user)
    data = serializer.data
    assert data["username"] == "readonlyuser"
    assert data["groups"] == ["TestGroup"]
    assert data["is_staff"] is True
    assert data["is_superuser"] is True
    assert "password" not in data


@pytest.mark.django_db
def test_custom_user_detail_serializer_update_excludes_password_and_staff(monkeypatch):
    user = User.objects.create_user(
        username="updateuser",
        email="update@example.com",
        password="updatepass",
        first_name="Update",
        last_name="User",
        role="user",
        is_staff=False,
        is_superuser=False,
    )
    request = APIRequestFactory().put("/")
    request.user = user  # Not a superuser
    serializer = CustomUserDetailSerializer(
        user,
        data={
            "first_name": "Updated",
            "is_staff": True,
            "password": "newpass",
        },
        partial=True,
        context={"request": request},
    )
    assert serializer.is_valid(), serializer.errors
    updated_user = serializer.save()
    assert updated_user.first_name == "Updated"
    assert not updated_user.is_staff  # Should not be updated by non-superuser
    assert not updated_user.check_password("newpass")  # Password not updated


@pytest.mark.django_db
def test_custom_user_list_serializer_fields():
    user = User.objects.create_user(
        username="listuser",
        email="listuser@example.com",
        password="listpass",
        first_name="List",
        last_name="User",
        role="user",
    )
    group = Group.objects.create(name="ListGroup")
    user.groups.add(group)
    serializer = CustomUserListSerializer(user)
    data = serializer.data
    assert data["username"] == "listuser"
    assert data["groups"] == ["ListGroup"]
    assert "password" not in data
    assert data["role"] == "user"


@pytest.mark.django_db
def test_custom_token_obtain_pair_serializer_get_token_fields():
    user = User.objects.create_user(
        username="jwtuser",
        email="jwtuser@example.com",
        password="jwtpass",
        first_name="JWT",
        last_name="User",
        role="admin",
        is_staff=True,
        is_superuser=True,
    )
    group = Group.objects.create(name="JWTGroup")
    user.groups.add(group)
    token = CustomTokenObtainPairSerializer.get_token(user)
    assert token["email"] == "jwtuser@example.com"
    assert token["username"] == "jwtuser"
    assert token["is_staff"] is True
    assert token["is_superuser"] is True
    assert "JWTGroup" in token["groups"]
    assert token["role"] == "admin"


def test_password_change_serializer_valid(monkeypatch):
    class DummyUser:
        def check_password(self, value):
            return value == "oldpass"

    request = APIRequestFactory().post("/")
    request.user = DummyUser()
    serializer = PasswordChangeSerializer(
        data={
            "old_password": "oldpass",
            "new_password": "newpass123",
            "new_password2": "newpass123",
        },
        context={"request": request},
    )
    assert serializer.is_valid(), serializer.errors
    assert serializer.validated_data["old_password"] == "oldpass"


def test_password_change_serializer_new_passwords_do_not_match():
    class DummyUser:
        def check_password(self, value):
            return True  # or False, doesn't matter for this test

    request = APIRequestFactory().post("/")
    request.user = DummyUser()
    serializer = PasswordChangeSerializer(
        data={
            "old_password": "oldpass",
            "new_password": "newpass1",
            "new_password2": "newpass2",
        },
        context={"request": request},
    )
    assert not serializer.is_valid()
    assert "non_field_errors" in serializer.errors or "New passwords do not match." in str(serializer.errors)


def test_password_change_serializer_invalid_old_password():
    class DummyUser:
        def check_password(self, value):
            return False

    request = APIRequestFactory().post("/")
    request.user = DummyUser()
    serializer = PasswordChangeSerializer(
        data={
            "old_password": "wrongpass",
            "new_password": "newpass",
            "new_password2": "newpass",
        },
        context={"request": request},
    )
    assert not serializer.is_valid()
    assert "old_password" in serializer.errors or "incorrectly" in str(serializer.errors)
