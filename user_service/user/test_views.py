import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from rest_framework.test import APIClient
from rest_framework import status

pytestmark = pytest.mark.django_db

CustomUser = get_user_model()

@pytest.fixture
def users_group(db):
    return Group.objects.create(name="Users")

@pytest.fixture
def staff_group(db):
    return Group.objects.create(name="Staff")

@pytest.fixture
def manager_group(db):
    return Group.objects.create(name="Managers")

def test_manager_can_list_staff_and_users(api_client, manager_user, staff_user, regular_user):
    api_client.force_authenticate(user=manager_user)
    url = get_user_list_url()
    response = api_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    emails = [u["email"] for u in response.data]
    assert staff_user.email in emails
    assert regular_user.email in emails
    assert manager_user.email in emails

def test_staff_can_list_only_users_and_self(api_client, staff_user, regular_user):
    api_client.force_authenticate(user=staff_user)
    url = get_user_list_url()
    response = api_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    emails = [u["email"] for u in response.data]
    assert regular_user.email in emails
    assert staff_user.email in emails

def test_manager_can_update_user(api_client, manager_user, regular_user):
    api_client.force_authenticate(user=manager_user)
    url = get_user_detail_url(regular_user.pk)
    data = {"first_name": "ManagerEdit"}
    response = api_client.patch(url, data)
    assert response.status_code == status.HTTP_200_OK
    regular_user.refresh_from_db()
    assert regular_user.first_name == "ManagerEdit"

def test_staff_cannot_update_other_user(api_client, staff_user, regular_user):
    api_client.force_authenticate(user=staff_user)
    url = get_user_detail_url(regular_user.pk)
    data = {"first_name": "ShouldFail"}
    response = api_client.patch(url, data)
    assert response.status_code in (status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND)

def test_regular_user_cannot_add_to_group(api_client, regular_user, staff_user):
    api_client.force_authenticate(user=regular_user)
    url = get_add_to_group_url(staff_user.pk)
    data = {"group_name": "Managers"}
    response = api_client.post(url, data)
    assert response.status_code in (status.HTTP_403_FORBIDDEN, status.HTTP_401_UNAUTHORIZED)

def test_admin_cannot_remove_own_staff_status(api_client, admin_user):
    api_client.force_authenticate(user=admin_user)
    url = get_set_staff_status_url(admin_user.pk)
    data = {"is_staff": False}
    response = api_client.patch(url, data)
    assert response.status_code == status.HTTP_403_FORBIDDEN

def test_admin_cannot_deactivate_self_via_action(api_client, admin_user):
    api_client.force_authenticate(user=admin_user)
    url = get_deactivate_url(admin_user.pk)
    response = api_client.post(url)
    assert response.status_code == status.HTTP_403_FORBIDDEN

def test_add_to_nonexistent_group(api_client, admin_user, regular_user):
    api_client.force_authenticate(user=admin_user)
    url = get_add_to_group_url(regular_user.pk)
    data = {"group_name": "Nonexistent"}
    response = api_client.post(url, data)
    assert response.status_code == status.HTTP_400_BAD_REQUEST

def test_remove_from_group_not_member(api_client, admin_user, regular_user, staff_group):
    api_client.force_authenticate(user=admin_user)
    url = get_remove_from_group_url(regular_user.pk)
    data = {"group_name": "Staff"}
    response = api_client.post(url, data)
    assert response.status_code == status.HTTP_400_BAD_REQUEST

def test_change_password_wrong_old(api_client, regular_user):
    api_client.force_authenticate(user=regular_user)
    url = get_change_password_url()
    data = {"old_password": "wrongpass", "new_password": "newpass", "new_password2": "newpass"}
    response = api_client.post(url, data)
    assert response.status_code == status.HTTP_400_BAD_REQUEST

@pytest.fixture
def admin_user(db):
    user = CustomUser.objects.create_user(email="admin@example.com", password="adminpass", is_superuser=True, is_staff=True)
    return user

@pytest.fixture
def manager_user(db, manager_group):
    user = CustomUser.objects.create_user(email="manager@example.com", password="managerpass", is_staff=True)
    user.groups.add(manager_group)
    return user

@pytest.fixture
def staff_user(db, staff_group):
    user = CustomUser.objects.create_user(email="staff@example.com", password="staffpass")
    user.groups.add(staff_group)
    return user

@pytest.fixture
def regular_user(db, users_group):
    user = CustomUser.objects.create_user(email="user@example.com", password="userpass")
    user.groups.add(users_group)
    return user

@pytest.fixture
def api_client():
    return APIClient()

def get_user_detail_url(user_id):
    return reverse("user-detail", args=[user_id])

def get_user_list_url():
    return reverse("user-list")

def get_me_url():
    return reverse("user-me")

def get_change_password_url():
    return reverse("user-change-password")

def get_activate_url(user_id):
    return reverse("user-activate-user", args=[user_id])

def get_deactivate_url(user_id):
    return reverse("user-deactivate-user", args=[user_id])

def get_add_to_group_url(user_id):
    return reverse("user-add-to-group", args=[user_id])

def get_remove_from_group_url(user_id):
    return reverse("user-remove-from-group", args=[user_id])

def get_set_staff_status_url(user_id):
    return reverse("user-set-staff-status", args=[user_id])

def test_user_registration(api_client, users_group):
    url = get_user_list_url()
    data = {
        "email": "newuser@example.com",
        "password": "newpass123",
        "first_name": "New",
        "last_name": "User",
        "password2": "newpass123",
    }
    response = api_client.post(url, data)
    assert response.status_code == status.HTTP_201_CREATED
    assert CustomUser.objects.filter(email="newuser@example.com").exists()

def test_user_list_admin(api_client, admin_user, regular_user):
    api_client.force_authenticate(user=admin_user)
    url = get_user_list_url()
    response = api_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert any(u["email"] == regular_user.email for u in response.data)

def test_user_list_regular_user(api_client, regular_user):
    api_client.force_authenticate(user=regular_user)
    url = get_user_list_url()
    response = api_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert len(response.data) == 1
    assert response.data[0]["email"] == regular_user.email

def test_user_retrieve_self(api_client, regular_user):
    api_client.force_authenticate(user=regular_user)
    url = get_user_detail_url(regular_user.pk)
    response = api_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert response.data["email"] == regular_user.email

def test_user_retrieve_other_forbidden(api_client, regular_user, staff_user):
    api_client.force_authenticate(user=regular_user)
    url = get_user_detail_url(staff_user.pk)
    response = api_client.get(url)
    assert response.status_code in (status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND)

def test_user_update_self(api_client, regular_user):
    api_client.force_authenticate(user=regular_user)
    url = get_user_detail_url(regular_user.pk)
    data = {"first_name": "Changed"}
    response = api_client.patch(url, data)
    assert response.status_code == status.HTTP_200_OK
    regular_user.refresh_from_db()
    assert regular_user.first_name == "Changed"

def test_user_destroy_admin(api_client, admin_user, regular_user):
    api_client.force_authenticate(user=admin_user)
    url = get_user_detail_url(regular_user.pk)
    response = api_client.delete(url)
    assert response.status_code == status.HTTP_204_NO_CONTENT
    regular_user.refresh_from_db()
    assert not regular_user.is_active

def test_user_destroy_self_admin_forbidden(api_client, admin_user):
    api_client.force_authenticate(user=admin_user)
    url = get_user_detail_url(admin_user.pk)
    response = api_client.delete(url)
    assert response.status_code == status.HTTP_403_FORBIDDEN

def test_me_get(api_client, regular_user):
    api_client.force_authenticate(user=regular_user)
    url = get_me_url()
    response = api_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert response.data["email"] == regular_user.email

def test_me_patch(api_client, regular_user):
    api_client.force_authenticate(user=regular_user)
    url = get_me_url()
    data = {"first_name": "MePatch"}
    response = api_client.patch(url, data)
    assert response.status_code == status.HTTP_200_OK
    regular_user.refresh_from_db()
    assert regular_user.first_name == "MePatch"

def test_change_password(api_client, regular_user):
    api_client.force_authenticate(user=regular_user)
    url = get_change_password_url()
    data = {"old_password": "userpass", "new_password": "newuserpass123", "new_password2": "newuserpass123"}
    response = api_client.post(url, data)
    assert response.status_code == status.HTTP_200_OK
    regular_user.refresh_from_db()
    assert regular_user.check_password("newuserpass123")

def test_activate_user(api_client, admin_user, regular_user):
    regular_user.is_active = False
    regular_user.save()
    api_client.force_authenticate(user=admin_user)
    url = get_activate_url(regular_user.pk)
    response = api_client.post(url)
    assert response.status_code == status.HTTP_200_OK
    regular_user.refresh_from_db()
    assert regular_user.is_active

def test_deactivate_user(api_client, admin_user, regular_user):
    api_client.force_authenticate(user=admin_user)
    url = get_deactivate_url(regular_user.pk)
    response = api_client.post(url)
    assert response.status_code == status.HTTP_200_OK
    regular_user.refresh_from_db()
    assert not regular_user.is_active

def test_add_to_group(api_client, admin_user, regular_user, staff_group):
    api_client.force_authenticate(user=admin_user)
    url = get_add_to_group_url(regular_user.pk)
    data = {"group_name": "Staff"}
    response = api_client.post(url, data)
    assert response.status_code == status.HTTP_200_OK
    assert staff_group in regular_user.groups.all()

def test_remove_from_group(api_client, admin_user, staff_user, staff_group):
    api_client.force_authenticate(user=admin_user)
    url = get_remove_from_group_url(staff_user.pk)
    data = {"group_name": "Staff"}
    response = api_client.post(url, data)
    assert response.status_code == status.HTTP_200_OK
    staff_user.refresh_from_db()
    assert staff_group not in staff_user.groups.all()

def test_set_staff_status(api_client, admin_user, regular_user):
    api_client.force_authenticate(user=admin_user)
    url = get_set_staff_status_url(regular_user.pk)
    data = {"is_staff": True}
    response = api_client.patch(url, data)
    assert response.status_code == status.HTTP_200_OK
    regular_user.refresh_from_db()
    assert regular_user.is_staff