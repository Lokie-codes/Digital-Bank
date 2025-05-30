import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from rest_framework.test import APIClient
from rest_framework import status

CustomUser = get_user_model()

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def users_group(db):
    return Group.objects.create(name='Users')

@pytest.fixture
def staff_group(db):
    return Group.objects.create(name='Staff')

@pytest.fixture
def managers_group(db):
    return Group.objects.create(name='Managers')

@pytest.fixture
def admin_user(db):
    user = CustomUser.objects.create_user(email='admin@example.com', password='adminpass', is_staff=True, is_superuser=True)
    return user

@pytest.fixture
def manager_user(db, managers_group):
    user = CustomUser.objects.create_user(email='manager@example.com', password='managerpass')
    user.groups.add(managers_group)
    return user

@pytest.fixture
def staff_user(db, staff_group):
    user = CustomUser.objects.create_user(email='staff@example.com', password='staffpass')
    user.groups.add(staff_group)
    return user

@pytest.fixture
def regular_user(db, users_group):
    user = CustomUser.objects.create_user(email='user@example.com', password='userpass')
    user.groups.add(users_group)
    return user

@pytest.mark.django_db
def test_user_registration(api_client, users_group):
    url = reverse('user-list')
    data = {
        'email': 'newuser@example.com',
        'password': 'newuserpass',
        'password2': 'newuserpass',
        'first_name': 'New',
        'last_name': 'User'
    }
    response = api_client.post(url, data)
    assert response.status_code == status.HTTP_201_CREATED
    assert CustomUser.objects.filter(email='newuser@example.com').exists()
    user = CustomUser.objects.get(email='newuser@example.com')
    assert users_group in user.groups.all()

@pytest.mark.django_db
def test_user_list_permissions(api_client, admin_user, manager_user, staff_user, regular_user):
    url = reverse('user-list')

    # Unauthenticated
    response = api_client.get(url)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    # Admin sees all
    api_client.force_authenticate(user=admin_user)
    response = api_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert len(response.data) >= 4

    # Manager sees staff, users, self
    api_client.force_authenticate(user=manager_user)
    response = api_client.get(url)
    emails = [u['email'] for u in response.data]
    assert manager_user.email in emails
    assert staff_user.email in emails
    assert regular_user.email in emails
    assert admin_user.email not in emails

    # Staff sees users, self
    api_client.force_authenticate(user=staff_user)
    response = api_client.get(url)
    emails = [u['email'] for u in response.data]
    assert staff_user.email in emails
    assert regular_user.email in emails
    assert manager_user.email not in emails
    assert admin_user.email not in emails

    # Regular user sees only self
    api_client.force_authenticate(user=regular_user)
    response = api_client.get(url)
    emails = [u['email'] for u in response.data]
    assert emails == [regular_user.email]

@pytest.mark.django_db
def test_me_endpoint(api_client, regular_user):
    url = reverse('user-me')
    api_client.force_authenticate(user=regular_user)
    response = api_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert response.data['email'] == regular_user.email

    # Update own profile
    patch_data = {'first_name': 'Updated'}
    response = api_client.patch(url, patch_data)
    assert response.status_code == status.HTTP_200_OK
    regular_user.refresh_from_db()
    assert regular_user.first_name == 'Updated'

@pytest.mark.django_db
def test_change_password(api_client, regular_user):
    url = reverse('user-change-password')
    api_client.force_authenticate(user=regular_user)
    data = {'old_password': 'userpass', 'new_password': 'newpass123', 'new_password2': 'newpass123'}
    response = api_client.post(url, data)
    assert response.status_code == status.HTTP_200_OK
    regular_user.refresh_from_db()
    assert regular_user.check_password('newpass123')

@pytest.mark.django_db
def test_activate_and_deactivate_user(api_client, admin_user, regular_user):
    deactivate_url = reverse('user-deactivate-user', args=[regular_user.pk])
    activate_url = reverse('user-activate-user', args=[regular_user.pk])

    api_client.force_authenticate(user=admin_user)
    # Deactivate
    response = api_client.post(deactivate_url)
    assert response.status_code == status.HTTP_200_OK
    regular_user.refresh_from_db()
    assert not regular_user.is_active

    # Activate
    response = api_client.post(activate_url)
    assert response.status_code == status.HTTP_200_OK
    regular_user.refresh_from_db()
    assert regular_user.is_active

@pytest.mark.django_db
def test_add_and_remove_group(api_client, admin_user, regular_user, staff_group):
    add_url = reverse('user-add-to-group', args=[regular_user.pk])
    remove_url = reverse('user-remove-from-group', args=[regular_user.pk])

    api_client.force_authenticate(user=admin_user)
    # Add to Staff group
    response = api_client.post(add_url, {'group_name': 'Staff'})
    assert response.status_code == status.HTTP_200_OK
    regular_user.refresh_from_db()
    assert staff_group in regular_user.groups.all()

    # Remove from Staff group
    response = api_client.post(remove_url, {'group_name': 'Staff'})
    assert response.status_code == status.HTTP_200_OK
    regular_user.refresh_from_db()
    assert staff_group not in regular_user.groups.all()

@pytest.mark.django_db
def test_set_staff_status(api_client, admin_user, regular_user):
    url = reverse('user-set-staff-status', args=[regular_user.pk])
    api_client.force_authenticate(user=admin_user)
    response = api_client.patch(url, {'is_staff': True})
    assert response.status_code == status.HTTP_200_OK
    regular_user.refresh_from_db()
    assert regular_user.is_staff

@pytest.mark.django_db
def test_destroy_user(api_client, admin_user, regular_user):
    url = reverse('user-detail', args=[regular_user.pk])
    api_client.force_authenticate(user=admin_user)
    response = api_client.delete(url)
    assert response.status_code == status.HTTP_204_NO_CONTENT
    regular_user.refresh_from_db()
    assert not regular_user.is_active