import pytest
from unittest.mock import Mock, MagicMock
from django.contrib.auth.models import AnonymousUser

from user.permissions import (
    IsInGroup, IsManagerGroup, IsStaffGroup,
    IsOwnerOrAdmin, IsOwnerOrManagerOrAdmin, IsOwnerOrStaffOrAdmin
)

@pytest.fixture
def user():
    user = Mock()
    user.is_authenticated = True
    user.is_superuser = False
    user.is_staff = False
    user.groups.filter = MagicMock(return_value=Mock(exists=Mock(return_value=False)))
    user.groups.values_list = MagicMock(return_value=[])
    return user

@pytest.fixture
def manager_user(user):
    user.groups.filter = MagicMock(side_effect=lambda **kwargs: Mock(exists=Mock(return_value=(kwargs.get('name') == 'Managers'))))
    user.groups.values_list = MagicMock(return_value=['Managers'])
    return user

@pytest.fixture
def staff_user(user):
    user.groups.filter = MagicMock(side_effect=lambda **kwargs: Mock(exists=Mock(return_value=(kwargs.get('name') == 'Staff'))))
    user.groups.values_list = MagicMock(return_value=['Staff'])
    return user

@pytest.fixture
def regular_user(user):
    user.groups.filter = MagicMock(side_effect=lambda **kwargs: Mock(exists=Mock(return_value=(kwargs.get('name') == 'Users'))))
    user.groups.values_list = MagicMock(return_value=['Users'])
    return user

@pytest.fixture
def superuser(user):
    user.is_superuser = True
    return user

@pytest.fixture
def staff_admin(user):
    user.is_staff = True
    return user

@pytest.fixture
def mock_request():
    req = Mock()
    req.user = None
    return req

@pytest.fixture
def view():
    return Mock()

def test_is_in_group_true(manager_user, request, view):
    request.user = manager_user
    perm = IsInGroup.create('Managers')()
    assert perm.has_permission(request, view)

def test_is_in_group_false(regular_user, request, view):
    request.user = regular_user
    perm = IsInGroup.create('Managers')()
    assert not perm.has_permission(request, view)

def test_is_manager_group(manager_user, request, view):
    request.user = manager_user
    perm = IsManagerGroup()
    assert perm.has_permission(request, view)

def test_is_staff_group(staff_user, request, view):
    request.user = staff_user
    perm = IsStaffGroup()
    assert perm.has_permission(request, view)

def test_is_in_group_anonymous(request, view):
    request.user = AnonymousUser()
    perm = IsInGroup.create('Managers')()
    assert not perm.has_permission(request, view)

def test_is_owner_or_admin_owner(regular_user, request, view):
    request.user = regular_user
    perm = IsOwnerOrAdmin()
    assert perm.has_object_permission(request, view, regular_user)

def test_is_owner_or_admin_superuser(superuser, regular_user, request, view):
    request.user = superuser
    perm = IsOwnerOrAdmin()
    assert perm.has_object_permission(request, view, regular_user)

def test_is_owner_or_admin_staff(staff_admin, regular_user, request, view):
    request.user = staff_admin
    staff_admin.is_authenticated = True
    staff_admin.is_superuser = False
    staff_admin.is_staff = True
    perm = IsOwnerOrAdmin()
    assert perm.has_object_permission(request, view, regular_user)

def test_is_owner_or_admin_not_owner(regular_user, mock_request, view):
    another_user = Mock()
    mock_request.user = regular_user
    perm = IsOwnerOrAdmin()
    assert not perm.has_object_permission(mock_request, view, another_user)

def test_is_owner_or_manager_or_admin_owner(regular_user, request, view):
    request.user = regular_user
    perm = IsOwnerOrManagerOrAdmin()
    assert perm.has_object_permission(request, view, regular_user)

def test_is_owner_or_manager_or_admin_manager_to_user(manager_user, regular_user, request, view):
    request.user = manager_user
    regular_user.groups.values_list = MagicMock(return_value=['Users'])
    perm = IsOwnerOrManagerOrAdmin()
    assert perm.has_object_permission(request, view, regular_user)

def test_is_owner_or_manager_or_admin_manager_to_staff(manager_user, staff_user, request, view):
    request.user = manager_user
    staff_user.groups.values_list = MagicMock(return_value=['Staff'])
    perm = IsOwnerOrManagerOrAdmin()
    assert perm.has_object_permission(request, view, staff_user)

def test_is_owner_or_manager_or_admin_manager_to_manager(manager_user, request, view):
    other_manager = Mock()
    other_manager.groups.values_list = MagicMock(return_value=['Managers'])
    request.user = manager_user
    perm = IsOwnerOrManagerOrAdmin()
    assert not perm.has_object_permission(request, view, other_manager)

def test_is_owner_or_manager_or_admin_superuser(superuser, regular_user, request, view):
    request.user = superuser
    perm = IsOwnerOrManagerOrAdmin()
    assert perm.has_object_permission(request, view, regular_user)

def test_is_owner_or_staff_or_admin_owner(regular_user, request, view):
    request.user = regular_user
    perm = IsOwnerOrStaffOrAdmin()
    assert perm.has_object_permission(request, view, regular_user)

def test_is_owner_or_staff_or_admin_staff_to_user(staff_user, regular_user, request, view):
    request.user = staff_user
    regular_user.groups.values_list = MagicMock(return_value=['Users'])
    perm = IsOwnerOrStaffOrAdmin()
    assert perm.has_object_permission(request, view, regular_user)

def test_is_owner_or_staff_or_admin_staff_to_staff(staff_user, request, view):
    other_staff = Mock()
    other_staff.groups.values_list = MagicMock(return_value=['Staff'])
    request.user = staff_user
    perm = IsOwnerOrStaffOrAdmin()
    assert not perm.has_object_permission(request, view, other_staff)

def test_is_owner_or_staff_or_admin_superuser(superuser, regular_user, request, view):
    request.user = superuser
    perm = IsOwnerOrStaffOrAdmin()
    assert perm.has_object_permission(request, view, regular_user)

def test_is_owner_or_staff_or_admin_staff_to_manager(staff_user, request, view):
    manager = Mock()
    manager.groups.values_list = MagicMock(return_value=['Managers'])
    request.user = staff_user
    perm = IsOwnerOrStaffOrAdmin()
    assert not perm.has_object_permission(request, view, manager)

def test_is_owner_or_staff_or_admin_anonymous(request, view):
    request.user = AnonymousUser()
    perm = IsOwnerOrStaffOrAdmin()
    obj = Mock()
    assert not perm.has_object_permission(request, view, obj)