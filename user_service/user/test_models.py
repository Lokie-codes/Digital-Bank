import pytest
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django.db.utils import IntegrityError

User = get_user_model()

@pytest.mark.django_db
def test_create_user_with_email_and_password():
    user = User.objects.create_user(email='test@example.com', password='testpass123')
    assert user.email == 'test@example.com'
    assert user.check_password('testpass123')
    assert user.is_active
    assert not user.is_staff
    assert not user.is_superuser

@pytest.mark.django_db
def test_create_user_without_email_raises_error():
    with pytest.raises(ValueError):
        User.objects.create_user(email=None, password='testpass123')

@pytest.mark.django_db
def test_create_superuser():
    superuser = User.objects.create_superuser(email='admin@example.com', password='adminpass')
    assert superuser.is_superuser
    assert superuser.is_staff
    assert superuser.is_active

@pytest.mark.django_db
def test_create_superuser_with_wrong_flags_raises_error():
    with pytest.raises(ValueError):
        User.objects.create_superuser(
            email='admin2@example.com',
            password='adminpass',
            is_staff=False
        )
    with pytest.raises(ValueError):
        User.objects.create_superuser(
            email='admin3@example.com',
            password='adminpass',
            is_superuser=False
        )

@pytest.mark.django_db
def test_email_is_unique():
    User.objects.create_user(email='unique@example.com', password='pass')
    with pytest.raises(IntegrityError):
        User.objects.create_user(email='unique@example.com', password='pass2')

@pytest.mark.django_db
def test_username_is_optional_and_unique():
    user1 = User.objects.create_user(email='user1@example.com', password='pass', username='user1')
    assert user1.username == 'user1'
    user2 = User.objects.create_user(email='user2@example.com', password='pass')
    assert user2.username == 'user2@example.com'  # fallback to email
    with pytest.raises(IntegrityError):
        User.objects.create_user(email='user3@example.com', password='pass', username='user1')

@pytest.mark.django_db
def test_get_full_name_and_short_name():
    user = User.objects.create_user(
        email='fullname@example.com',
        password='pass',
        first_name='John',
        last_name='Doe'
    )
    assert user.get_full_name() == 'John Doe'
    assert user.get_short_name() == 'John'

@pytest.mark.django_db
def test_str_returns_email():
    user = User.objects.create_user(email='str@example.com', password='pass')
    assert str(user) == 'str@example.com'

@pytest.mark.django_db
def test_role_field_and_properties():
    user = User.objects.create_user(email='role@example.com', password='pass', role='manager')
    assert user.role == 'manager'
    assert not user.is_admin
    assert not user.is_manager
    assert not user.is_a_staff

@pytest.mark.django_db
def test_is_admin_property_for_superuser():
    user = User.objects.create_superuser(email='adminprop@example.com', password='pass')
    assert user.is_admin

@pytest.mark.django_db
def test_clean_sets_username_to_email_if_blank():
    user = User(email='clean@example.com')
    user.clean()
    assert user.username == 'clean@example.com'

@pytest.mark.django_db
def test_create_user_sets_email_and_username():
    user = User.objects.create_user(email='foo@bar.com', password='secret', username='foobar')
    assert user.email == 'foo@bar.com'
    assert user.username == 'foobar'
    assert user.check_password('secret')

@pytest.mark.django_db
def test_create_user_username_defaults_to_email():
    user = User.objects.create_user(email='baz@qux.com', password='secret')
    assert user.username == 'baz@qux.com'

@pytest.mark.django_db
def test_create_user_raises_error_if_email_missing():
    with pytest.raises(ValueError):
        User.objects.create_user(email=None, password='secret')

@pytest.mark.django_db
def test_create_user_normalizes_email():
    user = User.objects.create_user(email='Test@Example.COM', password='pass')
    assert user.email == 'Test@example.com'

@pytest.mark.django_db
def test_create_user_sets_password_properly():
    user = User.objects.create_user(email='pwtest@example.com', password='mypassword')
    assert user.check_password('mypassword')
