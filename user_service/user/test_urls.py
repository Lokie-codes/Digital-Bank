import pytest
from django.urls import reverse, resolve
from rest_framework.routers import DefaultRouter
from user import views as user_views
from user import auth_views

@pytest.mark.django_db
def test_users_list_url_resolves():
    # The router registers 'users' endpoint
    router = DefaultRouter()
    router.register(r'users', user_views.UserViewSet, basename='user')
    # Get the first registered url pattern for 'users-list'
    url = router.urls[0].pattern.describe()
    assert 'users' in url

@pytest.mark.django_db
def test_token_obtain_pair_url_resolves():
    resolver = resolve('/api/auth/token/')
    assert resolver.func.view_class == auth_views.CustomTokenObtainPairView
    assert resolver.url_name == 'token_obtain_pair'
    
@pytest.mark.django_db
def test_router_users_url_patterns():
    """
    Ensure that the router registers the correct viewset and basename.
    """
    router = DefaultRouter()
    router.register(r'users', user_views.UserViewSet, basename='user')
    urls = [u.pattern.describe() for u in router.urls]
    assert any('users' in url for url in urls)
    # Check that the viewset is correctly registered
    assert router.registry[0][0] == 'users'
    assert router.registry[0][1] == user_views.UserViewSet
    assert router.registry[0][2] == 'user'

@pytest.mark.django_db
def test_auth_token_url_reverse():
    """
    Ensure that the 'token_obtain_pair' url can be reversed and resolves to the correct view.
    """
    url = reverse('token_obtain_pair')
    assert url.endswith('/auth/token/')
    resolver = resolve(url)
    assert resolver.func.view_class == auth_views.CustomTokenObtainPairView
    assert resolver.url_name == 'token_obtain_pair'




