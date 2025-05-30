# users/views.py
from rest_framework import status, serializers
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny, BasePermission, IsAdminUser as DRFIsAdminUser # Renamed to avoid conflict
from rest_framework.decorators import action
from rest_framework.viewsets import ModelViewSet
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group # Import Group model
from django.utils.translation import gettext_lazy as _
from django.shortcuts import get_object_or_404
from django.db.models import Q # For complex queries

from .serialiazers import (
    CustomUserCreateSerializer,
    CustomUserDetailSerializer,
    CustomUserListSerializer,
    CustomTokenObtainPairSerializer,
    PasswordChangeSerializer,
)

CustomUser = get_user_model()

# --- Custom Group-Based Permissions ---

class IsInGroup(BasePermission):
    """
    Custom permission to check if the user is in a specific group.
    Usage: permission_classes = [IsInGroup.create('Managers')]
    """
    required_group = None

    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated:
            return request.user.groups.filter(name=self.required_group).exists()
        return False

    @classmethod
    def create(cls, group_name):
        return type(f'IsIn{group_name}Group', (cls,), {'required_group': group_name})

# Define specific group permission instances
IsManagerGroup = IsInGroup.create('Managers')
IsStaffGroup = IsInGroup.create('Staff')


class IsOwnerOrAdmin(BasePermission):
    """
    Allows access to the object owner OR a superuser/DRFIsAdminUser.
    """
    def has_object_permission(self, request, view, obj):
        if request.user and request.user.is_authenticated:
            # Superusers always have permission
            if request.user.is_superuser:
                return True
            # Allow DRFIsAdminUser (is_staff=True) to manage others
            # if they are allowed to manage based on their specific permissions
            # Note: This might need more refinement if is_staff doesn't mean "admin-level"
            # For this context, we'll assume DRFIsAdminUser implies sufficient privilege for obj management
            if DRFIsAdminUser().has_permission(request, view):
                return True
            # Owner can manage their own object
            return obj == request.user
        return False

class IsOwnerOrManagerOrAdmin(BasePermission):
    """
    Allows access to the object owner, or a Manager group member, or a Superuser/DRFIsAdminUser.
    Used for update/retrieve where managers can manage staff/users.
    """
    def has_object_permission(self, request, view, obj):
        if request.user and request.user.is_authenticated:
            # Superusers always have permission
            if request.user.is_superuser:
                return True
            # DRFIsAdminUser (is_staff=True) has permission
            if DRFIsAdminUser().has_permission(request, view):
                 return True

            # Managers can update Staff and regular Users, but not themselves or Admins
            if IsManagerGroup().has_permission(request, view):
                if obj == request.user: # Manager can view/update their own profile
                    return True
                # Manager can update/retrieve Staff and User accounts
                # This assumes 'Staff' and 'Users' are group names for these roles
                target_user_groups = obj.groups.values_list('name', flat=True)
                return ('Staff' in target_user_groups or 'Users' in target_user_groups)
            
            # Regular user can only access their own object
            return obj == request.user
        return False


class IsOwnerOrStaffOrAdmin(BasePermission):
    """
    Allows access to the object owner, or a Staff group member, or a Superuser/DRFIsAdminUser.
    Used for retrieve where staff can view any user.
    """
    def has_object_permission(self, request, view, obj):
        if request.user and request.user.is_authenticated:
            # Superusers always have permission
            if request.user.is_superuser:
                return True
            # DRFIsAdminUser (is_staff=True) has permission
            if DRFIsAdminUser().has_permission(request, view):
                 return True

            # Staff can retrieve regular Users, but not Managers or Admins, or other Staff
            if IsStaffGroup().has_permission(request, view):
                if obj == request.user: # Staff can view their own profile
                    return True
                # Staff can retrieve User accounts (assuming 'Users' is a group name)
                target_user_groups = obj.groups.values_list('name', flat=True)
                return 'Users' in target_user_groups
            
            # Regular user can only access their own object
            return obj == request.user
        return False


# --- Views ---

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data
        return Response(token, status=status.HTTP_200_OK)

class UserViewSet(ModelViewSet):
    queryset = CustomUser.objects.all().order_by('id')
    serializer_class = CustomUserListSerializer
    lookup_field = 'pk'

    def get_queryset(self):
        """
        Dynamically adjust queryset based on user group membership.
        """
        user = self.request.user
        if user.is_authenticated:
            if user.is_superuser or DRFIsAdminUser().has_permission(self.request, self):
                return CustomUser.objects.all().order_by('id') # Admins/Superusers see all

            # Managers see users in 'Staff' or 'Users' group, and themselves
            if IsManagerGroup().has_permission(self.request, self):
                return CustomUser.objects.filter(
                    Q(groups__name='Staff') | Q(groups__name='Users') | Q(pk=user.pk)
                ).distinct().order_by('id')

            # Staff see users in 'Users' group, and themselves
            if IsStaffGroup().has_permission(self.request, self):
                return CustomUser.objects.filter(
                    Q(groups__name='Users') | Q(pk=user.pk)
                ).distinct().order_by('id')
            
            # Regular users only see themselves
            return CustomUser.objects.filter(pk=user.pk).order_by('id')
        
        return CustomUser.objects.none() # No unauthenticated access to list

    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        if self.action == 'create': # User Registration
            self.permission_classes = [AllowAny]
        elif self.action == 'list': # List all users (subset based on get_queryset)
            self.permission_classes = [IsAuthenticated] # All authenticated can list subset
        elif self.action == 'retrieve': # Retrieve specific user
            self.permission_classes = [IsOwnerOrStaffOrAdmin] # Staff can retrieve users, managers can retrieve staff/users, owner can retrieve self, admin can retrieve all
        elif self.action in ['update', 'partial_update']: # Update specific user
            self.permission_classes = [IsOwnerOrManagerOrAdmin] # Manager can update staff/users, owner can update self, admin can update all
        elif self.action == 'destroy': # Soft delete user
            self.permission_classes = [DRFIsAdminUser] # Only DRFIsAdminUser can delete
        elif self.action in ['me', 'change_password']: # Self-management
            self.permission_classes = [IsAuthenticated]
        elif self.action in ['activate_user', 'deactivate_user', 'add_to_group', 'remove_from_group', 'set_staff_status']: # Admin actions
            self.permission_classes = [DRFIsAdminUser]
        else:
            self.permission_classes = [IsAuthenticated] # Default safe permission

        return [permission() for permission in self.permission_classes]

    def get_serializer_class(self):
        if self.action == 'create':
            return CustomUserCreateSerializer
        elif self.action == 'list':
            return CustomUserListSerializer
        elif self.action in ['retrieve', 'me']:
            return CustomUserDetailSerializer
        elif self.action in ['update', 'partial_update']:
            return CustomUserDetailSerializer # Use the detail serializer for updates
        elif self.action == 'change_password':
            return PasswordChangeSerializer
        elif self.action in ['add_to_group', 'remove_from_group']:
            class GroupManagementSerializer(serializers.Serializer):
                group_name = serializers.CharField(max_length=150, required=True)
            return GroupManagementSerializer
        elif self.action == 'set_staff_status':
            class StaffStatusSerializer(serializers.Serializer):
                is_staff = serializers.BooleanField(required=True)
            return StaffStatusSerializer
        return super().get_serializer_class()

    def perform_create(self, serializer):
        user = serializer.save()
        # Optional: Add newly created user to a default 'Users' group if it exists
        try:
            default_group = Group.objects.get(name='Users')
            user.groups.add(default_group)
        except Group.DoesNotExist:
            pass # Or log an error, or create the group dynamically

    def perform_destroy(self, instance):
        instance.is_active = False
        instance.save()

    @action(detail=False, methods=['get', 'put', 'patch'], url_path='me')
    def me(self, request):
        if request.method == 'GET':
            serializer = self.get_serializer(request.user)
            return Response(serializer.data)
        elif request.method in ['PUT', 'PATCH']:
            # The CustomUserDetailSerializer will prevent non-superusers from changing is_staff/groups
            serializer = self.get_serializer(request.user, data=request.data, partial=True, context={'request': request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    @action(detail=False, methods=['post'], url_path='change-password')
    def change_password(self, request):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        user = request.user
        user.set_password(serializer.validated_data['new_password'])
        user.save()

        return Response({"message": _("Password changed successfully.")}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='activate', permission_classes=[DRFIsAdminUser])
    def activate_user(self, request, pk=None):
        user = get_object_or_404(CustomUser, pk=pk)
        if not user.is_active:
            user.is_active = True
            user.save()
            return Response({"message": _(f"User '{user.email}' activated successfully.")}, status=status.HTTP_200_OK)
        return Response({"message": _(f"User '{user.email}' is already active.")}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'], url_path='deactivate', permission_classes=[DRFIsAdminUser])
    def deactivate_user(self, request, pk=None):
        user = get_object_or_404(CustomUser, pk=pk)
        if user.is_active:
            # Prevent superuser/DRFIsAdminUser from deactivating themselves
            if user == request.user and (request.user.is_superuser or DRFIsAdminUser().has_permission(request, self)):
                return Response({"message": _("Admin users cannot deactivate themselves.")}, status=status.HTTP_403_FORBIDDEN)
            user.is_active = False
            user.save()
            return Response({"message": _(f"User '{user.email}' deactivated successfully.")}, status=status.HTTP_200_OK)
        return Response({"message": _(f"User '{user.email}' is already inactive.")}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'], url_path='add-to-group', permission_classes=[DRFIsAdminUser])
    def add_to_group(self, request, pk=None):
        """
        Add a user to a specified group. Only for superusers.
        """
        user_to_update = get_object_or_404(CustomUser, pk=pk)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        group_name = serializer.validated_data['group_name']

        try:
            group = Group.objects.get(name=group_name)
            user_to_update.groups.add(group)
            return Response({"message": _(f"User '{user_to_update.email}' added to group '{group_name}'.")}, status=status.HTTP_200_OK)
        except Group.DoesNotExist:
            return Response({"message": _(f"Group '{group_name}' does not exist.")}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'], url_path='remove-from-group', permission_classes=[DRFIsAdminUser])
    def remove_from_group(self, request, pk=None):
        """
        Remove a user from a specified group. Only for superusers.
        """
        user_to_update = get_object_or_404(CustomUser, pk=pk)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        group_name = serializer.validated_data['group_name']

        try:
            group = Group.objects.get(name=group_name)
            if group in user_to_update.groups.all():
                user_to_update.groups.remove(group)
                return Response({"message": _(f"User '{user_to_update.email}' removed from group '{group_name}'.")}, status=status.HTTP_200_OK)
            return Response({"message": _(f"User '{user_to_update.email}' is not in group '{group_name}'.")}, status=status.HTTP_400_BAD_REQUEST)
        except Group.DoesNotExist:
            return Response({"message": _(f"Group '{group_name}' does not exist.")}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['patch'], url_path='set-staff-status', permission_classes=[DRFIsAdminUser])
    def set_staff_status(self, request, pk=None):
        """
        Set the is_staff status of a user. Only for superusers.
        """
        user_to_update = get_object_or_404(CustomUser, pk=pk)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        new_staff_status = serializer.validated_data['is_staff']
        
        # Prevent superuser from setting own is_staff to False (if it's their only admin access)
        if user_to_update == request.user and request.user.is_superuser and not new_staff_status:
             return Response({"message": _("Superusers cannot remove their own staff status directly.")}, status=status.HTTP_403_FORBIDDEN)

        user_to_update.is_staff = new_staff_status
        user_to_update.save()
        return Response(CustomUserDetailSerializer(user_to_update).data, status=status.HTTP_200_OK)

    # Override the default retrieve/update/destroy methods to ensure object permissions are checked
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        self.check_object_permissions(request, instance) # Explicitly check object permissions
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        self.check_object_permissions(request, instance) # Explicitly check object permissions

        # The serializer's update method handles preventing non-superusers from changing staff/groups
        serializer = self.get_serializer(instance, data=request.data, partial=partial, context={'request': request})
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(CustomUserDetailSerializer(instance).data) # Return updated instance data

    def partial_update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.check_object_permissions(request, instance) # Ensure permission is checked
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)