# users/views.py
from rest_framework import status, serializers # Keep serializers for potential inline ones if ever needed
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser as DRFIsAdminUser
from rest_framework.decorators import action
from rest_framework.viewsets import ModelViewSet
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.utils.translation import gettext_lazy as _
from django.shortcuts import get_object_or_404
from django.db.models import Q
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes

# Local imports
from .serializers import ( # Corrected typo from 'serialiazers'
    CustomUserCreateSerializer,
    CustomUserDetailSerializer,
    CustomUserListSerializer,
    PasswordChangeSerializer,
    GroupManagementSerializer, # Assuming this is defined in serializers.py
    StaffStatusSerializer      # Assuming this is defined in serializers.py
)
from .permissions import (
    IsOwnerOrAdmin,
    IsOwnerOrManagerOrAdmin,
    IsOwnerOrStaffOrAdmin,
    IsManagerGroup,
    IsStaffGroup
)

CustomUser = get_user_model()

@extend_schema(tags=['User Management'])
class UserViewSet(ModelViewSet):
    """
    A ViewSet for managing user accounts, with extensive group-based access control.

    Permissions are applied dynamically based on the requesting user's group memberships and `is_superuser`/`is_staff` status.
    - **Admins (Superusers/is_staff)**: Full access to all user accounts and management actions.
    - **Managers**: Can list, retrieve, and update Staff and regular User accounts.
    - **Staff**: Can list and retrieve regular User accounts.
    - **Regular Users**: Can only view and update their own profile, and change their password.
    """
    queryset = CustomUser.objects.all().order_by('id')
    serializer_class = CustomUserListSerializer # Default serializer
    lookup_field = 'pk'

    def get_queryset(self):
        user = self.request.user
        if user.is_authenticated:
            if user.is_superuser or DRFIsAdminUser().has_permission(self.request, self):
                return CustomUser.objects.all().order_by('id')

            if IsManagerGroup().has_permission(self.request, self):
                return CustomUser.objects.filter(
                    Q(groups__name='Staff') | Q(groups__name='Users') | Q(pk=user.pk)
                ).distinct().order_by('id')

            if IsStaffGroup().has_permission(self.request, self):
                return CustomUser.objects.filter(
                    Q(groups__name='Users') | Q(pk=user.pk)
                ).distinct().order_by('id')
            
            return CustomUser.objects.filter(pk=user.pk).order_by('id')
        
        return CustomUser.objects.none()

    def get_permissions(self):
        if self.action == 'create':
            self.permission_classes = [AllowAny]
        elif self.action == 'list':
            self.permission_classes = [IsAuthenticated]
        elif self.action == 'retrieve':
            self.permission_classes = [IsAuthenticated, IsOwnerOrStaffOrAdmin] # Added IsAuthenticated
        elif self.action in ['update', 'partial_update']:
            self.permission_classes = [IsAuthenticated, IsOwnerOrManagerOrAdmin] # Added IsAuthenticated
        elif self.action == 'destroy':
            self.permission_classes = [DRFIsAdminUser]
        elif self.action in ['me', 'change_password']:
            self.permission_classes = [IsAuthenticated]
        # For admin actions, permissions are often set directly on the @action decorator
        # but can also be managed here if preferred.
        elif self.action in ['activate_user', 'deactivate_user', 'add_to_group', 'remove_from_group', 'set_staff_status']:
             self.permission_classes = [DRFIsAdminUser] # General admin restriction
        else:
            self.permission_classes = [IsAuthenticated]
        return [permission() for permission in self.permission_classes]

    def get_serializer_class(self):
        if self.action == 'create':
            return CustomUserCreateSerializer
        elif self.action == 'list':
            return CustomUserListSerializer
        elif self.action in ['retrieve', 'me']:
            return CustomUserDetailSerializer
        elif self.action in ['update', 'partial_update']:
            return CustomUserDetailSerializer
        elif self.action == 'change_password':
            return PasswordChangeSerializer
        elif self.action in ['add_to_group', 'remove_from_group']:
            return GroupManagementSerializer # Use the imported serializer
        elif self.action == 'set_staff_status':
            return StaffStatusSerializer     # Use the imported serializer
        return super().get_serializer_class()

    @extend_schema(
        summary='Register a New User',
        description='Allows anyone to create a new user account. Newly created users are optionally added to the "Users" group.',
        request=CustomUserCreateSerializer,
        responses={201: CustomUserDetailSerializer, 400: {'description': 'Bad Request - Validation Errors'}},
    )
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        # Use CustomUserDetailSerializer for the response after creation for more detail
        user_detail_serializer = CustomUserDetailSerializer(serializer.instance, context=self.get_serializer_context())
        headers = self.get_success_headers(user_detail_serializer.data)
        return Response(user_detail_serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        user = serializer.save()
        try:
            default_group = Group.objects.get(name='Users')
            user.groups.add(default_group)
        except Group.DoesNotExist:
            # Consider logging this: logger.warning("Default 'Users' group not found during user creation.")
            pass

    @extend_schema(
        summary='List Users',
        description='Retrieves a list of users. Filtered based on requester\'s permissions.',
        responses={200: CustomUserListSerializer(many=True), 401: {'description': 'Authentication credentials were not provided.'}},
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @extend_schema(
        summary='Retrieve User Details',
        description='Retrieves the details of a specific user by ID.',
        parameters=[OpenApiParameter(name='pk', type=OpenApiTypes.INT, description='User ID', required=True, location=OpenApiParameter.PATH)],
        responses={
            200: CustomUserDetailSerializer,
            401: {'description': 'Authentication credentials were not provided.'},
            403: {'description': 'Permission Denied'},
            404: {'description': 'Not Found'},
        },
    )
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        # self.check_object_permissions(request, instance) # Already handled by get_permissions + DRF
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    @extend_schema(
        summary='Update User Details (Full)',
        description='Updates all details of a specific user by ID.',
        parameters=[OpenApiParameter(name='pk', type=OpenApiTypes.INT, description='User ID', required=True, location=OpenApiParameter.PATH)],
        request=CustomUserDetailSerializer,
        responses={
            200: CustomUserDetailSerializer,
            400: {'description': 'Bad Request - Validation Errors'},
            401: {'description': 'Authentication credentials were not provided.'},
            403: {'description': 'Permission Denied'},
            404: {'description': 'Not Found'},
        },
    )
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        # self.check_object_permissions(request, instance) # Already handled by get_permissions + DRF
        serializer = self.get_serializer(instance, data=request.data, partial=partial, context={'request': request})
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(CustomUserDetailSerializer(instance, context=self.get_serializer_context()).data)


    @extend_schema(
        summary='Update User Details (Partial)',
        description='Partially updates details of a specific user by ID.',
        parameters=[OpenApiParameter(name='pk', type=OpenApiTypes.INT, description='User ID', required=True, location=OpenApiParameter.PATH)],
        request=CustomUserDetailSerializer, # Or a specific partial update serializer if fields differ significantly
        responses={
            200: CustomUserDetailSerializer,
            400: {'description': 'Bad Request - Validation Errors'},
            401: {'description': 'Authentication credentials were not provided.'},
            403: {'description': 'Permission Denied'},
            404: {'description': 'Not Found'},
        },
    )
    def partial_update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)

    @extend_schema(
        summary='Soft Delete User (Deactivate)',
        description='Deactivates a user account by setting `is_active` to `false`. Only Admin/Superuser.',
        parameters=[OpenApiParameter(name='pk', type=OpenApiTypes.INT, description='User ID to deactivate', required=True, location=OpenApiParameter.PATH)],
        responses={
            204: {'description': 'User deactivated successfully.'},
            400: {'description': 'Bad Request - User already inactive or admin deactivating self.'},
            401: {'description': 'Authentication credentials were not provided.'},
            403: {'description': 'Permission Denied or Admin cannot deactivate themselves.'},
            404: {'description': 'Not Found'},
        },
    )
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        # self.check_object_permissions(request, instance) # Already handled by get_permissions + DRF
        
        # Prevent admin from deactivating themselves via the standard destroy action
        # The 'deactivate_user' action has more specific logic for this.
        # Here, we simply check if the admin is trying to destroy (deactivate) themselves.
        if instance == request.user and (request.user.is_superuser or DRFIsAdminUser().has_permission(request, self)):
             return Response({"message": _("Admins cannot deactivate their own account using this generic endpoint. Use the specific 'deactivate' action if applicable, or manage through Django admin.")}, status=status.HTTP_403_FORBIDDEN)

        if not instance.is_active:
            return Response({"message": _("User is already inactive.")}, status=status.HTTP_400_BAD_REQUEST)

        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    def perform_destroy(self, instance):
        instance.is_active = False
        instance.save()

    # --- Custom Actions ---
    @extend_schema(
        summary='Manage My Profile',
        description='Retrieves, updates (full), or partially updates the details of the currently authenticated user.',
        request=CustomUserDetailSerializer, # Applies to PUT/PATCH
        responses={200: CustomUserDetailSerializer, 400: {}, 401: {}},
        tags=['Self Management']
    )
    @action(detail=False, methods=['get', 'put', 'patch'], url_path='me', permission_classes=[IsAuthenticated])
    def me(self, request):
        user = request.user
        if request.method == 'GET':
            serializer = CustomUserDetailSerializer(user, context=self.get_serializer_context())
            return Response(serializer.data)
        
        elif request.method in ['PUT', 'PATCH']:
            partial = request.method == 'PATCH'
            # Pass request to context for serializer, might be needed for some validation logic
            serializer = CustomUserDetailSerializer(user, data=request.data, partial=partial, context={'request': request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    @extend_schema(
        summary='Change My Password',
        description='Allows the currently authenticated user to change their password.',
        request=PasswordChangeSerializer,
        responses={200: {'description': 'Password changed successfully.'}, 400: {}, 401: {}},
        tags=['Self Management']
    )
    @action(detail=False, methods=['post'], url_path='change-password', permission_classes=[IsAuthenticated])
    def change_password(self, request):
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        request.user.set_password(serializer.validated_data['new_password'])
        request.user.save()
        return Response({"message": _("Password changed successfully.")}, status=status.HTTP_200_OK)

    @extend_schema(
        summary='Activate User Account',
        description='Activates a user account. Only Admin/Superuser.',
        parameters=[OpenApiParameter(name='pk', type=OpenApiTypes.INT, required=True, location=OpenApiParameter.PATH)],
        responses={200: {}, 400: {}, 401: {}, 403: {}, 404: {}},
        tags=['Admin Actions']
    )
    @action(detail=True, methods=['post'], url_path='activate', permission_classes=[DRFIsAdminUser])
    def activate_user(self, request, pk=None):
        user = get_object_or_404(CustomUser, pk=pk)
        if not user.is_active:
            user.is_active = True
            user.save()
            return Response({"message": _(f"User '{user.email}' activated successfully.")}, status=status.HTTP_200_OK)
        return Response({"message": _(f"User '{user.email}' is already active.")}, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(
        summary='Deactivate User Account',
        description='Deactivates a user account (soft delete). Only Admin/Superuser. Admin cannot deactivate self.',
        parameters=[OpenApiParameter(name='pk', type=OpenApiTypes.INT, required=True, location=OpenApiParameter.PATH)],
        responses={200: {}, 400: {}, 401: {}, 403: {}, 404: {}},
        tags=['Admin Actions']
    )
    @action(detail=True, methods=['post'], url_path='deactivate', permission_classes=[DRFIsAdminUser])
    def deactivate_user(self, request, pk=None):
        user_to_deactivate = get_object_or_404(CustomUser, pk=pk)
        if user_to_deactivate == request.user: # Check if the admin is trying to deactivate themselves
            return Response({"message": _("Administrators cannot deactivate their own account via this action.")}, status=status.HTTP_403_FORBIDDEN)
        
        if user_to_deactivate.is_active:
            user_to_deactivate.is_active = False
            user_to_deactivate.save()
            return Response({"message": _(f"User '{user_to_deactivate.email}' deactivated successfully.")}, status=status.HTTP_200_OK)
        return Response({"message": _(f"User '{user_to_deactivate.email}' is already inactive.")}, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(
        summary='Add User to Group',
        description='Adds a user to a group. Only Admin/Superuser.',
        parameters=[OpenApiParameter(name='pk', type=OpenApiTypes.INT, required=True, location=OpenApiParameter.PATH)],
        request=GroupManagementSerializer,
        responses={200: {}, 400: {}, 401: {}, 403: {}, 404: {}},
        examples=[OpenApiExample('Add to Staff', value={'group_name': 'Staff'}, request_only=True)],
        tags=['Admin Actions']
    )
    @action(detail=True, methods=['post'], url_path='add-to-group', permission_classes=[DRFIsAdminUser])
    def add_to_group(self, request, pk=None):
        user_to_update = get_object_or_404(CustomUser, pk=pk)
        serializer = GroupManagementSerializer(data=request.data) # Use imported serializer
        serializer.is_valid(raise_exception=True)
        group_name = serializer.validated_data['group_name']
        try:
            group = Group.objects.get(name=group_name)
            user_to_update.groups.add(group)
            return Response({"message": _(f"User '{user_to_update.email}' added to group '{group_name}'.")}, status=status.HTTP_200_OK)
        except Group.DoesNotExist:
            return Response({"message": _(f"Group '{group_name}' does not exist.")}, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(
        summary='Remove User from Group',
        description='Removes a user from a group. Only Admin/Superuser.',
        parameters=[OpenApiParameter(name='pk', type=OpenApiTypes.INT, required=True, location=OpenApiParameter.PATH)],
        request=GroupManagementSerializer,
        responses={200: {}, 400: {}, 401: {}, 403: {}, 404: {}},
        examples=[OpenApiExample('Remove from Staff', value={'group_name': 'Staff'}, request_only=True)],
        tags=['Admin Actions']
    )
    @action(detail=True, methods=['post'], url_path='remove-from-group', permission_classes=[DRFIsAdminUser])
    def remove_from_group(self, request, pk=None):
        user_to_update = get_object_or_404(CustomUser, pk=pk)
        serializer = GroupManagementSerializer(data=request.data) # Use imported serializer
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

    @extend_schema(
        summary='Set User Staff Status',
        description='Sets `is_staff` status. Only Admin/Superuser. Superuser cannot remove own staff status.',
        parameters=[OpenApiParameter(name='pk', type=OpenApiTypes.INT, required=True, location=OpenApiParameter.PATH)],
        request=StaffStatusSerializer,
        responses={200: CustomUserDetailSerializer, 400: {}, 401: {}, 403: {}, 404: {}},
        tags=['Admin Actions']
    )
    @action(detail=True, methods=['patch'], url_path='set-staff-status', permission_classes=[DRFIsAdminUser])
    def set_staff_status(self, request, pk=None):
        user_to_update = get_object_or_404(CustomUser, pk=pk)
        serializer = StaffStatusSerializer(data=request.data) # Use imported serializer
        serializer.is_valid(raise_exception=True)
        new_staff_status = serializer.validated_data['is_staff']

        if user_to_update == request.user and request.user.is_superuser and not new_staff_status:
             return Response({"message": _("Superusers cannot remove their own staff status directly.")}, status=status.HTTP_403_FORBIDDEN)

        user_to_update.is_staff = new_staff_status
        user_to_update.save()
        return Response(CustomUserDetailSerializer(user_to_update, context=self.get_serializer_context()).data, status=status.HTTP_200_OK)