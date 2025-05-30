# users/permissions.py
from rest_framework.permissions import BasePermission, IsAdminUser as DRFIsAdminUser

class IsInGroup(BasePermission):
    """
    Custom permission to check if the user is in a specific group.
    Usage: permission_classes = [IsInGroup.create('Managers')]
    """
    required_group = None

    def has_permission(self, request, view):
        """
        Checks if the authenticated user belongs to the required group.
        """
        if request.user and request.user.is_authenticated:
            return request.user.groups.filter(name=self.required_group).exists()
        return False

    @classmethod
    def create(cls, group_name):
        """
        Factory method to create a permission class for a specific group.
        Usage: `permission_classes = [IsInGroup.create('Managers')]`
        """
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
            if request.user.is_superuser:
                return True
            if DRFIsAdminUser().has_permission(request, view): # checks user.is_staff
                return True
            return obj == request.user
        return False

class IsOwnerOrManagerOrAdmin(BasePermission):
    """
    Allows access to the object owner, or a Manager group member, or a Superuser/DRFIsAdminUser.
    """
    def has_object_permission(self, request, view, obj):
        if request.user and request.user.is_authenticated:
            if request.user.is_superuser:
                return True
            if DRFIsAdminUser().has_permission(request, view): # checks user.is_staff
                return True
            
            is_manager = request.user.groups.filter(name='Managers').exists()
            if is_manager:
                if obj == request.user: # Manager can view/update their own profile
                    return True
                # Manager can update/retrieve Staff and User accounts
                target_user_groups = obj.groups.values_list('name', flat=True)
                # Assumes 'Users' is a group for non-staff, non-manager users.
                # Managers should be able to manage 'Staff' and 'Users'
                if 'Staff' in target_user_groups or 'Users' in target_user_groups:
                    return True 
                # Prevent managers from managing other managers unless they are also admins/superusers (covered above)
                # or if obj is themselves.
                if 'Managers' in target_user_groups and obj != request.user:
                    return False # A manager cannot manage another manager by default via this rule
                return True # Fallback if target user has no specific restrictive group

            return obj == request.user # Owner access
        return False

class IsOwnerOrStaffOrAdmin(BasePermission):
    """
    Allows access to the object owner, or a Staff group member, or a Superuser/DRFIsAdminUser.
    """
    def has_object_permission(self, request, view, obj):
        if request.user and request.user.is_authenticated:
            if request.user.is_superuser:
                return True
            if DRFIsAdminUser().has_permission(request, view): # checks user.is_staff
                return True

            is_staff_member = request.user.groups.filter(name='Staff').exists()
            if is_staff_member:
                if obj == request.user: # Staff can view their own profile
                    return True
                # Staff can retrieve 'Users' accounts (assuming 'Users' group for regular users)
                target_user_groups = obj.groups.values_list('name', flat=True)
                if 'Users' in target_user_groups: # Staff can see users in the "Users" group
                    return True
                # Staff generally shouldn't see other Staff or Managers unless they are owner or admin
                return False 

            return obj == request.user # Owner access
        return False