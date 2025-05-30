from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group # Import Group model
from django.utils.translation import gettext_lazy as _

# Get the CustomUser model using get_user_model()
CustomUser = get_user_model()

class GroupManagementSerializer(serializers.Serializer):
    group_name = serializers.CharField(
        max_length=150, 
        required=True,
        help_text=_("Name of the group (e.g., 'Managers', 'Staff', 'Users').")
    )

class StaffStatusSerializer(serializers.Serializer):
    is_staff = serializers.BooleanField(
        required=True,
        help_text="Set to `true` to make the user staff, `false` otherwise."
    )

class CustomUserCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.
    Handles creation of new users, ensuring password hashing and
    not returning the password in the response.
    """
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    password2 = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    # Role field can be here for initial setting, but won't dictate permissions
    role = serializers.CharField(max_length=10, required=False, default='user')

    class Meta:
        model = CustomUser
        fields = [
            'id', 'username', 'email', 'password', 'password2',
            'first_name', 'last_name', 'role'
        ]
        read_only_fields = ['id']

    def validate(self, data):
        """
        Validate that the two password fields match.
        """
        if data['password'] != data['password2']:
            raise serializers.ValidationError(_("Passwords do not match."))
        return data

    def create(self, validated_data):
        """
        Create a new user with hashed password.
        """
        # Pop password2 as it's not a model field
        validated_data.pop('password2')
        password = validated_data.pop('password')
        # Check if username is provided, if not, use email as username
        if not validated_data.get('username'):
            validated_data['username'] = validated_data['email']
        # Create the user instance
        user = CustomUser.objects.create(**validated_data)
        user.set_password(password) # Use the set_password method for hashing
        user.save()
        
        # Optional: Add new users to a default 'Users' group if it exists
        # This is typically done in a post_save signal or more explicitly in views
        # try:
        #     default_group = Group.objects.get(name='Users')
        #     user.groups.add(default_group)
        # except Group.DoesNotExist:
        #     pass # Handle if 'Users' group doesn't exist

        return user

class CustomUserDetailSerializer(serializers.ModelSerializer):
    """
    Serializer for retrieving and updating individual user details.
    Password updates are handled separately for security.
    """
    groups = serializers.SlugRelatedField(
        many=True,
        read_only=True,
        slug_field='name' # Display group names instead of IDs
    )
    class Meta:
        model = CustomUser
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'is_active', 'is_staff', 'is_superuser', 'date_joined', 'groups', 'role' # Added groups, is_superuser
        ]
        read_only_fields = ['id', 'is_active', 'is_staff', 'is_superuser', 'date_joined', 'groups']

    def update(self, instance, validated_data):
        """
        Update user fields. Exclude password from general update.
        """
        # It's best practice to handle password changes through a separate endpoint
        # or a dedicated serializer to avoid accidentally exposing or mishandling passwords.
        # If password is in validated_data, it will be ignored here.
        validated_data.pop('password', None)
        # Prevent non-admin from changing their own is_staff or groups
        request_user = self.context.get('request').user
        if not request_user.is_superuser: # Only superusers can modify these
            validated_data.pop('is_staff', None)
            validated_data.pop('groups', None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance

class CustomUserListSerializer(serializers.ModelSerializer):
    """
    Serializer for listing multiple users.
    Ensures sensitive fields like password are never exposed.
    """
    groups = serializers.SlugRelatedField(
        many=True,
        read_only=True,
        slug_field='name'
    )
    class Meta:
        model = CustomUser
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'is_active', 'is_staff', 'is_superuser', 'groups', 'role' # Added groups, is_superuser
        ]
        read_only_fields = fields # All fields are read-only for a list view

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Customizes the JWT token to include additional user claims.
    """
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['email'] = user.email # Use email as the primary identifier in the token
        if user.username: # Username might be optional now
            token['username'] = user.username
        token['is_staff'] = user.is_staff
        token['is_superuser'] = user.is_superuser
        token['groups'] = [group.name for group in user.groups.all()] # Include group names
        token['role'] = user.role # Still include if you keep the role field

        return token

class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for changing a user's password.
    Requires old password for verification.
    """
    old_password = serializers.CharField(write_only=True, required=True)
    new_password = serializers.CharField(write_only=True, required=True)
    new_password2 = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        if data['new_password'] != data['new_password2']:
            raise serializers.ValidationError(_("New passwords do not match."))
        return data

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(_("Your old password was entered incorrectly. Please enter it again."))
        return value