from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import get_user_model # Recommended way to get the user model
from django.utils.translation import gettext_lazy as _

# Get the CustomUser model using get_user_model()
CustomUser = get_user_model()

class CustomUserCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.
    Handles creation of new users, ensuring password hashing and
    not returning the password in the response.
    """
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    password2 = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    class Meta:
        model = CustomUser
        fields = [
            'id', 'username', 'email', 'password', 'password2',
            'first_name', 'last_name', 'role'
        ]
        read_only_fields = ['id'] # ID is set by the database
        extra_kwargs = {
            'role': {'required': False, 'default': 'user'} # Role can be optional during creation
        }

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

        user = CustomUser.objects.create(**validated_data)
        user.set_password(password) # Use the set_password method for hashing
        user.save()
        return user

class CustomUserDetailSerializer(serializers.ModelSerializer):
    """
    Serializer for retrieving and updating individual user details.
    Password updates are handled separately for security.
    """
    class Meta:
        model = CustomUser
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'is_active', 'is_staff', 'date_joined', 'role'
        ]
        read_only_fields = ['id', 'is_active', 'is_staff', 'date_joined']

    def update(self, instance, validated_data):
        """
        Update user fields. Exclude password from general update.
        """
        # It's best practice to handle password changes through a separate endpoint
        # or a dedicated serializer to avoid accidentally exposing or mishandling passwords.
        # If password is in validated_data, it will be ignored here.
        validated_data.pop('password', None) # Ensure password isn't processed here

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance

class CustomUserListSerializer(serializers.ModelSerializer):
    """
    Serializer for listing multiple users.
    Ensures sensitive fields like password are never exposed.
    """
    class Meta:
        model = CustomUser
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'is_active', 'is_staff', 'date_joined', 'role'
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
        token['role'] = user.role
        token['is_staff'] = user.is_staff
        token['is_superuser'] = user.is_superuser

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