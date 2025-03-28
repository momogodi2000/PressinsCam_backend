from datetime import timezone
from rest_framework import serializers
from .models import Contact, User, OTP
from django.contrib.auth import authenticate
import random
from rest_framework import serializers
from .models import Contact
from django.utils import timezone  # Correct import for Django's timezone
from rest_framework import serializers
from .models import DeliveryPlan, SavedAddress


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    phone_number = serializers.CharField(required=False)
    
    class Meta:
        model = User
        fields = ['email', 'phone_number', 'password', 'first_name', 'last_name', 'role']
        extra_kwargs = {'password': {'write_only': True}}
    
    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            phone_number=validated_data.get('phone_number'),
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            role=validated_data.get('role', 'client'),
            is_active=False  # User is inactive until email is verified
        )
        return user

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp_code = serializers.CharField()
    
    def validate(self, data):
        email = data.get('email')
        otp_code = data.get('otp_code')
        
        try:
            user = User.objects.get(email=email)
            otp = OTP.objects.filter(user=user, code=otp_code, is_used=False).order_by('-created_at').first()
            
            if not otp:
                raise serializers.ValidationError("Invalid OTP")
            
            return data
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    
    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        
        user = authenticate(email=email, password=password)
        
        if not user:
            raise serializers.ValidationError("Invalid credentials")
        
        if not user.is_email_verified:
            raise serializers.ValidationError("Email not verified")
        
        return data

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'phone_number', 
                  'role', 'is_email_verified', 'is_active', 'date_joined']
        read_only_fields = ['id', 'email', 'is_email_verified', 'is_active', 'date_joined']

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class VerifyResetCodeSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(min_length=6, max_length=6)

class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(min_length=6, max_length=6)
    new_password = serializers.CharField(min_length=8)
    confirm_password = serializers.CharField(min_length=8)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        return data

class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = ['name', 'email', 'subject', 'message']

class AdminUserSerializer(serializers.ModelSerializer):
    """Serializer for admin operations on User model"""
    password = serializers.CharField(write_only=True, required=False)
    
    class Meta:
        model = User
        fields = ['id', 'phone_number', 'email', 'first_name', 'last_name', 
                  'role', 'is_email_verified', 'is_active', 'password',
                  'date_joined', 'last_login']
    
    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = User.objects.create(**validated_data)
        
        if password:
            user.set_password(password)
            user.save()
        
        return user
    
    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        
        # Update all other fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        # Handle password separately
        if password:
            instance.set_password(password)
        
        instance.save()
        return instance

class ContactResponseSerializer(serializers.Serializer):
    response = serializers.CharField(required=False)


class SavedAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = SavedAddress
        fields = ['id', 'name', 'street', 'city', 'quarter', 'is_default']

class DeliveryPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeliveryPlan
        fields = [
            'id', 'pickup_date', 'pickup_time', 
            'delivery_date', 'delivery_time', 
            'address', 'is_express_service', 
            'special_instructions', 'status', 
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'status', 'created_at', 'updated_at']
        
    def validate_pickup_date(self, value):
        """Ensure pickup date is not in the past"""
        if value < timezone.now().date():
            raise serializers.ValidationError("Pickup date cannot be in the past")
        return value
        
    def validate(self, data):
        """Ensure delivery date is after pickup date"""
        if data['delivery_date'] <= data['pickup_date']:
            raise serializers.ValidationError({
                'delivery_date': "Delivery date must be after pickup date"
            })
        return data


