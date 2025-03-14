from rest_framework import serializers
from .models import User, OTP
from django.contrib.auth import authenticate
import random

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    email = serializers.EmailField(required=False)
    
    class Meta:
        model = User
        fields = ['phone_number', 'email', 'password', 'first_name', 'last_name', 'role']
        extra_kwargs = {'password': {'write_only': True}}
    
    def create(self, validated_data):
        user = User.objects.create_user(
            phone_number=validated_data['phone_number'],
            email=validated_data.get('email'),
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            role=validated_data.get('role', 'client'),
            is_active=False  # User is inactive until phone is verified
        )
        return user

class VerifyOTPSerializer(serializers.Serializer):
    phone_number = serializers.CharField()
    otp_code = serializers.CharField()
    
    def validate(self, data):
        phone_number = data.get('phone_number')
        otp_code = data.get('otp_code')
        
        try:
            user = User.objects.get(phone_number=phone_number)
            otp = OTP.objects.filter(user=user, code=otp_code, is_used=False).order_by('-created_at').first()
            
            if not otp:
                raise serializers.ValidationError("Invalid OTP")
            
            return data
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")

class UserLoginSerializer(serializers.Serializer):
    phone_number = serializers.CharField()
    password = serializers.CharField()
    
    def validate(self, data):
        phone_number = data.get('phone_number')
        password = data.get('password')
        
        user = authenticate(phone_number=phone_number, password=password)
        
        if not user:
            raise serializers.ValidationError("Invalid credentials")
        
        if not user.is_phone_verified:
            raise serializers.ValidationError("Phone number not verified")
        
        return data

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['phone_number', 'email', 'first_name', 'last_name', 'role', 'is_phone_verified']
        read_only_fields = ['phone_number', 'role', 'is_phone_verified']

