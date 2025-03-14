from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserRegistrationSerializer, VerifyOTPSerializer, UserLoginSerializer
from .models import User, OTP
import random
from django.utils import timezone
from datetime import timedelta

class RegisterView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            # Generate OTP
            otp_code = ''.join(random.choices('0123456789', k=6))
            OTP.objects.create(user=user, code=otp_code)
            
            # Here you would integrate with an SMS service to send the OTP
            # For example: send_sms(user.phone_number, f"Your verification code is: {otp_code}")
            
            return Response({
                'message': 'User registered successfully. Please verify your phone number.',
                'phone_number': user.phone_number,
                'otp': otp_code  # In production, remove this line and actually send the OTP via SMS
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyOTPView(APIView):
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            phone_number = serializer.validated_data['phone_number']
            otp_code = serializer.validated_data['otp_code']
            
            user = User.objects.get(phone_number=phone_number)
            otp = OTP.objects.filter(user=user, code=otp_code, is_used=False).order_by('-created_at').first()
            
            if otp:
                # Mark OTP as used
                otp.is_used = True
                otp.save()
                
                # Activate user
                user.is_active = True
                user.is_phone_verified = True
                user.save()
                
                # Generate tokens
                refresh = RefreshToken.for_user(user)
                
                return Response({
                    'message': 'Phone number verified successfully',
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'role': user.role
                }, status=status.HTTP_200_OK)
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            phone_number = serializer.validated_data['phone_number']
            
            user = User.objects.get(phone_number=phone_number)
            
            # Generate tokens
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'message': 'Login successful',
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'role': user.role
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResendOTPView(APIView):
    def post(self, request):
        phone_number = request.data.get('phone_number')
        
        try:
            user = User.objects.get(phone_number=phone_number)
            
            # Generate new OTP
            otp_code = ''.join(random.choices('0123456789', k=6))
            OTP.objects.create(user=user, code=otp_code)
            
            # Here you would integrate with an SMS service to send the OTP
            # For example: send_sms(user.phone_number, f"Your verification code is: {otp_code}")
            
            return Response({
                'message': 'OTP resent successfully',
                'phone_number': user.phone_number,
                'otp': otp_code  # In production, remove this line and actually send the OTP via SMS
            }, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

class RoleBasedRedirectView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        if user.role == 'client':
            return Response({'redirect_url': '/clients_panel/'})
        elif user.role == 'deliver':
            return Response({'redirect_url': '/delivery_panel/'})
        elif user.role == 'admin':
            return Response({'redirect_url': '/admin_panel/'})
        else:
            return Response({'error': 'Invalid role'}, status=status.HTTP_400_BAD_REQUEST)
