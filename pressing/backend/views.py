from functools import cache
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import ContactSerializer, PasswordResetConfirmSerializer, PasswordResetRequestSerializer, UserProfileSerializer, VerifyOTPSerializer, VerifyResetCodeSerializer
from .models import User
from django.core.cache import cache
from django.contrib.auth import logout
from django.contrib.auth.password_validation import validate_password
from django.core.mail import send_mail
from django.conf import settings
import random
import yagmail
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from django.shortcuts import get_object_or_404
from .serializers import AdminUserSerializer
from .permissions import IsAdminUser
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
import yagmail
from .models import User, OTP  # Import the OTP model

from .models import Contact
from .serializers import ContactSerializer, ContactResponseSerializer
from .permissions import IsAdminUser
from .serializers import UserRegistrationSerializer, UserLoginSerializer


class RegisterView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            # Generate OTP
            otp_code = ''.join(random.choices('0123456789', k=6))
            OTP.objects.create(user=user, code=otp_code)
            
            # Send OTP via email
            try:
                yag.send(
                    to=user.email,
                    subject="Your Account Verification Code",
                    contents=[
                        f"Your verification code is: {otp_code}",
                        "This code will expire in 15 minutes.",
                        "If you didn't create an account, please ignore this email."
                    ]
                )
            except Exception as e:
                return Response({
                    'error': f'Failed to send email: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            return Response({
                'message': 'User registered successfully. Please verify your email.',
                'email': user.email,
                'otp': otp_code  # In production, remove this line and only send the OTP via email
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyOTPView(APIView):
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp_code = serializer.validated_data['otp_code']
            
            try:
                user = User.objects.get(email=email)
                otp = OTP.objects.filter(user=user, code=otp_code, is_used=False).order_by('-created_at').first()
                
                if otp:
                    # Mark OTP as used
                    otp.is_used = True
                    otp.save()
                    
                    # Activate user
                    user.is_active = True
                    user.is_email_verified = True
                    user.save()
                    
                    # Generate tokens
                    refresh = RefreshToken.for_user(user)
                    
                    return Response({
                        'message': 'Email verified successfully',
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                        'role': user.role
                    }, status=status.HTTP_200_OK)
                return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            user = User.objects.get(email=email)
            
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
        email = request.data.get('email')
        
        try:
            user = User.objects.get(email=email)
            
            # Generate new OTP
            otp_code = ''.join(random.choices('0123456789', k=6))
            OTP.objects.create(user=user, code=otp_code)
            
            # Send OTP via email
            try:
                yag.send(
                    to=user.email,
                    subject="Your Account Verification Code",
                    contents=[
                        f"Your verification code is: {otp_code}",
                        "This code will expire in 15 minutes.",
                        "If you didn't create an account, please ignore this email."
                    ]
                )
            except Exception as e:
                return Response({
                    'error': f'Failed to send email: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            return Response({
                'message': 'OTP resent successfully',
                'email': user.email,
                'otp': otp_code  # In production, remove this line and only send the OTP via email
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


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logoutview(request):
    try:
        # Get the refresh token
        refresh_token = request.data.get('refresh_token')
        
        try:
            # Record logout time - wrapped in try/except in case method fails
            if hasattr(request.user, 'record_logout'):
                request.user.record_logout()
        except Exception as e:
            print(f"Error recording logout time: {str(e)}")
            # Continue with logout even if recording fails
            pass
        
        if refresh_token:
            try:
                # Blacklist the refresh token
                token = RefreshToken(refresh_token)
                token.blacklist()
            except Exception as e:
                # Continue with logout even if token blacklisting fails
                print(f"Error blacklisting token: {str(e)}")
                pass
        
        # Perform Django logout
        logout(request)
        
        return Response(
            {'message': 'Successfully logged out'},
            status=status.HTTP_200_OK
        )
    except Exception as e:
        print(f"Logout error: {str(e)}")  # Log the actual error
        return Response(
            {'error': 'Logout failed. Please try again.'},
            status=status.HTTP_400_BAD_REQUEST
        )

class CurrentUserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """
        Get the profile information of the currently logged-in user.
        """
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data)
    
    def patch(self, request):
        """
        Update partial information of the currently logged-in user.
        """
        serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) 
    

# Use email configuration from settings
yag = yagmail.SMTP(
    settings.EMAIL_HOST_USER,
    settings.EMAIL_HOST_PASSWORD
)

def generate_reset_code():
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

@api_view(['POST'])
@permission_classes([AllowAny])
def request_password_reset(request):
    try:
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            # Check if user exists
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response(
                    {'error': 'No account found with this email'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Generate and store reset code
            reset_code = generate_reset_code()
            cache_key = f'password_reset_{email}'
            cache.set(cache_key, reset_code, timeout=300)  # 5 minutes expiry
            
            # Send email
            subject = "Password Reset Code"
            contents = [
                f"Your password reset code is: {reset_code}",
                "This code will expire in 5 minutes.",
                "If you didn't request this reset, please ignore this email."
            ]
            
            yag.send(to=email, subject=subject, contents=contents)
            
            return Response({
                'message': 'Reset code sent successfully',
                'email': email
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def verify_reset_code(request):
    try:
        serializer = VerifyResetCodeSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            submitted_code = serializer.validated_data['code']
            
            # Get stored code
            cache_key = f'password_reset_{email}'
            stored_code = cache.get(cache_key)
            
            if not stored_code:
                return Response(
                    {'error': 'Reset code has expired'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if submitted_code != stored_code:
                return Response(
                    {'error': 'Invalid reset code'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            return Response({'message': 'Code verified successfully'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password(request):
    try:
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            submitted_code = serializer.validated_data['code']
            new_password = serializer.validated_data['new_password']
            
            # Verify code again
            cache_key = f'password_reset_{email}'
            stored_code = cache.get(cache_key)
            
            if not stored_code or submitted_code != stored_code:
                return Response(
                    {'error': 'Invalid or expired reset code'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get user and update password
            try:
                user = User.objects.get(email=email)
                validate_password(new_password, user)
                user.set_password(new_password)
                user.save()
                
                # Clear the reset code
                cache.delete(cache_key)
                
                # Send confirmation email
                subject = "Password Reset Successful"
                contents = [
                    "Your password has been successfully reset.",
                    "If you didn't make this change, please contact support immediately."
                ]
                yag.send(to=email, subject=subject, contents=contents)
                
                return Response({'message': 'Password reset successful'})
            except User.DoesNotExist:
                return Response(
                    {'error': 'User not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            except Exception as e:
                return Response(
                    {'error': str(e)},
                    status=status.HTTP_400_BAD_REQUEST
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

class ContactView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = ContactSerializer(data=request.data)
        if serializer.is_valid():
            contact = serializer.save()
            
            # Send email notification
            try:
                send_mail(
                    subject=f'New Contact Form Submission: {contact.subject}',
                    message=f'Name: {contact.name}\nEmail: {contact.email}\nMessage: {contact.message}',
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[settings.ADMIN_EMAIL],
                    fail_silently=False,
                )
            except Exception as e:
                print(f"Error sending contact email: {str(e)}")
                # Continue even if email fails
            
            return Response(
                {'message': 'Message sent successfully'},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class AdminUserListView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    def get(self, request):
        """List all users (admin only)"""
        users = User.objects.all()
        serializer = AdminUserSerializer(users, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        """Create a new user (admin only)"""
        serializer = AdminUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AdminUserDetailView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    def get_user(self, pk):
        return get_object_or_404(User, pk=pk)
    
    def get(self, request, pk):
        """Get user details (admin only)"""
        user = self.get_user(pk)
        serializer = AdminUserSerializer(user)
        return Response(serializer.data)
    
    def put(self, request, pk):
        """Update user (admin only)"""
        user = self.get_user(pk)
        serializer = AdminUserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """Delete user (admin only)"""
        user = self.get_user(pk)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUser])
def user_stats(request):
    """Get user statistics (counts by role, etc.)"""
    total_users = User.objects.count()
    active_users = User.objects.filter(is_active=True).count()
    verified_users = User.objects.filter(is_email_verified=True).count()
    
    role_counts = {
        'client': User.objects.filter(role='client').count(),
        'deliver': User.objects.filter(role='deliver').count(),
        'admin': User.objects.filter(role='admin').count()
    }
    
    return Response({
        'total_users': total_users,
        'active_users': active_users,
        'verified_users': verified_users,
        'role_counts': role_counts
    })


# Email configuration - use the existing yagmail setup
username = "yvangodimomo@gmail.com"
password = "pzls apph esje cgdl"
yag = yagmail.SMTP(username, password)

# Custom permission class for admin access
class IsAdminUser(IsAuthenticated):
    def has_permission(self, request, view):
        return super().has_permission(request, view) and request.user.role == 'admin'

class ContactAdminViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for admin users to view all contact messages
    """
    queryset = Contact.objects.all().order_by('-created_at')
    serializer_class = ContactSerializer
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Allow filtering by fields
        name = self.request.query_params.get('name', None)
        email = self.request.query_params.get('email', None)
        subject = self.request.query_params.get('subject', None)
        
        if name:
            queryset = queryset.filter(name__icontains=name)
        if email:
            queryset = queryset.filter(email__icontains=email)
        if subject:
            queryset = queryset.filter(subject__icontains=subject)
            
        return queryset

@api_view(['DELETE'])
@permission_classes([IsAdminUser])
def delete_contact(request, pk):
    """
    Delete a specific contact message by ID
    """
    contact = get_object_or_404(Contact, pk=pk)
    contact.delete()
    return Response(
        {'message': 'Contact message deleted successfully'},
        status=status.HTTP_204_NO_CONTENT
    )

class ContactResponseView(APIView):
    """
    View for admin users to respond to contact messages
    """
    permission_classes = [IsAdminUser]
    
    def post(self, request, pk):
        contact = get_object_or_404(Contact, pk=pk)
        serializer = ContactResponseSerializer(data=request.data)
        
        if serializer.is_valid():
            response_message = serializer.validated_data.get('response')
            
            # If no response message provided, generate a standard one
            if not response_message:
                response_message = (
                    f"Dear {contact.name},\n\n"
                    f"Thank you for contacting us regarding '{contact.subject}'.\n\n"
                    f"We have received your message and will address your inquiry as soon as possible. "
                    f"If you have any additional questions, please don't hesitate to reach out.\n\n"
                    f"Best regards,\n"
                    f"The Support Team"
                )
            
            # Send email response
            try:
                # Prepare email content
                subject = f"Re: {contact.subject}"
                
                # Send the email using yagmail
                yag = yagmail.SMTP(username, password)
                yag.send(
                    to=contact.email,
                    subject=subject,
                    contents=response_message
                )
                
                # Update the contact record to mark it as responded
                contact.is_responded = True
                contact.save()
                
                return Response(
                    {'message': 'Response sent successfully'},
                    status=status.HTTP_200_OK
                )
            except Exception as e:
                return Response(
                    {'error': f'Failed to send email: {str(e)}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

