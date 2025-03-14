from django.conf import settings
from django.urls import path, include
from django.conf.urls.static import static
from .views import (RegisterView, VerifyOTPView, LoginView, ResendOTPView, RoleBasedRedirectView
)
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    # Authentication URLs
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('login/', LoginView.as_view(), name='login'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('redirect/', RoleBasedRedirectView.as_view(), name='role-redirect'),
    # Include the router URLs
   
] 
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
