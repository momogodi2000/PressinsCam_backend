from django.conf import settings
from django.urls import path, include
from django.conf.urls.static import static
from .views import (ContactView, CurrentUserProfileView, DeliveryPlanViewSet, RegisterView, SavedAddressViewSet, VerifyOTPView, LoginView, ResendOTPView, RoleBasedRedirectView
)
from rest_framework_simplejwt.views import TokenRefreshView
from backend import views
from rest_framework.routers import DefaultRouter
from .views import ContactAdminViewSet, ContactResponseView


# Create router for viewsets
router = DefaultRouter()
router.register(r'admin/contacts', ContactAdminViewSet)
router.register(r'delivery-plans', DeliveryPlanViewSet, basename='delivery-plan')
router.register(r'saved-addresses', SavedAddressViewSet, basename='saved-address')


urlpatterns = [
    # Authentication URLs
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('login/', LoginView.as_view(), name='login'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('redirect/', RoleBasedRedirectView.as_view(), name='role-redirect'),
    path('logout/', views.logoutview, name='logout'),
    path('profile/', CurrentUserProfileView.as_view(), name='user-profile'),


    # Password reset URLs
    path('password/reset/request/', views.request_password_reset, name='request-password-reset'),
    path('password/reset/verify/', views.verify_reset_code, name='verify-reset-code'),
    path('password/reset/confirm/', views.reset_password, name='reset-password'),
    #admin Crud
    path('admin/users/', views.AdminUserListView.as_view(), name='admin-user-list'),
    path('admin/users/<int:pk>/', views.AdminUserDetailView.as_view(), name='admin-user-detail'),
    path('admin/user-stats/', views.user_stats, name='admin-user-stats'),

    # Contact and Newsletter URLs
    path('contact/', ContactView.as_view(), name='contact'),
    #path('admin/contacts/<int:pk>/delete/', delete_contact, name='admin-delete-contact'),
    path('admin/contacts/<int:pk>/respond/', ContactResponseView.as_view(), name='admin-respond-contact'),


    
    # Include the router URLs
    path('', include(router.urls)),

] 
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
