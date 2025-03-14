from django.shortcuts import redirect
from django.urls import reverse
from django.conf import settings
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed

class RoleBasedRedirectMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.jwt_auth = JWTAuthentication()

    def __call__(self, request):
        # Skip for API paths
        if request.path.startswith('/api/'):
            return self.get_response(request)
        
        # Skip for static files
        if request.path.startswith('/static/') or request.path.startswith('/media/'):
            return self.get_response(request)
        
        # Check if the user is authenticated
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header or not auth_header.startswith('Bearer '):
            return self.get_response(request)
        
        try:
            validated_token = self.jwt_auth.get_validated_token(auth_header.split(' ')[1])
            user = self.jwt_auth.get_user(validated_token)
            
            # Check if the user is trying to access a restricted area
            if user.role == 'client' and request.path.startswith('/admin_panel/'):
                return redirect('/clients_panel/')
            elif user.role == 'client' and request.path.startswith('/delivery_panel/'):
                return redirect('/clients_panel/')
            elif user.role == 'deliver' and request.path.startswith('/admin_panel/'):
                return redirect('/delivery_panel/')
            elif user.role == 'deliver' and request.path.startswith('/clients_panel/'):
                return redirect('/delivery_panel/')
            elif user.role == 'admin' and request.path.startswith('/clients_panel/'):
                return redirect('/admin_panel/')
            elif user.role == 'admin' and request.path.startswith('/delivery_panel/'):
                return redirect('/admin_panel/')
        except Exception:
            pass
        
        return self.get_response(request)
    
    