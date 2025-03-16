# permissions.py - Create this file
from rest_framework import permissions

class IsAdminUser(permissions.BasePermission):
    """
    Custom permission to only allow admin users to access
    """
    def has_permission(self, request, view):
        return request.user.role == 'admin'