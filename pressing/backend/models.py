from django.utils import timezone  # Correct import
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _
from django.conf import settings  # Add this import at the top
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _



class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_('The Email must be set'))
        
        user = self.model(
            email=self.normalize_email(email),
            **extra_fields
        )
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('role', 'admin')
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        return self.create_user(email, password, **extra_fields)

class User(AbstractUser):
    ROLE_CHOICES = (
        ('client', 'Client'),
        ('deliver', 'Deliver'),
        ('admin', 'Admin'),
    )
    username = None
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    email = models.EmailField(_('email address'), unique=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='client')
    is_email_verified = models.BooleanField(default=False)
        
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    objects = CustomUserManager()
    
    def __str__(self):
        return self.email

class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='otps')
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.user.email} - {self.code}"
    
    
class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=200)
    message = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    is_responded = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.name} - {self.subject}"
    
class DeliveryPlan(models.Model):
    STATUS_CHOICES = [
        ('Planifié', 'Planifié'),
        ('En cours', 'En cours'),
        ('Terminé', 'Terminé')
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    pickup_date = models.DateField()
    pickup_time = models.CharField(max_length=20)
    delivery_date = models.DateField()
    delivery_time = models.CharField(max_length=20)
    address = models.TextField()
    is_express_service = models.BooleanField(default=False)
    special_instructions = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Planifié')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Delivery Plan {self.id} - {self.address}"

class SavedAddress(models.Model):
    CITY_CHOICES = [
        ('douala', 'Douala'),
        ('yaounde', 'Yaoundé')
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    street = models.CharField(max_length=255)
    city = models.CharField(max_length=20, choices=CITY_CHOICES)
    quarter = models.CharField(max_length=100)
    is_default = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.name} - {self.street}, {self.quarter}, {self.city}"
    

