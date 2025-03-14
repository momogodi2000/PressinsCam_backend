# In yourapp/management/commands/check_profile_images.py
import os
from django.core.management.base import BaseCommand
from django.conf import settings
from backend.models import CustomUser  # Replace with your actual user model import

class Command(BaseCommand):
    help = 'Check for missing profile pictures and fix database references'

    def handle(self, *args, **options):
        # Get all users with profile pictures
        users_with_pics = CustomUser.objects.exclude(profile_picture='')
        self.stdout.write(f"Checking {users_with_pics.count()} users with profile pictures...")
        
        fixed_count = 0
        for user in users_with_pics:
            if user.profile_picture and not os.path.exists(user.profile_picture.path):
                self.stdout.write(self.style.WARNING(
                    f"User {user.email}: Missing file {user.profile_picture.path}"
                ))
                
                # Option 1: Clear the reference
                user.profile_picture = None
                user.save(update_fields=['profile_picture'])
                fixed_count += 1
                
        self.stdout.write(self.style.SUCCESS(f"Fixed {fixed_count} user records"))