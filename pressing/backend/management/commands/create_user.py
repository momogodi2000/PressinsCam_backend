from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

class Command(BaseCommand):
    help = 'Creates default users with different roles'

    def handle(self, *args, **kwargs):
        User = get_user_model()

        users_data = [
            {
                'phone_number': '1234567890', 
                'email': 'admin@example.com', 
                'password': 'admin123', 
                'role': 'admin'
            },
            {
                'phone_number': '9876543210', 
                'email': 'client@example.com', 
                'password': 'client123', 
                'role': 'client'
            },
            {
                'phone_number': '5566778899', 
                'email': 'deliver@example.com', 
                'password': 'deliver123', 
                'role': 'deliver'
            },
        ]

        for user_data in users_data:
            if User.objects.filter(phone_number=user_data['phone_number']).exists():
                self.stdout.write(self.style.WARNING(f"User with phone number {user_data['phone_number']} already exists."))
            elif user_data.get('email') and User.objects.filter(email=user_data['email']).exists():
                self.stdout.write(self.style.WARNING(f"User with email {user_data['email']} already exists."))
            else:
                if user_data['role'] == 'admin':
                    user = User.objects.create_superuser(
                        phone_number=user_data['phone_number'],
                        email=user_data.get('email'),
                        password=user_data['password'],
                    )
                else:
                    user = User.objects.create_user(
                        phone_number=user_data['phone_number'],
                        email=user_data.get('email'),
                        password=user_data['password'],
                        role=user_data['role'],
                    )

                self.stdout.write(self.style.SUCCESS(f"{user_data['role'].capitalize()} user created with phone number: {user_data['phone_number']}"))