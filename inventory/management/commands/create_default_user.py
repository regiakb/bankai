"""
Management command to create default admin user.
"""
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db import transaction

User = get_user_model()


class Command(BaseCommand):
    help = 'Create default admin user if it does not exist'

    def handle(self, *args, **options):
        username = 'admin'
        password = 'bankai'
        email = 'admin@bankai.local'
        
        try:
            # Check if user already exists: do not change password, only ensure superuser/staff
            if User.objects.filter(username=username).exists():
                user = User.objects.get(username=username)
                user.is_superuser = True
                user.is_staff = True
                user.save(update_fields=['is_superuser', 'is_staff'])
                self.stdout.write(self.style.SUCCESS(f'User "{username}" already exists; kept existing password'))
                return
            
            # Create new superuser
            with transaction.atomic():
                user = User.objects.create_superuser(
                    username=username,
                    email=email,
                    password=password
                )
                self.stdout.write(self.style.SUCCESS(f'Successfully created superuser "{username}" with password "{password}"'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error creating user: {str(e)}'))
            raise
