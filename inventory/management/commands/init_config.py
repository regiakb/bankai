"""
Management command to initialize default configurations.
"""
from django.core.management.base import BaseCommand
from inventory.models import SystemConfig, IntegrationConfig


class Command(BaseCommand):
    help = 'Initialize default system configurations and integrations'

    def handle(self, *args, **options):
        self.stdout.write("Initializing BANKAI configuration...")
        
        # Create default system configs
        defaults = [
            ('DISCOVERY_CIDR', '192.168.1.0/24', 'Network CIDR for discovery scans'),
            ('DISCOVERY_INTERVAL', '10', 'Discovery scan interval in minutes'),
            ('SERVICE_SCAN_INTERVAL', '60', 'Service scan interval in minutes'),
            ('PROXMOX_SYNC_INTERVAL', '30', 'Proxmox sync interval in minutes'),
            ('ADGUARD_SYNC_INTERVAL', '60', 'AdGuard Home sync interval in minutes'),
            ('NOTIFY_NEW_SERVICE', 'False', 'Send Telegram notifications for new services'),
        ]
        
        for key, value, description in defaults:
            config, created = SystemConfig.objects.get_or_create(
                key=key,
                defaults={'value': value, 'description': description}
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f"Created config: {key}"))
            else:
                self.stdout.write(self.style.WARNING(f"Config already exists: {key}"))
        
        # Create default integration configs (one per type with display_name='Default')
        integrations = [
            ('telegram', {'bot_token': '', 'chat_id': ''}),
            ('proxmox', {'url': '', 'token_id': '', 'token_secret': '', 'node': ''}),
            ('adguard', {'url': '', 'username': '', 'password': '', 'default_tags': ''}),
        ]
        
        for name, default_config in integrations:
            integration, created = IntegrationConfig.objects.get_or_create(
                name=name,
                display_name='Default',
                defaults={'enabled': False, 'config_data': default_config}
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f"Created integration: {name}"))
            else:
                self.stdout.write(self.style.WARNING(f"Integration already exists: {name}"))
        
        self.stdout.write(self.style.SUCCESS("\nConfiguration initialization complete!"))
        self.stdout.write("Complete the setup wizard at /setup/ to configure your system")
