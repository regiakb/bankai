"""
Management command to split a merged "unknown" host back into separate hosts per IP.
"""
from django.core.management.base import BaseCommand
from inventory.models import Host, IPAddress, Service, InterfaceAttachment
from django.utils import timezone


class Command(BaseCommand):
    help = 'Split a merged "unknown" host back into separate hosts, one per IP'

    def add_arguments(self, parser):
        parser.add_argument(
            '--host-id',
            type=int,
            help='ID of the host to split (if not provided, will split all "unknown" hosts with multiple IPs)',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be split without actually splitting',
        )

    def handle(self, *args, **options):
        dry_run = options.get('dry_run', False)
        host_id = options.get('host_id')
        
        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN MODE - No changes will be made"))
            self.stdout.write("=" * 60)
        
        if host_id:
            hosts_to_split = Host.objects.filter(id=host_id)
        else:
            # Find all "unknown" hosts with multiple IPs
            hosts_to_split = Host.objects.filter(name='unknown').prefetch_related('ip_addresses')
            hosts_to_split = [h for h in hosts_to_split if h.ip_addresses.count() > 1]
        
        if not hosts_to_split:
            self.stdout.write(self.style.SUCCESS("No hosts to split found"))
            return
        
        self.stdout.write(f"Found {len(hosts_to_split)} host(s) to split")
        
        split_count = 0
        for host in hosts_to_split:
            ips = list(host.ip_addresses.all())
            if len(ips) <= 1:
                continue
            
            self.stdout.write(f"\nSplitting host '{host.name}' (ID: {host.id}) with {len(ips)} IPs:")
            
            # Keep first IP with original host
            first_ip = ips[0]
            self.stdout.write(f"  Keeping IP {first_ip.ip} with original host")
            
            # Create new hosts for remaining IPs
            for ip_obj in ips[1:]:
                self.stdout.write(f"  Creating new host for IP {ip_obj.ip}")
                split_count += 1
                
                if not dry_run:
                    # Create new host for this IP
                    new_host = Host.objects.create(
                        name='unknown',
                        source=host.source,
                        device_type=host.device_type,
                        vendor=host.vendor,
                        notes=host.notes,
                        is_active=host.is_active,
                        last_seen=timezone.now(),
                    )
                    
                    # Move IP to new host
                    ip_obj.host = new_host
                    ip_obj.save()
                    
                    # Note: Services will remain with the original host
                    # They'll need to be manually reassigned or will be discovered again on next scan
        
        if dry_run:
            self.stdout.write(self.style.WARNING(f"\nWould split {split_count} IP(s) into separate hosts"))
        else:
            self.stdout.write(self.style.SUCCESS(f"\nSplit {split_count} IP(s) into separate hosts"))
