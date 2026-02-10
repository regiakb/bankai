"""
Management command to fix unknown host names.
Changes "unknown-{ip}" to just "unknown"
"""
from django.core.management.base import BaseCommand
from inventory.models import Host
import re


class Command(BaseCommand):
    help = 'Fix unknown host names from "unknown-{ip}" to "unknown"'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be changed without actually changing',
        )

    def handle(self, *args, **options):
        dry_run = options.get('dry_run', False)
        
        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN MODE - No changes will be made"))
            self.stdout.write("=" * 60)
        
        # Find all hosts with names starting with "unknown-"
        hosts_to_fix = Host.objects.filter(name__startswith='unknown-')
        
        if not hosts_to_fix.exists():
            self.stdout.write(self.style.SUCCESS("No hosts with 'unknown-{ip}' format found"))
            return
        
        self.stdout.write(f"Found {hosts_to_fix.count()} host(s) with 'unknown-IP' format")
        
        updated_count = 0
        for host in hosts_to_fix:
            old_name = host.name
            new_name = 'unknown'
            
            self.stdout.write(f"  {old_name} -> {new_name}")
            
            if not dry_run:
                # Just rename - don't merge hosts with different IPs
                # Each IP should have its own "unknown" host
                host.name = new_name
                host.save()
            
            updated_count += 1
        
        if dry_run:
            self.stdout.write(self.style.WARNING(f"\nWould update {updated_count} host(s)"))
        else:
            self.stdout.write(self.style.SUCCESS(f"\nUpdated {updated_count} host(s)"))
