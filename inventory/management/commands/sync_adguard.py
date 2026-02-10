"""
Management command to sync Bankai hosts to AdGuard Home clients.
"""
import logging
from django.core.management.base import BaseCommand
from django.utils import timezone
from inventory.models import Host, IPAddress, TaskExecution, Alert, AlertType
from inventory.services.adguard_client import sync_bankai_hosts_to_adguard, get_adguard_clients
from inventory.config_manager import get_adguard_integrations
from inventory.views import format_duration

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Sync Bankai hosts to AdGuard Home clients'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be synced without actually syncing',
        )
        parser.add_argument(
            '--tags',
            type=str,
            help='Comma-separated list of default tags to apply to all clients',
        )

    def handle(self, *args, **options):
        integrations = get_adguard_integrations()
        if not integrations:
            self.stdout.write(self.style.WARNING("No AdGuard Home integration is enabled"))
            return
        
        task_exec = TaskExecution.record_start('sync_adguard')
        
        try:
            self.stdout.write(f"Syncing Bankai hosts to {len(integrations)} AdGuard Home instance(s)...")
            
            dry_run = options.get('dry_run', False)
            if dry_run:
                self.stdout.write(self.style.WARNING("DRY RUN MODE - No changes will be made"))
            
            hosts = Host.objects.filter(is_active=True).prefetch_related('ip_addresses')
            if not hosts.exists():
                self.stdout.write(self.style.WARNING("No active hosts found in Bankai"))
                task_exec.record_success(items_processed=0, output="No active hosts found")
                return
            
            host_data = []
            for host in hosts:
                # Get IP addresses
                ips = list(host.ip_addresses.values_list('ip', flat=True))
                
                # Skip hosts without MAC or IP
                if not host.mac and not ips:
                    self.stdout.write(
                        self.style.WARNING(f"  ⚠ Skipping {host.name}: no MAC or IP addresses")
                    )
                    continue
                
                host_info = {
                    'name': host.name,
                    'mac': host.mac or '',
                    'ips': ips,
                    'device_type': host.device_type,
                    'source': host.source,
                }
                host_data.append(host_info)
            
            if not host_data:
                self.stdout.write(self.style.WARNING("No hosts with MAC or IP addresses found"))
                task_exec.record_success(items_processed=0, output="No hosts with identifiers found")
                return
            
            self.stdout.write(f"Found {len(host_data)} hosts to sync")
            
            if dry_run:
                first = integrations[0]
                default_tags = []
                if options.get('tags'):
                    default_tags = [tag.strip() for tag in options['tags'].split(',') if tag.strip()]
                else:
                    tags_config = first.get_config('default_tags', '')
                    if tags_config:
                        default_tags = [tag.strip() for tag in tags_config.split(',') if tag.strip()]
                self.stdout.write("\n🔍 Checking existing AdGuard Home clients...")
                try:
                    existing_clients = get_adguard_clients(integration=first)
                    if not isinstance(existing_clients, list):
                        existing_clients = []
                    existing_names = {c.get('name') for c in existing_clients if c and isinstance(c, dict)}
                    self.stdout.write(f"Found {len(existing_clients)} existing clients in AdGuard Home")
                except Exception as e:
                    logger.warning(f"Could not get existing clients for dry-run: {e}")
                    existing_names = set()
                    self.stdout.write(self.style.WARNING(f"  ⚠ Could not check existing clients: {e}"))
                self.stdout.write("\n📋 Hosts that would be synced:")
                added_count = updated_count = skipped_count = 0
                for host_info in host_data:
                    name = host_info['name']
                    identifiers = []
                    if host_info['mac']:
                        identifiers.append(f"MAC: {host_info['mac']}")
                    for ip in host_info['ips']:
                        identifiers.append(f"IP: {ip}")
                    if not identifiers:
                        self.stdout.write(f"  ⚠ SKIP {name}: no identifiers")
                        skipped_count += 1
                        continue
                    status = "UPDATE" if name in existing_names else "ADD"
                    if status == "UPDATE":
                        updated_count += 1
                    else:
                        added_count += 1
                    self.stdout.write(f"  [{status}] {name}: {', '.join(identifiers)}")
                if default_tags:
                    self.stdout.write(f"\n🏷️  Default tags: {', '.join(default_tags)}")
                self.stdout.write(f"\n📊 Summary: Would add: {added_count}, update: {updated_count}, skip: {skipped_count}")
                task_exec.record_success(items_processed=len(host_data), output=f"Dry run: {len(integrations)} instance(s)")
                return
            
            total_added = total_updated = total_skipped = total_errors = 0
            for integration in integrations:
                display_name = integration.display_name or 'Default'
                default_tags = []
                if options.get('tags'):
                    default_tags = [tag.strip() for tag in options['tags'].split(',') if tag.strip()]
                else:
                    tags_config = integration.get_config('default_tags', '')
                    if tags_config:
                        default_tags = [tag.strip() for tag in tags_config.split(',') if tag.strip()]
                stats = sync_bankai_hosts_to_adguard(
                    host_data,
                    default_tags=default_tags if default_tags else None,
                    integration=integration,
                )
                total_added += stats['added']
                total_updated += stats['updated']
                total_skipped += stats['skipped']
                total_errors += stats['errors']
                self.stdout.write(f"  [{display_name}] Added: {stats['added']}, Updated: {stats['updated']}, Skipped: {stats['skipped']}, Errors: {stats['errors']}")
            
            self.stdout.write("\nSync results (all instances):")
            self.stdout.write(f"  ✓ Added: {total_added}")
            self.stdout.write(f"  ↻ Updated: {total_updated}")
            self.stdout.write(f"  ⚠ Skipped: {total_skipped}")
            if total_errors > 0:
                self.stdout.write(self.style.ERROR(f"  ✗ Errors: {total_errors}"))
            
            total_processed = total_added + total_updated + total_skipped
            self.stdout.write(self.style.SUCCESS(f"\nSync completed: {total_processed} hosts processed across {len(integrations)} instance(s)"))
            
            output = f"Added: {total_added}, Updated: {total_updated}, Skipped: {total_skipped}, Errors: {total_errors} ({len(integrations)} instance(s))"
            task_exec.record_success(items_processed=total_processed, output=output)
            
            duration = task_exec.completed_at - task_exec.started_at if task_exec.completed_at else None
            duration_str = format_duration(duration.total_seconds()) if duration else 'N/A'
            Alert.objects.create(
                type=AlertType.TASK_COMPLETED,
                message=f"AdGuard Home sync completed: {total_processed} hosts processed ({len(integrations)} instance(s))",
                details=(
                    f"Task: AdGuard Home Sync\n"
                    f"Status: Success\n"
                    f"Instances: {len(integrations)}\n"
                    f"Added: {total_added}, Updated: {total_updated}, Skipped: {total_skipped}, Errors: {total_errors}\n"
                    f"Duration: {duration_str}\n\nOutput:\n{task_exec.output}"
                ),
            )
        except Exception as e:
            error_msg = f"Error syncing to AdGuard Home: {str(e)}"
            logger.error(error_msg, exc_info=True)
            self.stdout.write(self.style.ERROR(error_msg))
            task_exec.record_error(error_msg)
            raise
