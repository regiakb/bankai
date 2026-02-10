"""
Management command to sync Proxmox VMs/LXCs.
"""
import logging
from django.core.management.base import BaseCommand
from django.utils import timezone
from inventory.models import Host, IPAddress, HostSource, MediumType, InterfaceAttachment, TaskExecution, Alert, AlertType, HostStatusEvent
from inventory.config_manager import get_proxmox_integrations
from inventory.services.proxmox_client import sync_proxmox_vms
from inventory.views import format_duration

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Sync hosts from Proxmox'

    def handle(self, *args, **options):
        integrations = get_proxmox_integrations()
        if not integrations:
            self.stdout.write(self.style.WARNING("No Proxmox integration is enabled"))
            return
        
        task_exec = TaskExecution.record_start('sync_proxmox')
        touched_host_ids = set()
        
        try:
            self.stdout.write(f"Syncing from {len(integrations)} Proxmox instance(s)...")
            
            synced_count = 0
            ip_count = 0
            all_vms = []
            for integration in integrations:
                vms = sync_proxmox_vms(integration=integration)
                display_name = integration.display_name or 'Default'
                self.stdout.write(f"  [{display_name}] Found {len(vms)} VMs/LXCs")
                for vm in vms:
                    vm['_integration_display'] = display_name
                all_vms.extend(vms)
            
            if not all_vms:
                self.stdout.write(self.style.WARNING("No Proxmox VMs found or Proxmox not configured"))
                task_exec.record_success(items_processed=0, output="No Proxmox VMs found or Proxmox not configured")
                return
            
            for vm in all_vms:
                name = vm.get('name', 'unknown')
                macs = vm.get('macs', [])
                ips = vm.get('ips', [])
                vmid = vm.get('vmid')
                vm_type = vm.get('type', 'unknown')
                node = vm.get('node', '')
                integration_display = vm.get('_integration_display', 'Default')
                instance_tag = f"[Proxmox:{integration_display}]"
            
                host = None
                host_identifier = None
            
                if vmid:
                    import re
                    all_proxmox_hosts = Host.objects.filter(source=HostSource.PROXMOX)
                    for existing_host in all_proxmox_hosts:
                        if instance_tag not in (existing_host.notes or ''):
                            continue
                        vmid_match = re.search(r'ID:\s*(\d+)', existing_host.notes or '')
                        if vmid_match and int(vmid_match.group(1)) == vmid:
                            host = existing_host
                            host_identifier = f"VMID:{vmid}"
                            break
            
                # If not found by VMID, try to find by first IP (but be careful with Proxmox hosts)
                if not host and ips:
                    # Try to find existing host by IP
                    try:
                        ip_obj = IPAddress.objects.filter(ip=ips[0]).first()
                        if ip_obj and ip_obj.host:
                            existing_host = ip_obj.host
                        
                            if existing_host.source == HostSource.PROXMOX and vmid:
                                if instance_tag not in (existing_host.notes or ''):
                                    host = None
                                else:
                                    import re
                                    existing_vmid_match = re.search(r'ID:\s*(\d+)', existing_host.notes or '')
                                    if existing_vmid_match:
                                        existing_vmid = int(existing_vmid_match.group(1))
                                        if existing_vmid != vmid:
                                            self.stdout.write(
                                                self.style.WARNING(
                                                    f"IP {ips[0]} already assigned to Proxmox VM {existing_vmid} ({existing_host.name}), "
                                                    f"but current VM is {vmid} ({name}). Creating separate host."
                                                )
                                            )
                                            host = None
                                        else:
                                            host = existing_host
                                            host_identifier = f"IP:{ips[0]}"
                                    else:
                                        host = None
                            elif existing_host.source != HostSource.PROXMOX:
                                # Existing host is not from Proxmox - merge Proxmox data into it
                                host = existing_host
                                host_identifier = f"IP:{ips[0]}"
                                # Merge Proxmox data into existing host
                                updated = False
                                # Update name if current is unknown or generic
                                if not host.name or host.name.lower() in ['unknown', 'unknown-host', ''] or host.name.startswith('unknown-'):
                                    host.name = name
                                    updated = True
                                # Update device_type if it's unknown
                                if not host.device_type or host.device_type == 'unknown':
                                    host.device_type = vm_type
                                    updated = True
                                # Update source to Proxmox (more reliable source)
                                host.source = HostSource.PROXMOX
                                updated = True
                                host.last_seen = timezone.now()
                                old_active = host.is_active
                                host.is_active = True
                                if updated:
                                    host.save()
                                    touched_host_ids.add(host.id)
                    except:
                        pass
            
                # If no host found by IP, try by MAC
                if not host and macs:
                    primary_mac = macs[0].lower()
                    host, created = Host.objects.get_or_create(
                        mac=primary_mac,
                        defaults={
                            'name': name,
                            'source': HostSource.PROXMOX,
                            'device_type': vm_type,
                            'notes': f"Proxmox {vm_type} (ID: {vmid}, Node: {node}) {instance_tag}",
                        }
                    )
                    if not created:
                        # Update existing host - complement data
                        # Update name if current is unknown or generic
                        if not host.name or host.name.lower() in ['unknown', 'unknown-host', ''] or host.name.startswith('unknown-'):
                            host.name = name
                        # Update device_type if it's unknown
                        if not host.device_type or host.device_type == 'unknown':
                            host.device_type = vm_type
                        # Update source to Proxmox if it was from another source (but keep if it's already Proxmox)
                        if host.source != HostSource.PROXMOX:
                            host.source = HostSource.PROXMOX
                        host.last_seen = timezone.now()
                        host.is_active = True
                        # Update notes to include Proxmox info if not present
                        if not host.notes or 'Proxmox' not in host.notes:
                            existing_notes = host.notes or ''
                            host.notes = f"{existing_notes}\nProxmox {vm_type} (ID: {vmid}, Node: {node}) {instance_tag}".strip()
                        host.save()
                    touched_host_ids.add(host.id)
                    host_identifier = f"MAC:{primary_mac}"
            
                # If still no host, create by name (use VMID in notes, not in name)
                if not host:
                    # Use just the name, not name-vmid
                    unique_name = name or f"proxmox-{vm_type}"
                
                    # For Proxmox, we need to ensure uniqueness by VMID, not just name
                    # So we'll search for existing host with same VMID first
                    if vmid:
                        import re
                        all_proxmox_hosts = Host.objects.filter(source=HostSource.PROXMOX)
                        for existing_host in all_proxmox_hosts:
                            if instance_tag not in (existing_host.notes or ''):
                                continue
                            vmid_match = re.search(r'ID:\s*(\d+)', existing_host.notes or '')
                            if vmid_match and int(vmid_match.group(1)) == vmid:
                                host = existing_host
                                host_identifier = f"VMID:{vmid}"
                                break
                    
                    if not host:
                        host, created = Host.objects.get_or_create(
                            name=unique_name,
                            source=HostSource.PROXMOX,
                            defaults={
                                'device_type': vm_type,
                                'notes': f"Proxmox {vm_type} (ID: {vmid}, Node: {node}) - No MAC/IP {instance_tag}",
                            }
                        )
                        if not created:
                            # Host with same name exists - check if it's the same VMID
                            import re
                            existing_vmid_match = re.search(r'ID:\s*(\d+)', host.notes or '')
                            if existing_vmid_match and int(existing_vmid_match.group(1)) != vmid:
                                # Different VMID but same name - create with VMID in name as fallback
                                unique_name = f"{name}-{vmid}" if name and name != 'unknown' else f"proxmox-{vm_type}-{vmid}"
                                host = Host.objects.create(
                                    name=unique_name,
                                    source=HostSource.PROXMOX,
                                    device_type=vm_type,
                                    notes=f"Proxmox {vm_type} (ID: {vmid}, Node: {node}) - No MAC/IP {instance_tag}",
                                )
                                touched_host_ids.add(host.id)
                            else:
                                # Same VMID or no VMID - update existing
                                host.last_seen = timezone.now()
                                old_active = host.is_active
                                host.is_active = True
                                host.save()
                                touched_host_ids.add(host.id)
                        else:
                            # New host created (default is_active=True)
                            touched_host_ids.add(host.id)
                        host_identifier = f"NAME:{unique_name}"
            
                # Complement host data if needed
                updated = False
            
                # For Proxmox hosts, use just the name (without VMID suffix)
                # Remove VMID suffix if present (e.g., "pialert-202" -> "pialert")
                if vmid and host.source == HostSource.PROXMOX:
                    import re
                    # Remove VMID suffix from name if present
                    if host.name.endswith(f"-{vmid}"):
                        base_name = host.name[:-len(f"-{vmid}")]
                        if name and name != 'unknown' and base_name != name:
                            host.name = name
                            updated = True
                        elif base_name and base_name != host.name:
                            host.name = base_name
                            updated = True
                    elif name and name != 'unknown' and host.name != name:
                        # Update name if we have a better one
                        host.name = name
                        updated = True
                elif not host.name or host.name.lower() in ['unknown', 'unknown-host', ''] or \
                    host.name.startswith('unknown-'):
                    # Update name if current is unknown or generic
                    if name and name != 'unknown':
                        host.name = name
                        updated = True
            
                # Update device_type if it's unknown
                if not host.device_type or host.device_type == 'unknown':
                    host.device_type = vm_type
                    updated = True
            
                # Update source if it's not Proxmox (but don't overwrite if already Proxmox)
                if host.source != HostSource.PROXMOX:
                    host.source = HostSource.PROXMOX
                    updated = True
            
                if vmid and host.source == HostSource.PROXMOX:
                    import re
                    if not host.notes or not re.search(r'ID:\s*' + str(vmid), host.notes or '') or instance_tag not in (host.notes or ''):
                        if host.notes and 'Proxmox' in host.notes:
                            host.notes = re.sub(
                                r'Proxmox\s+\w+\s*\(ID:\s*\d+',
                                f'Proxmox {vm_type} (ID: {vmid}',
                                host.notes
                            )
                            if instance_tag not in host.notes:
                                host.notes = (host.notes or '').strip() + ' ' + instance_tag
                        else:
                            existing_notes = host.notes or ''
                            host.notes = f"{existing_notes}\nProxmox {vm_type} (ID: {vmid}, Node: {node}) {instance_tag}".strip()
                        updated = True
            
                if updated:
                    host.save()
                touched_host_ids.add(host.id)
            
                # Create interface attachments for all MACs
                if macs:
                    for mac in macs:
                        InterfaceAttachment.objects.get_or_create(
                            host=host,
                            medium=MediumType.ETHERNET,
                            defaults={}
                        )
            
                # Process IP addresses
                if ips:
                    for ip in ips:
                        ip_obj, ip_created = IPAddress.objects.get_or_create(
                            ip=ip,
                            defaults={
                                'host': host,
                                'assignment': 'static' if vm_type == 'lxc' else 'dhcp',
                                'online': True,
                            }
                        )
                        if not ip_created:
                            # IP already exists - check if it should be reassigned
                            if ip_obj.host and ip_obj.host != host:
                                # IP is assigned to a different host
                                existing_host = ip_obj.host
                            
                                if existing_host.source == HostSource.PROXMOX and host.source == HostSource.PROXMOX and vmid:
                                    if instance_tag not in (existing_host.notes or ''):
                                        continue
                                    import re
                                    existing_vmid_match = re.search(r'ID:\s*(\d+)', existing_host.notes or '')
                                    if existing_vmid_match:
                                        existing_vmid = int(existing_vmid_match.group(1))
                                        if existing_vmid != vmid:
                                            # Different Proxmox VMs - don't reassign IP, create new IP entry or skip
                                            self.stdout.write(
                                                self.style.WARNING(
                                                    f"  ⚠ IP {ip} already assigned to Proxmox VM {existing_vmid} ({existing_host.name}), "
                                                    f"skipping assignment to VM {vmid} ({name})"
                                                )
                                            )
                                            continue  # Skip this IP assignment
                            
                                # For non-Proxmox or same VMID, reassign to current host
                                ip_obj.host = host
                        
                            ip_obj.last_seen = timezone.now()
                            ip_obj.online = True
                            ip_obj.save()
                        else:
                            ip_count += 1
            
                touched_host_ids.add(host.id)

                synced_count += 1
                self.stdout.write(f"  ✓ {name} ({vm_type}) - IPs: {ips if ips else 'none'} - {host_identifier}")

            self.stdout.write(
                self.style.SUCCESS(
                    f"Synced {synced_count} Proxmox hosts from {len(integrations)} instance(s)"
                    + (f" and {ip_count} IP addresses" if ip_count > 0 else "")
                )
            )
            
            task_exec.record_success(items_processed=synced_count, output=f"Synced {synced_count} Proxmox hosts and {ip_count} IP addresses from {len(integrations)} instance(s)")

            # Record snapshot events for all touched hosts on every sync (not only changes)
            try:
                HostStatusEvent.record_snapshot_for_hosts(
                    touched_host_ids,
                    source='sync_proxmox',
                    task_execution=task_exec,
                    recorded_at=task_exec.completed_at,
                )
            except Exception as e:
                logger.error("Failed to record HostStatusEvent snapshot for sync_proxmox: %s", e)
            
            duration = task_exec.completed_at - task_exec.started_at if task_exec.completed_at else None
            duration_str = format_duration(duration.total_seconds()) if duration else 'N/A'
            Alert.objects.create(
                type=AlertType.TASK_COMPLETED,
                message=f"Proxmox sync completed: {synced_count} hosts synced, {ip_count} IP addresses ({len(integrations)} instance(s))",
                details=f"Task: Proxmox Sync\nStatus: Success\nInstances: {len(integrations)}\nHosts synced: {synced_count}\nIP addresses: {ip_count}\nDuration: {duration_str}\n\nOutput:\n{task_exec.output}",
            )
        except Exception as e:
            error_msg = f"Error syncing Proxmox: {str(e)}"
            logger.error(error_msg, exc_info=True)
            self.stdout.write(self.style.ERROR(error_msg))
            task_exec.record_error(error_msg)
            raise