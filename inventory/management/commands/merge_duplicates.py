"""
Management command to merge duplicate hosts.
"""
import logging
from django.core.management.base import BaseCommand
from django.utils import timezone
from inventory.models import Host, IPAddress, Service, InterfaceAttachment, HostStatusEvent

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Merge duplicate hosts based on IP addresses'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be merged without actually merging',
        )

    def handle(self, *args, **options):
        dry_run = options.get('dry_run', False)
        
        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN MODE - No changes will be made"))
            self.stdout.write("=" * 60)
        
        merged_count = 0
        
        # Method 1: Find hosts with duplicate IPs (same IP assigned to multiple hosts)
        ip_addresses = IPAddress.objects.filter(host__isnull=False).select_related('host')
        ip_to_hosts = {}
        for ip_obj in ip_addresses:
            ip = ip_obj.ip
            if ip not in ip_to_hosts:
                ip_to_hosts[ip] = []
            if ip_obj.host and ip_obj.host not in ip_to_hosts[ip]:
                ip_to_hosts[ip].append(ip_obj.host)
        
        duplicates_found = {}
        for ip, hosts in ip_to_hosts.items():
            if len(hosts) > 1:
                duplicates_found[ip] = hosts
        
        # Also find hosts that share at least one IP (even if not exact duplicates)
        # This catches cases where Proxmox and Nmap found the same device
        host_ip_map = {}
        for ip_obj in ip_addresses:
            if ip_obj.host:
                if ip_obj.host not in host_ip_map:
                    host_ip_map[ip_obj.host] = []
                host_ip_map[ip_obj.host].append(ip_obj.ip)
        
        # Find hosts that share IPs
        shared_ip_duplicates = {}
        processed_pairs = set()
        for host1, ips1 in host_ip_map.items():
            for host2, ips2 in host_ip_map.items():
                if host1.id == host2.id:
                    continue
                shared_ips = set(ips1) & set(ips2)
                if shared_ips:
                    pair_key = tuple(sorted([host1.id, host2.id]))
                    if pair_key not in processed_pairs:
                        processed_pairs.add(pair_key)
                        # Use first shared IP as key
                        key_ip = list(shared_ips)[0]
                        if key_ip not in shared_ip_duplicates:
                            shared_ip_duplicates[key_ip] = []
                        if host1 not in shared_ip_duplicates[key_ip]:
                            shared_ip_duplicates[key_ip].append(host1)
                        if host2 not in shared_ip_duplicates[key_ip]:
                            shared_ip_duplicates[key_ip].append(host2)
        
        # Merge shared IP duplicates into duplicates_found
        for ip, hosts in shared_ip_duplicates.items():
            if ip not in duplicates_found:
                duplicates_found[ip] = []
            for host in hosts:
                if host not in duplicates_found[ip]:
                    duplicates_found[ip].append(host)
        
        # Method 2: Find Proxmox hosts with same VMID but different names
        # Also find hosts with same base name (e.g., "pialert" and "pialert-202")
        import re
        all_hosts = Host.objects.filter(source='proxmox').prefetch_related('ip_addresses')
        vmid_to_hosts = {}
        name_to_hosts = {}  # Group by base name
        
        for host in all_hosts:
            vmid = None
            # Extract VMID from notes: "Proxmox qemu (ID: 107, Node: rs1core)"
            vmid_match = re.search(r'ID:\s*(\d+)', host.notes or '')
            if vmid_match:
                vmid = int(vmid_match.group(1))
            else:
                # Try to extract from name: "pialert-202" -> 202
                name_vmid_match = re.search(r'-(\d+)$', host.name)
                if name_vmid_match:
                    vmid = int(name_vmid_match.group(1))
            
            if vmid:
                if vmid not in vmid_to_hosts:
                    vmid_to_hosts[vmid] = []
                vmid_to_hosts[vmid].append(host)
            
            # Also group by base name (remove VMID suffix if present)
            base_name = re.sub(r'-\d+$', '', host.name)
            if base_name not in name_to_hosts:
                name_to_hosts[base_name] = []
            name_to_hosts[base_name].append(host)
        
        # Find VMIDs with multiple hosts (duplicates)
        vmid_duplicates = {}
        for vmid, host_list in vmid_to_hosts.items():
            if len(host_list) > 1:
                # Multiple hosts with same VMID - these are duplicates
                unique_hosts = list(set(host_list))  # Remove any duplicates
                if len(unique_hosts) > 1:
                    # Use first IP of first host as key
                    first_ip = None
                    for host in unique_hosts:
                        host_ips = [ip.ip for ip in host.ip_addresses.all()]
                        if host_ips:
                            first_ip = host_ips[0]
                            break
                    if not first_ip:
                        first_ip = f"vmid_{vmid}"
                    vmid_duplicates[first_ip] = unique_hosts
        
        # Find hosts with same base name but different VMID suffixes (e.g., "pialert" and "pialert-202")
        name_duplicates = {}
        for base_name, host_list in name_to_hosts.items():
            if len(host_list) > 1:
                # Check if they have different VMIDs or one has VMID and other doesn't
                unique_hosts = list(set(host_list))
                if len(unique_hosts) > 1:
                    # Check if they're actually duplicates (same VMID or one missing VMID)
                    should_merge = False
                    vmids_found = set()
                    for host in unique_hosts:
                        vmid = None
                        vmid_match = re.search(r'ID:\s*(\d+)', host.notes or '')
                        if vmid_match:
                            vmid = int(vmid_match.group(1))
                        else:
                            name_vmid_match = re.search(r'-(\d+)$', host.name)
                            if name_vmid_match:
                                vmid = int(name_vmid_match.group(1))
                        if vmid:
                            vmids_found.add(vmid)
                    
                    # If all have same VMID, or one has VMID and others don't (likely same host)
                    if len(vmids_found) <= 1:
                        should_merge = True
                    
                    if should_merge:
                        first_ip = None
                        for host in unique_hosts:
                            host_ips = [ip.ip for ip in host.ip_addresses.all()]
                            if host_ips:
                                first_ip = host_ips[0]
                                break
                        if not first_ip:
                            first_ip = f"name_{base_name}"
                        name_duplicates[first_ip] = unique_hosts
        
        # Method 3: Find hosts with names containing IPs that exist in other hosts
        all_ips = set(IPAddress.objects.values_list('ip', flat=True))
        ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        name_based_duplicates = {}
        
        for host in Host.objects.all().prefetch_related('ip_addresses'):
            # Extract IP from host name
            name_ips = ip_pattern.findall(host.name)
            host_ips = set(ip.ip for ip in host.ip_addresses.all())
            
            for name_ip in name_ips:
                # If the IP in the name exists in database but not assigned to this host
                if name_ip in all_ips and name_ip not in host_ips:
                    # Find the host that has this IP
                    ip_obj = IPAddress.objects.filter(ip=name_ip).first()
                    if ip_obj and ip_obj.host and ip_obj.host.id != host.id:
                        # These should be merged
                        key = f"name_ip_{name_ip}"
                        if key not in name_based_duplicates:
                            name_based_duplicates[key] = []
                        if ip_obj.host not in name_based_duplicates[key]:
                            name_based_duplicates[key].append(ip_obj.host)
                        if host not in name_based_duplicates[key]:
                            name_based_duplicates[key].append(host)
        
        # Method 4: Find hosts that share IPs (transitive)
        host_to_ips = {}
        for ip_obj in ip_addresses:
            if ip_obj.host:
                if ip_obj.host not in host_to_ips:
                    host_to_ips[ip_obj.host] = []
                if ip_obj.ip not in host_to_ips[ip_obj.host]:
                    host_to_ips[ip_obj.host].append(ip_obj.ip)
        
        hosts_to_merge = {}
        processed_hosts = set()
        
        for host1, ips1 in host_to_ips.items():
            if host1.id in processed_hosts:
                continue
            
            merge_group = [host1]
            for host2, ips2 in host_to_ips.items():
                if host2.id == host1.id or host2.id in processed_hosts:
                    continue
                if set(ips1) & set(ips2):
                    merge_group.append(host2)
                    processed_hosts.add(host2.id)
            
            if len(merge_group) > 1:
                key_ip = ips1[0]
                hosts_to_merge[key_ip] = merge_group
                processed_hosts.add(host1.id)
        
        # Combine all duplicate detection methods
        all_duplicates = {}
        
        # Add direct IP duplicates
        for ip, hosts in duplicates_found.items():
            all_duplicates[ip] = hosts
        
        # Add VMID-based duplicates (Proxmox hosts with same VMID)
        for ip, hosts in vmid_duplicates.items():
            if ip not in all_duplicates:
                all_duplicates[ip] = []
            for host in hosts:
                if host not in all_duplicates[ip]:
                    all_duplicates[ip].append(host)
        
        # Add name-based duplicates (Proxmox hosts with same base name)
        for ip, hosts in name_duplicates.items():
            if ip not in all_duplicates:
                all_duplicates[ip] = []
            for host in hosts:
                if host not in all_duplicates[ip]:
                    all_duplicates[ip].append(host)
        
        # Add name-based duplicates
        for key, hosts in name_based_duplicates.items():
            # Use the IP from the key as identifier
            ip = key.replace('name_ip_', '')
            if ip not in all_duplicates:
                all_duplicates[ip] = []
            for host in hosts:
                if host not in all_duplicates[ip]:
                    all_duplicates[ip].append(host)
        
        # Add transitive duplicates (avoid duplicates)
        for ip, hosts in hosts_to_merge.items():
            if ip not in all_duplicates:
                all_duplicates[ip] = hosts
            else:
                # Merge lists
                for host in hosts:
                    if host not in all_duplicates[ip]:
                        all_duplicates[ip].append(host)
        
        # Remove groups with only one host
        all_duplicates = {ip: hosts for ip, hosts in all_duplicates.items() if len(set(h.id for h in hosts)) > 1}
        
        if not all_duplicates:
            self.stdout.write(self.style.SUCCESS("No duplicate hosts found"))
            self.stdout.write("\nDebug info:")
            self.stdout.write(f"  Total hosts: {Host.objects.count()}")
            self.stdout.write(f"  Total IPs: {IPAddress.objects.count()}")
            self.stdout.write(f"  IPs with hosts: {IPAddress.objects.filter(host__isnull=False).count()}")
            return
        
        self.stdout.write(f"Found {len(all_duplicates)} group(s) of duplicate hosts")
        
        # Merge hosts for each duplicate group
        for ip, hosts in all_duplicates.items():
            # Remove duplicates from hosts list
            unique_hosts = []
            seen_ids = set()
            for host in hosts:
                if host.id not in seen_ids:
                    unique_hosts.append(host)
                    seen_ids.add(host.id)
            hosts = unique_hosts
            
            if len(hosts) <= 1:
                continue
            
            # IMPORTANT: Don't merge Proxmox hosts with different VMIDs
            # Also merge Proxmox hosts with same VMID but different names (e.g., "pialert" and "pialert-202")
            import re
            proxmox_hosts = [h for h in hosts if h.source == 'proxmox']
            if len(proxmox_hosts) > 1:
                # Extract VMIDs from notes and names
                vmids_info = []
                for host in proxmox_hosts:
                    vmid_from_notes = None
                    vmid_from_name = None
                    
                    # Extract VMID from notes: "Proxmox qemu (ID: 107, Node: rs1core)"
                    vmid_match = re.search(r'ID:\s*(\d+)', host.notes or '')
                    if vmid_match:
                        vmid_from_notes = int(vmid_match.group(1))
                    
                    # Extract VMID from name: "pialert-202" -> 202
                    name_vmid_match = re.search(r'-(\d+)$', host.name)
                    if name_vmid_match:
                        vmid_from_name = int(name_vmid_match.group(1))
                    
                    # Use VMID from notes if available, otherwise from name
                    vmid = vmid_from_notes or vmid_from_name
                    vmids_info.append((host.id, vmid, host.name))
                
                # Group by VMID
                vmid_groups = {}
                for host_id, vmid, host_name in vmids_info:
                    if vmid:
                        if vmid not in vmid_groups:
                            vmid_groups[vmid] = []
                        vmid_groups[vmid].append((host_id, host_name))
                
                # If we have different VMIDs, these are different VMs - don't merge
                if len(vmid_groups) > 1:
                    self.stdout.write(f"\nIP {ip}:")
                    self.stdout.write(self.style.WARNING(f"  SKIPPING: Different Proxmox VMs detected (different VMIDs)"))
                    for vmid, host_list in vmid_groups.items():
                        for host_id, host_name in host_list:
                            self.stdout.write(f"    - {host_name} (ID: {host_id}, VMID: {vmid})")
                    continue
                
                # If same VMID but different hosts, these should be merged (same VM, different name format)
                if len(vmid_groups) == 1 and len(proxmox_hosts) > 1:
                    # Same VMID, different hosts - these are duplicates that should be merged
                    self.stdout.write(f"\nIP {ip}:")
                    self.stdout.write(self.style.SUCCESS(f"  Found Proxmox hosts with same VMID - will merge duplicates"))
                    for host_id, host_name in list(vmid_groups.values())[0]:
                        self.stdout.write(f"    - {host_name} (ID: {host_id})")
            
            # Choose the "best" host to keep
            # Priority: 1) Proxmox with VMID, 2) Proxmox without VMID, 3) Named hosts, 4) Unknown hosts, 5) Most recent
            hosts_sorted = sorted(hosts, key=lambda h: (
                h.source != 'proxmox',  # Proxmox first
                not (h.notes and 'ID:' in h.notes) if h.source == 'proxmox' else True,  # Proxmox with VMID first
                h.name.lower().startswith('unknown'),  # Named hosts first
                h.name == 'unknown',  # "unknown" before "unknown-ip"
                -len([ip for ip in h.ip_addresses.all()]),  # More IPs first
                -h.last_seen.timestamp() if h.last_seen else 0  # Most recent
            ))
            
            primary_host = hosts_sorted[0]
            duplicate_hosts = hosts_sorted[1:]
            
            self.stdout.write(f"\nIP {ip}:")
            self.stdout.write(f"  Keeping: {primary_host.name} (ID: {primary_host.id}, Source: {primary_host.get_source_display()}, Type: {primary_host.device_type})")
            
            for dup_host in duplicate_hosts:
                self.stdout.write(f"  Merging: {dup_host.name} (ID: {dup_host.id}, Source: {dup_host.get_source_display()}, Type: {dup_host.device_type})")
                
                # Count for dry-run too
                merged_count += 1
                
                if not dry_run:
                    # Merge data from duplicate into primary
                    # Update name if primary is unknown
                    if (not primary_host.name or primary_host.name.lower() in ['unknown', 'unknown-host', ''] or 
                        primary_host.name.startswith('unknown-')) and dup_host.name and not dup_host.name.startswith('unknown-'):
                        primary_host.name = dup_host.name
                    
                    # Update device_type if primary is unknown
                    if (not primary_host.device_type or primary_host.device_type == 'unknown') and dup_host.device_type and dup_host.device_type != 'unknown':
                        primary_host.device_type = dup_host.device_type
                    
                    # Update vendor if missing
                    if not primary_host.vendor and dup_host.vendor:
                        primary_host.vendor = dup_host.vendor
                    
                    # Update source to better source (Proxmox > Nmap > Manual)
                    source_priority = {'proxmox': 3, 'nmap': 2, 'manual': 1}
                    if source_priority.get(primary_host.source, 0) < source_priority.get(dup_host.source, 0):
                        primary_host.source = dup_host.source
                    
                    # Merge MAC if primary doesn't have one
                    # But check if the MAC doesn't already exist in another host
                    if not primary_host.mac and dup_host.mac:
                        # Check if this MAC is already assigned to another host
                        existing_mac_host = Host.objects.filter(mac=dup_host.mac).exclude(id=primary_host.id).first()
                        if not existing_mac_host:
                            primary_host.mac = dup_host.mac
                        else:
                            self.stdout.write(f"    Warning: MAC {dup_host.mac} already assigned to host {existing_mac_host.name}, skipping")
                    
                    # If primary has MAC but duplicate has different MAC, clear duplicate's MAC first
                    if primary_host.mac and dup_host.mac and primary_host.mac != dup_host.mac:
                        # Clear duplicate's MAC to avoid unique constraint violation
                        dup_host.mac = None
                        dup_host.save()
                    
                    # Merge notes
                    if dup_host.notes:
                        existing_notes = primary_host.notes or ''
                        if dup_host.notes not in existing_notes:
                            primary_host.notes = f"{existing_notes}\n{dup_host.notes}".strip() if existing_notes else dup_host.notes
                    
                    # Update last_seen to most recent
                    if dup_host.last_seen and (not primary_host.last_seen or dup_host.last_seen > primary_host.last_seen):
                        primary_host.last_seen = dup_host.last_seen
                    
                    old_active = primary_host.is_active
                    primary_host.is_active = primary_host.is_active or dup_host.is_active
                    primary_host.save()
                    if old_active != primary_host.is_active:
                        HostStatusEvent.record(primary_host, primary_host.is_active)
                    
                    # Move all IPs from duplicate to primary
                    IPAddress.objects.filter(host=dup_host).update(host=primary_host)
                    
                    # Move all services from duplicate to primary
                    # Handle duplicate services (same port/proto) by merging data
                    for dup_service in Service.objects.filter(host=dup_host):
                        # Check if primary host already has a service with same port/proto
                        existing_service = Service.objects.filter(
                            host=primary_host,
                            port=dup_service.port,
                            proto=dup_service.proto
                        ).first()
                        
                        if existing_service:
                            # Merge service data - update if duplicate has more info
                            updated = False
                            if not existing_service.name and dup_service.name:
                                existing_service.name = dup_service.name
                                updated = True
                            if not existing_service.product and dup_service.product:
                                existing_service.product = dup_service.product
                                updated = True
                            if not existing_service.version and dup_service.version:
                                existing_service.version = dup_service.version
                                updated = True
                            if not existing_service.extra_info and dup_service.extra_info:
                                existing_service.extra_info = dup_service.extra_info
                                updated = True
                            # Update last_seen to most recent
                            if dup_service.last_seen and (not existing_service.last_seen or dup_service.last_seen > existing_service.last_seen):
                                existing_service.last_seen = dup_service.last_seen
                                updated = True
                            if updated:
                                existing_service.save()
                            # Delete duplicate service
                            dup_service.delete()
                        else:
                            # No conflict - just move the service
                            dup_service.host = primary_host
                            dup_service.save()
                    
                    # Move all interfaces from duplicate to primary
                    InterfaceAttachment.objects.filter(host=dup_host).update(host=primary_host)
                    
                    # Delete duplicate host
                    dup_host.delete()
                    
                    merged_count += 1
        
        if dry_run:
            self.stdout.write(self.style.WARNING(f"\nWould merge {merged_count} duplicate host(s)"))
        else:
            self.stdout.write(self.style.SUCCESS(f"\nMerged {merged_count} duplicate host(s)"))
