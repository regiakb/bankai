"""
Management command to scan network for hosts (discovery scan).
"""
import logging
import os
import subprocess
import tempfile
from django.core.management.base import BaseCommand
from django.utils import timezone
from inventory.config_manager import should_notify_new_service
from inventory.models import Host, IPAddress, Alert, AlertType, HostSource, IPAssignment, TaskExecution, Service, Hostname, HostStatusEvent
from inventory.services.nmap_parser import parse_nmap_xml
from inventory.services.telegram import send_telegram, escape_telegram_html, inline_keyboard_setname
from inventory.views import format_duration

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Scan network for hosts using nmap discovery scan'

    def add_arguments(self, parser):
        parser.add_argument(
            '--cidr',
            type=str,
            required=True,
            help='CIDR network to scan (e.g., 192.168.1.0/24)',
        )
        parser.add_argument(
            '--skip-telegram',
            action='store_true',
            help='Skip Telegram notifications',
        )

    def handle(self, *args, **options):
        cidr = options['cidr']
        skip_telegram = options['skip_telegram']
        touched_host_ids = set()
        
        # Record task execution
        task_exec = TaskExecution.record_start('scan_discovery')
        logger.info("Discovery scan started for CIDR=%s", cidr)

        # Run a fast nmap scan (requested: nmap -T4 -F <CIDR>)
        self.stdout.write(f"Starting discovery scan for {cidr}...")
        self.stdout.write("Running fast scan: nmap -T4 -F (top 100 ports, aggressive timing)...")
        self.stdout.write("This should be much faster. Progress updates will appear below...")
        try:
            # Create temporary file for XML output
            temp_xml = tempfile.NamedTemporaryFile(mode='w+', suffix='.xml', delete=False)
            temp_xml_path = temp_xml.name
            temp_xml.close()
            
            # Keep XML output for parsing + normal output for progress, while matching requested base command.
            cmd = [
                'nmap',
                '-T4',  # Aggressive timing
                '-F',   # Fast mode (top 100 ports)
                '--stats-every', '10s',  # Show progress every 10 seconds
                '-vv',  # Very verbose output (shows hosts as they're discovered)
                '-oX', temp_xml_path,  # XML output to file (so we can parse results)
                '-oN', '-',  # Normal output to stdout for progress
                cidr,
            ]
            
            logger.info(
                "Nmap command: nmap -T4 -F --stats-every 10s -vv -oX <tmp> -oN - %s", cidr
            )
            # Run nmap with real-time output
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )
            logger.info("Nmap process started (PID=%s), reading output...", process.pid)

            # Read output line by line and display progress
            last_update = timezone.now()
            update_interval = 30  # Show update every 30 seconds
            start_time = timezone.now()
            hosts_found = set()  # Track unique hosts found
            
            # Track hosts that are actually up or have open ports
            active_hosts = set()  # IPs of hosts that are up or have open ports
            current_host_ip = None
            current_host_up = False
            current_host_has_open_ports = False
            first_line_at = None  # When we got first output from nmap

            # Read output line by line (blocking, but shows progress); accumulate for TaskExecution.output
            nmap_output_lines = []
            for line in process.stdout:
                line_stripped = line.strip()
                if line_stripped:
                    nmap_output_lines.append(line_stripped)
                    if first_line_at is None:
                        first_line_at = timezone.now()
                        elapsed_until_first = (first_line_at - start_time).total_seconds()
                        logger.info(
                            "First nmap output after %.1fs: %s",
                            elapsed_until_first,
                            line_stripped[:120] + ("..." if len(line_stripped) > 120 else ""),
                        )
                line = line_stripped
                if not line:
                    continue

                # Show important progress messages
                if 'Stats:' in line or 'Discovered' in line or 'scanned in' in line.lower():
                    self.stdout.write(line)
                elif 'Nmap scan report for' in line:
                    # New host found - reset tracking
                    parts = line.split('for')
                    if len(parts) > 1:
                        host_info = parts[1].strip()
                        # Extract IP or hostname
                        host_ip = host_info.split()[0] if host_info.split() else host_info
                        # Remove any brackets or extra info
                        host_ip = host_ip.split('[')[0].strip()
                        current_host_ip = host_ip
                        current_host_up = False
                        current_host_has_open_ports = False
                        logger.debug("Nmap scan report for host: %s", host_ip)
                elif 'Host is up' in line:
                    # Host is responding
                    current_host_up = True
                    if current_host_ip and current_host_ip not in active_hosts:
                        active_hosts.add(current_host_ip)
                        logger.info("Host is up: %s", current_host_ip)
                        self.stdout.write(f"  🔍 Found active host: {current_host_ip}")
                    self.stdout.write(f"    ✓ {line}")
                elif '/tcp' in line or '/udp' in line:
                    # Show ports/services
                    if 'open' in line.lower():
                        current_host_has_open_ports = True
                        if current_host_ip and current_host_ip not in active_hosts:
                            active_hosts.add(current_host_ip)
                            if not current_host_up:
                                self.stdout.write(f"  🔍 Found active host: {current_host_ip} (has open ports)")
                        self.stdout.write(f"    ✓ OPEN: {line}")
                    elif 'filtered' in line.lower():
                        self.stdout.write(f"    ⚠ FILTERED: {line}")
                elif 'PORT' in line and 'STATE' in line:
                    # Header for ports table
                    self.stdout.write(f"    {line}")
                
                # Periodic status update (every 30 seconds)
                now = timezone.now()
                elapsed = (now - last_update).total_seconds()
                if elapsed >= update_interval:
                    elapsed_min = int((now - start_time).total_seconds() / 60)
                    logger.info(
                        "Discovery progress: %s min elapsed, %s active hosts found (nmap lines so far: %s)",
                        elapsed_min, len(active_hosts), len(nmap_output_lines),
                    )
                    self.stdout.write(f"⏳ Progress: {elapsed_min} min elapsed, {len(active_hosts)} active hosts found")
                    last_update = now

            # Wait for process to complete
            process.wait()
            duration_sec = (timezone.now() - start_time).total_seconds()
            logger.info(
                "Nmap process finished: returncode=%s, duration=%.1fs, active_hosts=%s, total_output_lines=%s",
                process.returncode, duration_sec, len(active_hosts), len(nmap_output_lines),
            )
            if len(nmap_output_lines) == 0:
                logger.warning(
                    "Nmap produced no output (returncode=%s, duration=%.1fs). Check network from container or nmap install.",
                    process.returncode, duration_sec,
                )

            if process.returncode != 0:
                error_msg = f"Nmap scan failed with return code {process.returncode}"
                logger.error(error_msg)
                Alert.objects.create(
                    type='error',
                    message=error_msg,
                )
                self.stdout.write(self.style.ERROR(error_msg))
                try:
                    os.unlink(temp_xml_path)
                except:
                    pass
                return
            
            # Read XML output from file
            with open(temp_xml_path, 'r') as f:
                xml_output = f.read()
            logger.info("Nmap XML output read, size=%s bytes", len(xml_output))

            # Clean up temp file
            try:
                os.unlink(temp_xml_path)
            except:
                pass
            
        except subprocess.TimeoutExpired:
            error_msg = "Nmap scan timed out after 30 minutes"
            logger.error(error_msg)
            Alert.objects.create(type='error', message=error_msg)
            self.stdout.write(self.style.ERROR(error_msg))
            try:
                os.unlink(temp_xml_path)
            except:
                pass
            return
        except FileNotFoundError:
            error_msg = "nmap not found. Please install nmap."
            logger.error(error_msg)
            Alert.objects.create(type='error', message=error_msg)
            self.stdout.write(self.style.ERROR(error_msg))
            return
        except Exception as e:
            error_msg = f"Error running nmap: {e}"
            logger.error(error_msg)
            Alert.objects.create(type='error', message=error_msg)
            self.stdout.write(self.style.ERROR(error_msg))
            return
        
        # Parse XML
        parsed = parse_nmap_xml(xml_output)
        hosts_data = parsed.get('hosts', [])
        logger.info("XML parsed: %s hosts in nmap output", len(hosts_data))

        # Separate hosts into active (up or has open ports) and inactive (down with no open ports)
        active_hosts_data = []
        inactive_hosts_data = []
        
        for host_data in hosts_data:
            status = host_data.get('status', 'down')
            services = host_data.get('services', [])
            open_services = [s for s in services if s.get('state') in ['open', 'open|filtered']]
            
            # Hosts that are up OR have open ports are considered active
            if status == 'up' or len(open_services) > 0:
                active_hosts_data.append(host_data)
            else:
                # Host is down and has no open ports - mark as inactive
                inactive_hosts_data.append(host_data)
        
        logger.info(
            "Discovery hosts split: active=%s, inactive=%s, total=%s",
            len(active_hosts_data), len(inactive_hosts_data), len(hosts_data),
        )
        self.stdout.write(f"Found {len(active_hosts_data)} active hosts and {len(inactive_hosts_data)} inactive hosts (out of {len(hosts_data)} total scanned)")

        # First, mark inactive hosts as inactive
        for host_data in inactive_hosts_data:
            ip = host_data.get('ip')
            if not ip:
                continue
            
            # Find host by IP and mark as inactive
            try:
                ip_obj = IPAddress.objects.get(ip=ip)
                if ip_obj.host:
                    old_is_active = ip_obj.host.is_active
                    ip_obj.host.is_active = False
                    ip_obj.host.save()
                    touched_host_ids.add(ip_obj.host_id)
                    ip_obj.online = False
                    ip_obj.save()
                    self.stdout.write(f"Marked host {ip_obj.host.name} ({ip}) as inactive (host down)")
                    
                    # Create alert if status changed from active to inactive
                    if old_is_active and not ip_obj.host.is_active:
                        Alert.objects.create(
                            type='host_status_change',
                            message=f"Host {ip_obj.host.name} ({ip}) status changed to Inactive",
                            related_host=ip_obj.host,
                            related_ip=ip_obj,
                            details=f"Previous status: Active\nNew status: Inactive\nReason: Host detected as down by nmap"
                        )
            except IPAddress.DoesNotExist:
                # IP doesn't exist in DB, skip
                pass
            except Exception as e:
                logger.error(f"Error marking host {ip} as inactive: {e}")
        
        new_ips_count = 0
        
        for host_data in active_hosts_data:
            ip = host_data.get('ip')
            if not ip:
                continue
            
            # Check if IP is new
            ip_obj, ip_created = IPAddress.objects.get_or_create(
                ip=ip,
                defaults={
                    'online': host_data.get('status') == 'up',
                    'assignment': IPAssignment.UNKNOWN,
                }
            )
            
            if ip_created:
                new_ips_count += 1
                self.stdout.write(self.style.SUCCESS(f"New IP detected: {ip}"))
                
                # Create alert
                alert = Alert.objects.create(
                    type='new_ip',
                    message=f"New IP address detected: {ip}",
                    related_ip=ip_obj,
                )
                
                # Send Telegram notification with all available information
                if not skip_telegram and should_notify_new_service():
                    # Build notification message with all available info
                    message_parts = [
                        f"🔍 <b>New IP Detected</b>",
                        f"",
                        f"<b>IP:</b> <code>{escape_telegram_html(ip)}</code>",
                    ]
                    
                    # Hostname
                    hostname = host_data.get('hostname')
                    if hostname:
                        message_parts.append(f"<b>Hostname:</b> <code>{escape_telegram_html(hostname)}</code>")
                    
                    # MAC and Vendor
                    mac = host_data.get('mac')
                    vendor = host_data.get('vendor')
                    if mac:
                        mac_info = f"<code>{escape_telegram_html(mac)}</code>"
                        if vendor:
                            mac_info += f" ({escape_telegram_html(vendor)})"
                        message_parts.append(f"<b>MAC:</b> {mac_info}")
                    
                    # OS Information
                    os_info = host_data.get('os')
                    if os_info:
                        os_accuracy = host_data.get('os_accuracy', '0')
                        message_parts.append(f"<b>OS:</b> {escape_telegram_html(os_info)} (accuracy: {escape_telegram_html(os_accuracy)}%)")
                    
                    # Services/Ports
                    services = host_data.get('services', [])
                    if services:
                        message_parts.append(f"<b>Open Ports/Services:</b>")
                        for svc in services[:10]:  # Limit to first 10 services
                            port = svc.get('port')
                            proto = svc.get('proto', 'tcp')
                            name = svc.get('name', 'unknown')
                            product = svc.get('product', '')
                            version = svc.get('version', '')
                            
                            svc_info = f"  • <code>{port}/{proto}</code> - {escape_telegram_html(str(name))}"
                            if product:
                                svc_info += f" ({escape_telegram_html(product)}"
                                if version:
                                    svc_info += f" {escape_telegram_html(version)}"
                                svc_info += ")"
                            message_parts.append(svc_info)
                        
                        if len(services) > 10:
                            message_parts.append(f"  ... and {len(services) - 10} more")
                    
                    # Try to get additional info from database
                    # First, check if host exists for this IP (might have been created in a previous scan)
                    try:
                        # Try to find host by IP
                        host = None
                        if ip_obj.host:
                            host = ip_obj.host
                        else:
                            # Try to find by MAC if available
                            if mac:
                                host = Host.objects.filter(mac=mac.lower()).first()
                            # Try to find by hostname if available
                            if not host and hostname:
                                host = Host.objects.filter(name=hostname).first()
                        
                        if host:
                            if host.name and host.name != 'unknown' and host.name != hostname:
                                # Insert after IP
                                for i, part in enumerate(message_parts):
                                    if '<b>IP:</b>' in part:
                                        message_parts.insert(i+1, f"<b>Host Name:</b> <code>{escape_telegram_html(host.name)}</code>")
                                        break
                            
                            if host.device_type and host.device_type != 'unknown':
                                message_parts.append(f"<b>Device Type:</b> {escape_telegram_html(host.device_type)}")
                            
                            if host.vendor and host.vendor != vendor:
                                message_parts.append(f"<b>Vendor:</b> {escape_telegram_html(host.vendor)}")
                            
                            # Get services from database (limit to 10 most recent)
                            db_services = host.services.all().order_by('-last_seen')[:10]
                            if db_services:
                                if not services:  # Only show DB services if no services from scan
                                    message_parts.append(f"<b>Known Services:</b>")
                                else:
                                    message_parts.append(f"<b>Additional Services (DB):</b>")
                                
                                for svc in db_services:
                                    svc_info = f"  • <code>{svc.port}/{svc.proto}</code> - {escape_telegram_html(svc.name or 'unknown')}"
                                    if svc.product:
                                        svc_info += f" ({escape_telegram_html(svc.product)}"
                                        if svc.version:
                                            svc_info += f" {escape_telegram_html(svc.version)}"
                                        svc_info += ")"
                                    message_parts.append(svc_info)
                    except Exception as e:
                        logger.debug(f"Could not get additional DB info: {e}")
                    
                    message_parts.append(f"<b>Time:</b> {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    send_telegram("\n".join(message_parts), reply_markup=inline_keyboard_setname(ip))
            else:
                # Update existing IP
                ip_obj.online = host_data.get('status') == 'up'
                ip_obj.last_seen = timezone.now()
                ip_obj.save()
            
            # Handle host
            hostname = host_data.get('hostname')
            mac = host_data.get('mac')
            os_info = host_data.get('os')
            services = host_data.get('services', [])
            
            # First, check if IP already has a host (most reliable for merge)
            host = None
            if ip_obj.host:
                host = ip_obj.host
                # Check if status changed before updating
                old_is_active = host.is_active
                
                # Merge data from nmap into existing host
                host.last_seen = timezone.now()
                # Mark as active if host is up or has open ports
                host_status = host_data.get('status', 'down')
                open_services = [s for s in services if s.get('state') in ['open', 'open|filtered']]
                host.is_active = (host_status == 'up' or len(open_services) > 0)
                
                # Create alert and status event if status changed
                if old_is_active != host.is_active:
                    status_text = "Active" if host.is_active else "Inactive"
                    Alert.objects.create(
                        type='host_status_change',
                        message=f"Host {host.name} ({ip}) status changed to {status_text}",
                        related_host=host,
                        related_ip=ip_obj,
                        details=f"Previous status: {'Active' if old_is_active else 'Inactive'}\nNew status: {status_text}\nNmap status: {host_status}\nOpen ports: {len(open_services)}"
                    )

                # Complement name if current is unknown or generic
                if hostname and (not host.name or host.name.lower() in ['unknown', 'unknown-host', ''] or 
                                 host.name.startswith('unknown-') or host.name == 'unknown'):
                    host.name = hostname
                
                # Save all hostnames found
                hostnames_found = host_data.get('hostnames', [])
                if hostnames_found:
                    for hostname_info in hostnames_found:
                        hostname_name = hostname_info.get('name', '').strip()
                        source_type = hostname_info.get('source_type', 'dns')
                        if hostname_name:
                            hostname_obj, created = Hostname.objects.get_or_create(
                                host=host,
                                name=hostname_name,
                                defaults={'source_type': source_type}
                            )
                            if not created:
                                # Update last_seen for existing hostname
                                hostname_obj.last_seen = timezone.now()
                                hostname_obj.save()
                
                # Complement vendor if missing
                if host_data.get('vendor') and not host.vendor:
                    host.vendor = host_data.get('vendor', '')
                
                # Complement device_type if it's unknown (but don't overwrite if it's already set from Proxmox)
                if (not host.device_type or host.device_type == 'unknown') and host.source != HostSource.PROXMOX:
                    # Keep unknown for nmap-discovered hosts
                    pass
                
                # Update OS information in notes
                if os_info:
                    os_accuracy = host_data.get('os_accuracy', '0')
                    os_note = f"OS: {os_info} (accuracy: {os_accuracy}%)"
                    if host.notes:
                        # Check if OS info already exists in notes
                        if 'OS:' not in host.notes:
                            host.notes = f"{host.notes}\n{os_note}".strip()
                        else:
                            # Update existing OS info
                            lines = host.notes.split('\n')
                            updated = False
                            for i, line in enumerate(lines):
                                if line.startswith('OS:'):
                                    lines[i] = os_note
                                    updated = True
                                    break
                            if updated:
                                host.notes = '\n'.join(lines)
                            else:
                                host.notes = f"{host.notes}\n{os_note}".strip()
                    else:
                        host.notes = os_note
                
                host.save()
                touched_host_ids.add(host.id)
                
                # Save services discovered during discovery scan
                for service_data in services:
                    port = service_data.get('port')
                    proto = service_data.get('proto', 'tcp')
                    
                    Service.objects.update_or_create(
                        host=host,
                        port=port,
                        proto=proto,
                        defaults={
                            'name': service_data.get('name', ''),
                            'product': service_data.get('product', ''),
                            'version': service_data.get('version', ''),
                            'extra_info': service_data.get('extra_info', ''),
                            'last_seen': timezone.now(),
                        }
                    )
            elif mac:
                # Try to find by MAC
                host, _ = Host.objects.get_or_create(
                    mac=mac.lower(),
                    defaults={
                        'name': hostname or 'unknown',
                        'vendor': host_data.get('vendor', ''),
                        'source': HostSource.NMAP,
                        'device_type': 'unknown',
                    }
                )
                if not _:
                    # Update existing - complement data
                    # Check if status changed before updating
                    old_is_active = host.is_active
                    
                    host.last_seen = timezone.now()
                    # Mark as active if host is up or has open ports
                    host_status = host_data.get('status', 'down')
                    open_services = [s for s in services if s.get('state') in ['open', 'open|filtered']]
                    host.is_active = (host_status == 'up' or len(open_services) > 0)
                    
                    # Create alert and status event if status changed
                    if old_is_active != host.is_active:
                        status_text = "Active" if host.is_active else "Inactive"
                        ip = host_data.get('ip', 'unknown')
                        try:
                            ip_obj = IPAddress.objects.get(ip=ip)
                        except IPAddress.DoesNotExist:
                            ip_obj = None
                        Alert.objects.create(
                            type='host_status_change',
                            message=f"Host {host.name} ({ip}) status changed to {status_text}",
                            related_host=host,
                            related_ip=ip_obj,
                            details=f"Previous status: {'Active' if old_is_active else 'Inactive'}\nNew status: {status_text}\nNmap status: {host_status}\nOpen ports: {len(open_services)}"
                        )
                    # Update name if current is unknown or generic
                    if hostname and (not host.name or host.name.lower() in ['unknown', 'unknown-host', ''] or 
                                     host.name.startswith('unknown-')):
                        host.name = hostname
                    
                    # Save all hostnames found
                    hostnames_found = host_data.get('hostnames', [])
                    if hostnames_found:
                        for hostname_info in hostnames_found:
                            hostname_name = hostname_info.get('name', '').strip()
                            source_type = hostname_info.get('source_type', 'dns')
                            if hostname_name:
                                hostname_obj, created = Hostname.objects.get_or_create(
                                    host=host,
                                    name=hostname_name,
                                    defaults={'source_type': source_type}
                                )
                                if not created:
                                    hostname_obj.last_seen = timezone.now()
                                    hostname_obj.save()
                    
                    # Update vendor if missing
                    if host_data.get('vendor') and not host.vendor:
                        host.vendor = host_data.get('vendor', '')
                    
                    # Update OS information in notes
                    if os_info:
                        os_accuracy = host_data.get('os_accuracy', '0')
                        os_note = f"OS: {os_info} (accuracy: {os_accuracy}%)"
                        if host.notes:
                            if 'OS:' not in host.notes:
                                host.notes = f"{host.notes}\n{os_note}".strip()
                            else:
                                lines = host.notes.split('\n')
                                updated = False
                                for i, line in enumerate(lines):
                                    if line.startswith('OS:'):
                                        lines[i] = os_note
                                        updated = True
                                        break
                                if updated:
                                    host.notes = '\n'.join(lines)
                                else:
                                    host.notes = f"{host.notes}\n{os_note}".strip()
                        else:
                            host.notes = os_note
                    
                    host.save()
                    touched_host_ids.add(host.id)
                    
                    # Save services discovered during discovery scan
                    for service_data in services:
                        port = service_data.get('port')
                        proto = service_data.get('proto', 'tcp')
                        
                        Service.objects.update_or_create(
                            host=host,
                            port=port,
                            proto=proto,
                            defaults={
                                'name': service_data.get('name', ''),
                                'product': service_data.get('product', ''),
                                'version': service_data.get('version', ''),
                                'extra_info': service_data.get('extra_info', ''),
                                'last_seen': timezone.now(),
                            }
                        )
            elif hostname:
                # Try to find by name (less reliable)
                host = Host.objects.filter(name=hostname).first()
                if not host:
                    host = Host.objects.create(
                        name=hostname,
                        source=HostSource.NMAP,
                        device_type='unknown',
                    )
                else:
                    # Check if status changed before updating
                    old_is_active = host.is_active
                    
                    host.last_seen = timezone.now()
                    # Mark as active if host is up or has open ports
                    host_status = host_data.get('status', 'down')
                    open_services = [s for s in services if s.get('state') in ['open', 'open|filtered']]
                    host.is_active = (host_status == 'up' or len(open_services) > 0)
                    host.save()
                    
                    # Create alert and status event if status changed
                    if old_is_active != host.is_active:
                        status_text = "Active" if host.is_active else "Inactive"
                        ip = host_data.get('ip', 'unknown')
                        try:
                            ip_obj = IPAddress.objects.get(ip=ip)
                        except IPAddress.DoesNotExist:
                            ip_obj = None
                        Alert.objects.create(
                            type='host_status_change',
                            message=f"Host {host.name} ({ip}) status changed to {status_text}",
                            related_host=host,
                            related_ip=ip_obj,
                            details=f"Previous status: {'Active' if old_is_active else 'Inactive'}\nNew status: {status_text}\nNmap status: {host_status}\nOpen ports: {len(open_services)}"
                        )

            if not host:
                # Create placeholder host with simple "unknown" name
                notes = ''
                if os_info:
                    os_accuracy = host_data.get('os_accuracy', '0')
                    notes = f"OS: {os_info} (accuracy: {os_accuracy}%)"
                
                # Determine if host should be active (up or has open ports)
                host_status = host_data.get('status', 'down')
                open_services = [s for s in services if s.get('state') in ['open', 'open|filtered']]
                is_active = (host_status == 'up' or len(open_services) > 0)
                
                host = Host.objects.create(
                    name=hostname or 'unknown',
                    source=HostSource.NMAP,
                    device_type='unknown',
                    vendor=host_data.get('vendor', '') if mac else '',
                    notes=notes,
                    is_active=is_active,
                )
                touched_host_ids.add(host.id)
            else:
                # Existing host path
                touched_host_ids.add(host.id)

            # Link IP to host
            if ip_obj.host != host:
                ip_obj.host = host
                ip_obj.save()
            
            # Save all hostnames found (for all hosts, including newly created)
            hostnames_found = host_data.get('hostnames', [])
            if hostnames_found:
                for hostname_info in hostnames_found:
                    hostname_name = hostname_info.get('name', '').strip()
                    source_type = hostname_info.get('source_type', 'dns')
                    if hostname_name:
                        hostname_obj, created = Hostname.objects.get_or_create(
                            host=host,
                            name=hostname_name,
                            defaults={'source_type': source_type}
                        )
                        if not created:
                            hostname_obj.last_seen = timezone.now()
                            hostname_obj.save()
            
            # Save services discovered during discovery scan (for newly created hosts)
            if services:
                for service_data in services:
                    port = service_data.get('port')
                    proto = service_data.get('proto', 'tcp')
                    
                    Service.objects.update_or_create(
                        host=host,
                        port=port,
                        proto=proto,
                        defaults={
                            'name': service_data.get('name', ''),
                            'product': service_data.get('product', ''),
                            'version': service_data.get('version', ''),
                            'extra_info': service_data.get('extra_info', ''),
                            'last_seen': timezone.now(),
                        }
                    )
        
        duration_total = (timezone.now() - task_exec.started_at).total_seconds()
        logger.info(
            "Discovery scan completed: active_hosts=%s, new_ips=%s, duration_sec=%.1f",
            len(active_hosts_data), new_ips_count, duration_total,
        )
        self.stdout.write(
            self.style.SUCCESS(
                f"Scan complete. Processed {len(active_hosts_data)} active hosts, "
                f"{new_ips_count} new IPs detected."
            )
        )

        # Record successful completion (include nmap output for Telegram/summary)
        nmap_output_text = '\n'.join(nmap_output_lines) if nmap_output_lines else f"Processed {len(active_hosts_data)} active hosts, {new_ips_count} new IPs"
        task_exec.record_success(items_processed=len(active_hosts_data), output=nmap_output_text)

        # Record snapshot events for ALL touched hosts (so connection history captures full runs, not only changes)
        try:
            created = HostStatusEvent.record_snapshot_for_hosts(
                touched_host_ids,
                source='scan_discovery',
                task_execution=task_exec,
                recorded_at=task_exec.completed_at,
            )
            logger.info("Recorded %s HostStatusEvent snapshot rows for scan_discovery", created)
        except Exception as e:
            logger.error("Failed to record HostStatusEvent snapshot for scan_discovery: %s", e)
        
        # Create alert with results
        duration = task_exec.completed_at - task_exec.started_at if task_exec.completed_at else None
        if duration:
            total_seconds = duration.total_seconds()
            duration_str = format_duration(total_seconds)
        else:
            duration_str = 'N/A'
        Alert.objects.create(
            type=AlertType.TASK_COMPLETED,
            message=f"Discovery scan completed: {len(active_hosts_data)} active hosts found, {new_ips_count} new IPs detected",
            details=f"Task: Discovery Scan\nStatus: Success\nHosts processed: {len(active_hosts_data)}\nNew IPs: {new_ips_count}\nDuration: {duration_str}\n\nOutput:\n{task_exec.output}",
        )