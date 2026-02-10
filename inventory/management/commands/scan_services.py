"""
Management command to scan hosts for services/ports.
"""
import logging
import subprocess
import time
import threading
import queue
from django.core.management.base import BaseCommand
from django.utils import timezone
from inventory.config_manager import should_notify_new_service
from inventory.models import Host, Service, Alert, AlertType, TaskExecution, Hostname, HostStatusEvent
from inventory.services.nmap_parser import parse_nmap_xml
from inventory.services.telegram import send_telegram, escape_telegram_html, inline_keyboard_setname
from inventory.views import format_duration

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Scan hosts for services using nmap service scan'

    def add_arguments(self, parser):
        parser.add_argument(
            '--targets',
            type=str,
            default='from_db',
            help='Targets to scan: "from_db" (use IPs from database) or CIDR/IP list',
        )
        parser.add_argument(
            '--top-ports',
            type=int,
            default=200,
            help='Number of top ports to scan',
        )
        parser.add_argument(
            '--version-detect',
            action='store_true',
            help='Enable version detection',
        )
        parser.add_argument(
            '--skip-telegram',
            action='store_true',
            help='Skip Telegram notifications',
        )

    def handle(self, *args, **options):
        # Record task execution
        task_exec = TaskExecution.record_start('scan_services')
        
        targets = options['targets']
        top_ports = options['top_ports']
        version_detect = options['version_detect']
        skip_telegram = options['skip_telegram']
        
        # Determine targets
        if targets == 'from_db':
            # Get online IPs from database
            from inventory.models import IPAddress
            ip_addresses = IPAddress.objects.filter(
                online=True
            ).values_list('ip', flat=True).distinct()
            if not ip_addresses:
                self.stdout.write(self.style.WARNING("No online IPs found in database"))
                return
            target_list = list(ip_addresses)
        else:
            target_list = [targets]
        
        self.stdout.write(f"Scanning {len(target_list)} target(s) for services...")
        self.stdout.write(f"Targets: {', '.join(target_list[:5])}{'...' if len(target_list) > 5 else ''}")
        self.stdout.write("Starting nmap scan (this may take several minutes)...")
        self.stdout.flush()
        
        # Build nmap command with progress output
        # We'll run nmap twice: once for progress, once for XML
        # Or use a single command that outputs both
        
        # First, show which targets we're scanning
        self.stdout.write(f"Target IPs to scan: {len(target_list)}")
        for i, target in enumerate(target_list[:10], 1):
            self.stdout.write(f"  {i}. {target}")
        if len(target_list) > 10:
            self.stdout.write(f"  ... and {len(target_list) - 10} more")
        self.stdout.write("")
        self.stdout.flush()
        
        # Build nmap command
        cmd = [
            'nmap',
            '-sV',  # Version detection
            f'--top-ports', str(top_ports),
            '-oX', '-',  # XML output to stdout
            '--stats-every', '5s',  # Show progress every 5 seconds (goes to stderr)
        ]
        
        if version_detect:
            cmd.append('--version-intensity=5')
        
        cmd.extend(target_list)
        
        # Run nmap scan with real-time output
        try:
            import threading
            import queue
            
            output_queue = queue.Queue()
            error_queue = queue.Queue()
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            def read_stdout():
                for line in iter(process.stdout.readline, ''):
                    if line:
                        output_queue.put(line)
                output_queue.put(None)  # Sentinel
            
            def read_stderr():
                for line in iter(process.stderr.readline, ''):
                    if line:
                        error_queue.put(line)
                error_queue.put(None)  # Sentinel
            
            # Start threads to read stdout and stderr
            stdout_thread = threading.Thread(target=read_stdout, daemon=True)
            stderr_thread = threading.Thread(target=read_stderr, daemon=True)
            stdout_thread.start()
            stderr_thread.start()
            
            # Process output in real-time
            output_lines = []
            targets_scanned = 0
            
            self.stdout.write("")
            self.stdout.write("=" * 60)
            self.stdout.write("Starting nmap scan...")
            self.stdout.write(f"Scanning {len(target_list)} target(s) with top {top_ports} ports")
            self.stdout.write("Estimated time: 10-30 minutes (depends on number of targets)")
            self.stdout.write("=" * 60)
            self.stdout.write("")
            self.stdout.flush()
            
            # Show periodic updates
            last_update = time.time()
            update_interval = 30  # Update every 30 seconds
            start_time = time.time()
            
            while True:
                # Show periodic status updates
                current_time = time.time()
                elapsed_total = int(current_time - start_time)
                if current_time - last_update >= update_interval:
                    self.stdout.write(f"[Status] Still scanning... ({elapsed_total}s elapsed, {targets_scanned}/{len(target_list)} targets)")
                    self.stdout.flush()
                    last_update = current_time
                
                # Check stderr for progress
                try:
                    stderr_line = error_queue.get(timeout=0.5)
                    if stderr_line is None:
                        break
                    stderr_line = stderr_line.strip()
                    if stderr_line:
                        # Show progress messages
                        if 'Stats:' in stderr_line or 'elapsed' in stderr_line.lower():
                            self.stdout.write(f"[Progress] {stderr_line}")
                            self.stdout.flush()
                            last_update = current_time  # Reset timer on progress update
                        elif 'Scanning' in stderr_line:
                            self.stdout.write(f"[Scanning] {stderr_line}")
                            self.stdout.flush()
                            targets_scanned += 1
                            last_update = current_time
                except queue.Empty:
                    pass
                
                # Check stdout for XML data
                try:
                    stdout_line = output_queue.get(timeout=0.1)
                    if stdout_line is None:
                        break
                    output_lines.append(stdout_line)
                except queue.Empty:
                    pass
                
                # Check if process is done
                if process.poll() is not None:
                    # Process remaining output
                    while True:
                        try:
                            stdout_line = output_queue.get_nowait()
                            if stdout_line is None:
                                break
                            output_lines.append(stdout_line)
                        except queue.Empty:
                            break
                    
                    while True:
                        try:
                            stderr_line = error_queue.get_nowait()
                            if stderr_line is None:
                                break
                            if stderr_line.strip():
                                self.stdout.write(f"[Info] {stderr_line.strip()}")
                                self.stdout.flush()
                        except queue.Empty:
                            break
                    break
            
            # Wait for threads to finish reading
            stdout_thread.join(timeout=5)
            stderr_thread.join(timeout=5)
            
            # Wait for process to complete
            process.wait()
            
            if process.returncode != 0:
                error_msg = f"Nmap service scan failed with exit code {process.returncode}"
                logger.error(error_msg)
                Alert.objects.create(type='error', message=error_msg)
                self.stdout.write(self.style.ERROR(error_msg))
                return
            
            # Get remaining output
            while True:
                try:
                    stdout_line = output_queue.get_nowait()
                    if stdout_line is None:
                        break
                    output_lines.append(stdout_line)
                except queue.Empty:
                    break
            
            xml_output = ''.join(output_lines)
            
            # Ensure XML is complete
            if not xml_output.strip().endswith('</nmaprun>'):
                # Try to fix incomplete XML
                if '</nmaprun>' in xml_output:
                    # XML is there but might have extra content
                    xml_output = xml_output[:xml_output.rfind('</nmaprun>') + 9]
                elif '<nmaprun' in xml_output:
                    # XML started but didn't finish - try to close it
                    last_host = xml_output.rfind('</host>')
                    if last_host > 0:
                        xml_output = xml_output[:last_host + 7] + '\n</nmaprun>'
                    else:
                        self.stdout.write(self.style.WARNING("XML output appears incomplete, attempting to parse anyway..."))
            
            self.stdout.write(f"Scan completed. Found XML output ({len(xml_output)} bytes)")
            self.stdout.write("Parsing results...")
            self.stdout.flush()
            
        except subprocess.TimeoutExpired:
            process.kill()
            error_msg = "Nmap service scan timed out"
            logger.error(error_msg)
            Alert.objects.create(type='error', message=error_msg)
            self.stdout.write(self.style.ERROR(error_msg))
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
        
        # Old code using subprocess.run (commented out for reference)
        # try:
        #     result = subprocess.run(
        #         cmd,
        #         capture_output=True,
        #         text=True,
        #         timeout=1800,  # 30 minute timeout
        #     )
            
        except subprocess.TimeoutExpired:
            error_msg = "Nmap service scan timed out"
            logger.error(error_msg)
            Alert.objects.create(type='error', message=error_msg)
            self.stdout.write(self.style.ERROR(error_msg))
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
        self.stdout.write("Parsing nmap XML output...")
        self.stdout.flush()
        parsed = parse_nmap_xml(xml_output)
        hosts_data = parsed.get('hosts', [])
        
        self.stdout.write(f"Found {len(hosts_data)} host(s) with services")
        self.stdout.flush()
        
        new_services_count = 0
        processed_hosts = 0
        
        for host_data in hosts_data:
            processed_hosts += 1
            ip = host_data.get('ip')
            if not ip:
                continue
            
            self.stdout.write(f"Processing host {processed_hosts}/{len(hosts_data)}: {ip}")
            self.stdout.flush()
            ip = host_data.get('ip')
            if not ip:
                continue
            
            # Find host by IP
            from inventory.models import IPAddress
            try:
                ip_obj = IPAddress.objects.get(ip=ip)
                host = ip_obj.host
            except IPAddress.DoesNotExist:
                self.stdout.write(self.style.WARNING(f"IP {ip} not in database, skipping"))
                continue
            
            if not host:
                self.stdout.write(self.style.WARNING(f"No host for IP {ip}, skipping"))
                continue
            
            # Update host status based on nmap results
            old_is_active = host.is_active
            host_status = host_data.get('status', 'down')
            services = host_data.get('services', [])
            open_services = [s for s in services if s.get('state') in ['open', 'open|filtered']]
            # Host is active if it's up OR has open ports
            host.is_active = (host_status == 'up' or len(open_services) > 0)
            host.last_seen = timezone.now()
            host.save()
            
            if not host.is_active:
                self.stdout.write(self.style.WARNING(f"Host {host.name} ({ip}) detected as DOWN - marked as inactive"))
            
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
                HostStatusEvent.record(host, host.is_active)

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
            
            # Process services
            for service_data in host_data.get('services', []):
                port = service_data.get('port')
                proto = service_data.get('proto', 'tcp')
                
                service, created = Service.objects.get_or_create(
                    host=host,
                    port=port,
                    proto=proto,
                    defaults={
                        'name': service_data.get('name', ''),
                        'product': service_data.get('product', ''),
                        'version': service_data.get('version', ''),
                        'extra_info': service_data.get('extra_info', ''),
                    }
                )
                
                if created:
                    new_services_count += 1
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"New service: {host.name}:{port}/{proto} ({service_data.get('name', 'unknown')})"
                        )
                    )
                    
                    # Create alert
                    Alert.objects.create(
                        type='new_service',
                        message=f"New service detected: {host.name}:{port}/{proto} ({service_data.get('name', 'unknown')})",
                        related_host=host,
                    )
                    
                    # Send Telegram notification (if enabled)
                    if not skip_telegram and should_notify_new_service():
                        first_ip = host.ip_addresses.order_by('-last_seen').first()
                        ip_for_btn = first_ip.ip if first_ip else None
                        reply_markup = inline_keyboard_setname(ip_for_btn) if ip_for_btn else None
                        send_telegram(
                            f"🔌 <b>New Service Detected</b>\n"
                            f"Host: <code>{escape_telegram_html(host.name)}</code>\n"
                            f"Service: <code>{port}/{proto}</code> ({escape_telegram_html(str(service_data.get('name', 'unknown')))})\n"
                            f"Product: {escape_telegram_html(str(service_data.get('product', 'N/A')))}",
                            reply_markup=reply_markup,
                        )
                else:
                    # Update existing service
                    service.name = service_data.get('name', service.name)
                    service.product = service_data.get('product', service.product)
                    service.version = service_data.get('version', service.version)
                    service.extra_info = service_data.get('extra_info', service.extra_info)
                    service.last_seen = timezone.now()
                    service.save()
        
        self.stdout.write(
            self.style.SUCCESS(
                f"Service scan complete. Found {new_services_count} new services."
            )
        )
        
        # Build readable output summary (host -> ports) for TaskExecution and Telegram
        output_lines = []
        for host_data in hosts_data:
            ip = host_data.get('ip')
            if not ip:
                continue
            svcs = host_data.get('services', [])
            open_svcs = [s for s in svcs if s.get('state') in ('open', 'open|filtered')]
            if not open_svcs:
                output_lines.append(f"{ip}: (no open ports)")
                continue
            parts = [f"{s.get('port')}/{s.get('proto', 'tcp')} ({s.get('name', 'unknown')})" for s in open_svcs]
            output_lines.append(f"{ip}: " + ", ".join(parts))
        output_text = "\n".join(output_lines) if output_lines else f"Found {new_services_count} new services from {len(hosts_data)} hosts"
        task_exec.record_success(items_processed=len(hosts_data), output=output_text)
        
        # Create alert with results
        duration = task_exec.completed_at - task_exec.started_at if task_exec.completed_at else None
        if duration:
            total_seconds = duration.total_seconds()
            duration_str = format_duration(total_seconds)
        else:
            duration_str = 'N/A'
        Alert.objects.create(
            type=AlertType.TASK_COMPLETED,
            message=f"Service scan completed: {new_services_count} new services found from {len(hosts_data)} hosts",
            details=f"Task: Service Scan\nStatus: Success\nHosts scanned: {len(hosts_data)}\nNew services: {new_services_count}\nDuration: {duration_str}\n\nOutput:\n{task_exec.output}",
        )