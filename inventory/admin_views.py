"""
Custom admin views - Completely new admin system from scratch.
No Django admin, completely custom implementation.
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.contrib.auth.models import User
from django.db.models import Q
from django.core.paginator import Paginator
from django.utils import timezone
from .models import (
    Host, IPAddress, Service, Alert, Hostname,
    SystemConfig, IntegrationConfig, TaskExecution,
    AlertType, HostSource
)
from .admin_forms import (
    TelegramIntegrationForm, ProxmoxIntegrationForm, AdGuardIntegrationForm
)
from .config_manager import ConfigManager
from .services.telegram import send_telegram
from .services.proxmox_client import get_proxmox_client
from .services.adguard_client import get_adguard_client
import logging

logger = logging.getLogger(__name__)


def is_staff(user):
    """Check if user is staff."""
    return user.is_staff


@login_required
@user_passes_test(is_staff)
def admin_dashboard(request):
    """Main admin dashboard."""
    context = {
        'alerts_count': Alert.objects.count(),
        'hosts_count': Host.objects.count(),
        'active_hosts_count': Host.objects.filter(is_active=True).count(),
        'integrations_count': IntegrationConfig.objects.count(),
        'enabled_integrations_count': IntegrationConfig.objects.filter(enabled=True).count(),
        'task_executions_count': TaskExecution.objects.count(),
        'users_count': User.objects.count(),
        'recent_alerts': Alert.objects.all()[:5],
        'recent_tasks': TaskExecution.objects.all()[:5],
    }
    return render(request, 'admin_panel/dashboard.html', context)


@login_required
@user_passes_test(is_staff)
def admin_alerts(request):
    """Alerts management."""
    search = request.GET.get('search', '')
    type_filter = request.GET.get('type', '')
    
    alerts = Alert.objects.all()
    
    if search:
        alerts = alerts.filter(
            Q(message__icontains=search) |
            Q(related_host__name__icontains=search) |
            Q(related_ip__ip__icontains=search)
        )
    
    if type_filter:
        alerts = alerts.filter(type=type_filter)
    
    alerts = alerts.order_by('-created_at')
    
    paginator = Paginator(alerts, 25)
    page = request.GET.get('page', 1)
    alerts_page = paginator.get_page(page)
    
    context = {
        'alerts': alerts_page,
        'search': search,
        'type_filter': type_filter,
        'alert_types': AlertType.choices,
    }
    return render(request, 'admin_panel/alerts.html', context)


@login_required
@user_passes_test(is_staff)
def admin_alerts_delete(request, alert_id):
    """Delete an alert."""
    alert = get_object_or_404(Alert, id=alert_id)
    alert.delete()
    messages.success(request, f'Alert "{alert.message[:50]}..." deleted successfully.')
    return redirect('admin_alerts')


@login_required
@user_passes_test(is_staff)
def admin_alerts_delete_all(request):
    """Delete all alerts."""
    if request.method == 'POST':
        count = Alert.objects.count()
        Alert.objects.all().delete()
        messages.success(request, f'All {count} alerts deleted successfully.')
        return redirect('admin_alerts')


@login_required
@user_passes_test(is_staff)
def admin_hosts(request):
    """Hosts management."""
    search = request.GET.get('search', '')
    status_filter = request.GET.get('status', '')
    source_filter = request.GET.get('source', '')
    
    hosts = Host.objects.all()
    
    if search:
        hosts = hosts.filter(
            Q(name__icontains=search) |
            Q(mac__icontains=search) |
            Q(vendor__icontains=search)
        )
    
    if status_filter == 'active':
        hosts = hosts.filter(is_active=True)
    elif status_filter == 'inactive':
        hosts = hosts.filter(is_active=False)
    
    if source_filter:
        hosts = hosts.filter(source=source_filter)
    
    hosts = hosts.order_by('-last_seen')
    
    paginator = Paginator(hosts, 25)
    page = request.GET.get('page', 1)
    hosts_page = paginator.get_page(page)
    
    context = {
        'hosts': hosts_page,
        'search': search,
        'status_filter': status_filter,
        'source_filter': source_filter,
        'source_choices': HostSource.choices,
    }
    return render(request, 'admin_panel/hosts.html', context)


@login_required
@user_passes_test(is_staff)
def admin_host_detail(request, host_id):
    """Host detail view with IPs, services, and hostnames - editable."""
    host = get_object_or_404(Host, id=host_id)
    
    if request.method == 'POST':
        # Update host basic info
        host.name = request.POST.get('name', host.name).strip()
        host.mac = request.POST.get('mac', host.mac) or None
        host.vendor = request.POST.get('vendor', host.vendor) or None
        host.device_type = request.POST.get('device_type', host.device_type) or None
        host.is_active = request.POST.get('is_active') == 'on'
        host.notes = request.POST.get('notes', '')
        host.save()
        
        # Handle IP deletions
        for key in request.POST.keys():
            if key.startswith('delete_ip_'):
                ip_id = key.replace('delete_ip_', '')
                try:
                    IPAddress.objects.filter(id=ip_id, host=host).delete()
                except:
                    pass
        
        # Handle Service deletions
        for key in request.POST.keys():
            if key.startswith('delete_service_'):
                service_id = key.replace('delete_service_', '')
                try:
                    Service.objects.filter(id=service_id, host=host).delete()
                except:
                    pass
        
        # Handle Hostname deletions
        for key in request.POST.keys():
            if key.startswith('delete_hostname_'):
                hostname_id = key.replace('delete_hostname_', '')
                try:
                    Hostname.objects.filter(id=hostname_id, host=host).delete()
                except:
                    pass
        
        # Add new IP
        new_ip = request.POST.get('new_ip', '').strip()
        if new_ip:
            try:
                ip_obj, created = IPAddress.objects.get_or_create(
                    ip=new_ip,
                    defaults={'host': host, 'assignment': 'static', 'online': True}
                )
                # If IP already exists but belongs to different host, update it
                if not created and ip_obj.host != host:
                    ip_obj.host = host
                    ip_obj.save()
            except Exception as e:
                logger.error(f"Error adding IP {new_ip}: {e}")
                messages.error(request, f'Error adding IP {new_ip}: {str(e)}')
        
        # Add new Service
        new_service_port = request.POST.get('new_service_port', '').strip()
        new_service_proto = request.POST.get('new_service_proto', 'tcp')
        new_service_name = request.POST.get('new_service_name', '').strip()
        if new_service_port:
            try:
                Service.objects.get_or_create(
                    host=host,
                    port=int(new_service_port),
                    proto=new_service_proto,
                    defaults={'name': new_service_name}
                )
            except Exception as e:
                logger.error(f"Error adding service {new_service_port}/{new_service_proto}: {e}")
                messages.error(request, f'Error adding service: {str(e)}')
        
        # Add new Hostname
        new_hostname = request.POST.get('new_hostname', '').strip()
        if new_hostname:
            try:
                Hostname.objects.get_or_create(
                    host=host,
                    name=new_hostname,
                    defaults={'source_type': 'user'}
                )
            except Exception as e:
                logger.error(f"Error adding hostname {new_hostname}: {e}")
                messages.error(request, f'Error adding hostname: {str(e)}')
        
        messages.success(request, f'Host "{host.name}" updated successfully.')
        return redirect('admin_host_detail', host_id=host.id)
    
    ips = IPAddress.objects.filter(host=host).order_by('-last_seen')
    services = Service.objects.filter(host=host).order_by('-last_seen')
    hostnames = Hostname.objects.filter(host=host).order_by('-last_seen')
    
    # Device types list
    device_types_list = [
        ('unknown', 'Unknown'),
        ('server', 'Server'),
        ('laptop', 'Laptop'),
        ('desktop', 'Desktop'),
        ('phone', 'Phone'),
        ('tablet', 'Tablet'),
        ('console', 'Console'),
        ('router', 'Router'),
        ('switch', 'Switch'),
        ('iot', 'IoT'),
        ('qemu', 'QEMU'),
        ('lxc', 'LXC'),
    ]
    
    context = {
        'host': host,
        'ips': ips,
        'services': services,
        'hostnames': hostnames,
        'device_types': device_types_list,
    }
    return render(request, 'admin_panel/host_detail.html', context)


@login_required
@user_passes_test(is_staff)
def admin_host_edit(request, host_id):
    """Edit host."""
    host = get_object_or_404(Host, id=host_id)
    
    if request.method == 'POST':
        host.name = request.POST.get('name', host.name)
        host.mac = request.POST.get('mac', host.mac) or None
        host.vendor = request.POST.get('vendor', host.vendor) or None
        host.device_type = request.POST.get('device_type', host.device_type) or None
        host.is_active = request.POST.get('is_active') == 'on'
        host.notes = request.POST.get('notes', '')
        host.save()
        messages.success(request, f'Host "{host.name}" updated successfully.')
        return redirect('admin_host_detail', host_id=host.id)
    
    # Device types list (not a TextChoices, just a CharField)
    device_types_list = [
        ('unknown', 'Unknown'),
        ('server', 'Server'),
        ('laptop', 'Laptop'),
        ('desktop', 'Desktop'),
        ('phone', 'Phone'),
        ('tablet', 'Tablet'),
        ('console', 'Console'),
        ('router', 'Router'),
        ('switch', 'Switch'),
        ('iot', 'IoT'),
        ('qemu', 'QEMU'),
        ('lxc', 'LXC'),
    ]
    
    context = {
        'host': host,
        'device_types': device_types_list,
    }
    return render(request, 'admin_panel/host_edit.html', context)


@login_required
@user_passes_test(is_staff)
def admin_integrations(request):
    """Integrations management."""
    integrations = IntegrationConfig.objects.all().order_by('name')
    context = {
        'integrations': integrations,
    }
    return render(request, 'admin_panel/integrations.html', context)


@login_required
@user_passes_test(is_staff)
def admin_integration_detail(request, integration_id):
    """Integration detail and configuration."""
    integration = get_object_or_404(IntegrationConfig, id=integration_id)
    
    # Get appropriate form based on integration type
    form_class = None
    if integration.name == 'telegram':
        form_class = TelegramIntegrationForm
    elif integration.name == 'proxmox':
        form_class = ProxmoxIntegrationForm
    elif integration.name == 'adguard':
        form_class = AdGuardIntegrationForm
    
    if request.method == 'POST':
        if form_class:
            form = form_class(request.POST, instance=integration)
            if form.is_valid():
                form.save()
                messages.success(request, f'{integration.get_name_display()} configuration saved successfully.')
                return redirect('admin_integration_detail', integration_id=integration.id)
        else:
            integration.enabled = request.POST.get('enabled') == 'on'
            integration.save()
            messages.success(request, f'{integration.get_name_display()} updated successfully.')
            return redirect('admin_integration_detail', integration_id=integration.id)
    else:
        form = form_class(instance=integration) if form_class else None
    
    # Test connection
    test_result = None
    test_message = None
    if request.GET.get('test') == '1':
        test_result, test_message = _test_integration(integration)
        integration.last_test = timezone.now()
        integration.last_test_result = test_result
        integration.last_test_message = test_message
        integration.save()
    
    context = {
        'integration': integration,
        'form': form,
        'test_result': test_result,
        'test_message': test_message,
    }
    return render(request, 'admin_panel/integration_detail.html', context)


def _test_integration(integration):
    """Test integration connection."""
    if integration.name == 'telegram':
        bot_token = integration.get_config('bot_token', '')
        chat_id = integration.get_config('chat_id', '')
        if not bot_token or not chat_id:
            return False, "Bot token or chat ID not configured"
        try:
            import requests
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                'chat_id': chat_id,
                'text': "🧪 BANKAI Integration Test - Connection successful!",
                'parse_mode': 'HTML',
            }
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            return True, "Telegram notification sent successfully"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    elif integration.name == 'proxmox':
        url = integration.get_config('url', '')
        token_id = integration.get_config('token_id', '')
        token_secret = integration.get_config('token_secret', '')
        if not all([url, token_id, token_secret]):
            return False, "Proxmox credentials not fully configured"
        try:
            client = get_proxmox_client(integration=integration)
            if client:
                nodes = client.nodes.get()
                return True, f"Connected successfully. Found {len(nodes)} node(s)"
            return False, "Failed to create Proxmox client"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
    
    elif integration.name == 'adguard':
        url = integration.get_config('url', '')
        username = integration.get_config('username', '')
        password = integration.get_config('password', '')
        if not all([url, username, password]):
            return False, "AdGuard Home credentials not fully configured"
        try:
            session = get_adguard_client(integration=integration)
            if session:
                adguard_url = url.rstrip('/')
                response = session.get(f"{adguard_url}/control/status", timeout=10)
                if response.status_code == 200:
                    status = response.json()
                    version = status.get('version', 'unknown')
                    dns_enabled = status.get('dns_enabled', False)
                    return True, f"Connected successfully. Version: {version}, DNS enabled: {dns_enabled}"
                elif response.status_code == 401:
                    return False, "Authentication failed: Invalid username or password"
                else:
                    error_msg = response.text[:200] if response.text else "Unknown error"
                    return False, f"Connection failed: HTTP {response.status_code} - {error_msg}"
            return False, "Failed to create AdGuard Home client"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    return False, "Unknown integration type"


@login_required
@user_passes_test(is_staff)
def admin_configurations(request):
    """System configurations management."""
    from .admin_forms import SchedulerConfigForm
    from .config_manager import (
        get_discovery_interval,
        get_service_scan_interval,
        get_proxmox_sync_interval,
        get_adguard_sync_interval,
        ConfigManager,
    )
    
    # Handle scheduler form submission
    scheduler_form = None
    if request.method == 'POST' and 'scheduler_submit' in request.POST:
        scheduler_form = SchedulerConfigForm(request.POST)
        if scheduler_form.is_valid():
            # Save intervals (convert minutes to seconds for internal storage)
            ConfigManager.set('DISCOVERY_INTERVAL', str(scheduler_form.cleaned_data['discovery_interval'] * 60))
            ConfigManager.set('SERVICE_SCAN_INTERVAL', str(scheduler_form.cleaned_data['service_scan_interval']))
            ConfigManager.set('PROXMOX_SYNC_INTERVAL', str(scheduler_form.cleaned_data['proxmox_sync_interval']))
            ConfigManager.set('ADGUARD_SYNC_INTERVAL', str(scheduler_form.cleaned_data['adguard_sync_interval']))
            
            # Save scheduler start time and delays
            ConfigManager.set('SCHEDULER_START_HOUR', str(scheduler_form.cleaned_data['scheduler_start_hour']))
            ConfigManager.set('SCHEDULER_START_MINUTE', str(scheduler_form.cleaned_data['scheduler_start_minute']))
            ConfigManager.set('SCHEDULER_DISCOVERY_DELAY', str(scheduler_form.cleaned_data['discovery_delay']))
            ConfigManager.set('SCHEDULER_SERVICE_DELAY', str(scheduler_form.cleaned_data['service_delay']))
            ConfigManager.set('SCHEDULER_PROXMOX_DELAY', str(scheduler_form.cleaned_data['proxmox_delay']))
            ConfigManager.set('SCHEDULER_ADGUARD_DELAY', str(scheduler_form.cleaned_data['adguard_delay']))
            
            messages.success(request, "Scheduler configuration saved successfully!")
            return redirect('admin_configurations')
    
    configs = SystemConfig.objects.all().order_by('key')
    
    # Friendly names mapping
    friendly_names = {
        'DISCOVERY_CIDR': 'Network Range (CIDR)',
        'DISCOVERY_INTERVAL': 'Discovery Scan Interval (minutes)',
        'SERVICE_SCAN_INTERVAL': 'Service Scan Interval (minutes)',
        'PROXMOX_SYNC_INTERVAL': 'Proxmox Sync Interval (minutes)',
        'ADGUARD_SYNC_INTERVAL': 'AdGuard Home Sync Interval (minutes)',
        'NOTIFY_NEW_SERVICE': 'Notify New Services via Telegram',
        'SCHEDULER_START_HOUR': 'Scheduler Start Hour',
        'SCHEDULER_START_MINUTE': 'Scheduler Start Minute',
        'SCHEDULER_DISCOVERY_DELAY': 'Discovery Delay (minutes)',
        'SCHEDULER_SERVICE_DELAY': 'Service Scan Delay (minutes)',
        'SCHEDULER_PROXMOX_DELAY': 'Proxmox Sync Delay (minutes)',
        'SCHEDULER_ADGUARD_DELAY': 'AdGuard Sync Delay (minutes)',
    }
    
    # Convert interval values from seconds to minutes for display
    interval_keys = ['DISCOVERY_INTERVAL', 'SERVICE_SCAN_INTERVAL', 'PROXMOX_SYNC_INTERVAL', 'ADGUARD_SYNC_INTERVAL']
    
    # Group configurations by category
    categories = {
        'Network': [],
        'Intervals': [],
        'Notifications': [],
        'Scheduler': [],
        'Other': [],
    }
    
    for config in configs:
        key = config.key
        # Convert interval values to minutes for display
        if key in interval_keys:
            try:
                value_seconds = int(config.value)
                config.display_value = str(value_seconds // 60) if value_seconds >= 60 else str(value_seconds)
                config.is_minutes = True
            except:
                config.display_value = config.value
                config.is_minutes = False
        else:
            config.display_value = config.value
            config.is_minutes = False
        
        config.friendly_name = friendly_names.get(key, key)
        
        if 'CIDR' in key or 'NETWORK' in key:
            categories['Network'].append(config)
        elif 'INTERVAL' in key:
            categories['Intervals'].append(config)
        elif 'NOTIFY' in key or 'TELEGRAM' in key:
            categories['Notifications'].append(config)
        elif 'SCHEDULER' in key:
            categories['Scheduler'].append(config)
        else:
            categories['Other'].append(config)
    
    # Initialize scheduler form with current values
    if scheduler_form is None:
        initial = {
            'discovery_interval': get_discovery_interval() // 60,
            'service_scan_interval': get_service_scan_interval(),
            'proxmox_sync_interval': get_proxmox_sync_interval(),
            'adguard_sync_interval': get_adguard_sync_interval(),
            'scheduler_start_hour': ConfigManager.get_int('SCHEDULER_START_HOUR', 0),
            'scheduler_start_minute': ConfigManager.get_int('SCHEDULER_START_MINUTE', 0),
            'discovery_delay': ConfigManager.get_int('SCHEDULER_DISCOVERY_DELAY', 0),
            'service_delay': ConfigManager.get_int('SCHEDULER_SERVICE_DELAY', 20),
            'proxmox_delay': ConfigManager.get_int('SCHEDULER_PROXMOX_DELAY', 40),
            'adguard_delay': ConfigManager.get_int('SCHEDULER_ADGUARD_DELAY', 50),
        }
        scheduler_form = SchedulerConfigForm(initial=initial)
    
    context = {
        'categories': categories,
        'scheduler_form': scheduler_form,
    }
    return render(request, 'admin_panel/configurations.html', context)


@login_required
@user_passes_test(is_staff)
def admin_configuration_edit(request, config_id):
    """Edit a configuration."""
    config = get_object_or_404(SystemConfig, id=config_id)
    
    # Friendly names
    friendly_names = {
        'DISCOVERY_CIDR': 'Network Range (CIDR)',
        'DISCOVERY_INTERVAL': 'Discovery Scan Interval (minutes)',
        'SERVICE_SCAN_INTERVAL': 'Service Scan Interval (minutes)',
        'PROXMOX_SYNC_INTERVAL': 'Proxmox Sync Interval (minutes)',
        'ADGUARD_SYNC_INTERVAL': 'AdGuard Home Sync Interval (minutes)',
        'NOTIFY_NEW_SERVICE': 'Notify New Services via Telegram',
        'SCHEDULER_START_HOUR': 'Scheduler Start Hour',
        'SCHEDULER_START_MINUTE': 'Scheduler Start Minute',
        'SCHEDULER_DISCOVERY_DELAY': 'Discovery Delay (minutes)',
        'SCHEDULER_SERVICE_DELAY': 'Service Scan Delay (minutes)',
        'SCHEDULER_PROXMOX_DELAY': 'Proxmox Sync Delay (minutes)',
        'SCHEDULER_ADGUARD_DELAY': 'AdGuard Sync Delay (minutes)',
    }
    
    # Interval keys that need conversion
    interval_keys = ['DISCOVERY_INTERVAL', 'SERVICE_SCAN_INTERVAL', 'PROXMOX_SYNC_INTERVAL', 'ADGUARD_SYNC_INTERVAL']
    
    if request.method == 'POST':
        value = request.POST.get('value', '')
        # Convert minutes to seconds for interval keys
        if config.key in interval_keys:
            try:
                value_minutes = int(value)
                value = str(value_minutes * 60)  # Convert to seconds for storage
            except:
                pass
        
        config.value = value
        if request.POST.get('description'):
            config.description = request.POST.get('description')
        config.save()
        messages.success(request, f'Configuration "{friendly_names.get(config.key, config.key)}" updated successfully.')
        return redirect('admin_configurations')
    
    # Convert seconds to minutes for display
    display_value = config.value
    if config.key in interval_keys:
        try:
            value_seconds = int(config.value)
            display_value = str(value_seconds // 60) if value_seconds >= 60 else str(value_seconds)
        except:
            pass
    
    context = {
        'config': config,
        'friendly_name': friendly_names.get(config.key, config.key),
        'display_value': display_value,
        'is_interval': config.key in interval_keys,
    }
    return render(request, 'admin_panel/configuration_edit.html', context)


@login_required
@user_passes_test(is_staff)
def admin_scheduler_config(request):
    """Scheduler configuration."""
    from .admin_forms import SchedulerConfigForm
    from .config_manager import (
        get_discovery_interval,
        get_service_scan_interval,
        get_proxmox_sync_interval,
        get_adguard_sync_interval,
    )
    
    if request.method == 'POST':
        form = SchedulerConfigForm(request.POST)
        if form.is_valid():
            # Save intervals (convert minutes to seconds for internal storage)
            ConfigManager.set('DISCOVERY_INTERVAL', str(form.cleaned_data['discovery_interval']))
            ConfigManager.set('SERVICE_SCAN_INTERVAL', str(form.cleaned_data['service_scan_interval']))
            ConfigManager.set('PROXMOX_SYNC_INTERVAL', str(form.cleaned_data['proxmox_sync_interval']))
            ConfigManager.set('ADGUARD_SYNC_INTERVAL', str(form.cleaned_data['adguard_sync_interval']))
            
            # Save scheduler start time and delays
            ConfigManager.set('SCHEDULER_START_HOUR', str(form.cleaned_data['scheduler_start_hour']))
            ConfigManager.set('SCHEDULER_START_MINUTE', str(form.cleaned_data['scheduler_start_minute']))
            ConfigManager.set('SCHEDULER_DISCOVERY_DELAY', str(form.cleaned_data['discovery_delay']))
            ConfigManager.set('SCHEDULER_SERVICE_DELAY', str(form.cleaned_data['service_delay']))
            ConfigManager.set('SCHEDULER_PROXMOX_DELAY', str(form.cleaned_data['proxmox_delay']))
            ConfigManager.set('SCHEDULER_ADGUARD_DELAY', str(form.cleaned_data['adguard_delay']))
            
            messages.success(request, "Scheduler configuration saved successfully!")
            return redirect('admin_scheduler_config')
    else:
        # Load current values
        initial = {
            'discovery_interval': get_discovery_interval(),
            'service_scan_interval': get_service_scan_interval(),
            'proxmox_sync_interval': get_proxmox_sync_interval(),
            'adguard_sync_interval': get_adguard_sync_interval(),
            'scheduler_start_hour': ConfigManager.get_int('SCHEDULER_START_HOUR', 0),
            'scheduler_start_minute': ConfigManager.get_int('SCHEDULER_START_MINUTE', 0),
            'discovery_delay': ConfigManager.get_int('SCHEDULER_DISCOVERY_DELAY', 0),
            'service_delay': ConfigManager.get_int('SCHEDULER_SERVICE_DELAY', 20),
            'proxmox_delay': ConfigManager.get_int('SCHEDULER_PROXMOX_DELAY', 40),
            'adguard_delay': ConfigManager.get_int('SCHEDULER_ADGUARD_DELAY', 50),
        }
        form = SchedulerConfigForm(initial=initial)
    
    context = {
        'form': form,
    }
    return render(request, 'admin_panel/scheduler_config.html', context)


@login_required
@user_passes_test(is_staff)
def admin_task_executions(request):
    """Task executions management."""
    search = request.GET.get('search', '')
    task_filter = request.GET.get('task', '')
    status_filter = request.GET.get('status', '')
    
    # Handle task deletion
    if request.method == 'POST' and 'delete_task' in request.POST:
        task_id = request.POST.get('delete_task')
        try:
            task = TaskExecution.objects.get(id=task_id)
            task.delete()
            messages.success(request, 'Task execution deleted successfully.')
            return redirect('admin_task_executions')
        except TaskExecution.DoesNotExist:
            messages.error(request, 'Task execution not found.')
    
    tasks = TaskExecution.objects.all()
    
    if search:
        tasks = tasks.filter(
            Q(output__icontains=search) |
            Q(error_message__icontains=search)
        )
    
    if task_filter:
        tasks = tasks.filter(task_name=task_filter)
    
    if status_filter:
        tasks = tasks.filter(status=status_filter)
    
    tasks = tasks.order_by('-started_at')
    
    paginator = Paginator(tasks, 25)
    page = request.GET.get('page', 1)
    tasks_page = paginator.get_page(page)
    
    context = {
        'tasks': tasks_page,
        'search': search,
        'task_filter': task_filter,
        'status_filter': status_filter,
        'task_choices': TaskExecution.TASK_CHOICES,
        'status_choices': [('running', 'Running'), ('success', 'Success'), ('error', 'Error')],
    }
    return render(request, 'admin_panel/task_executions.html', context)


@login_required
@user_passes_test(is_staff)
def admin_task_detail(request, task_id):
    """Task execution detail."""
    task = get_object_or_404(TaskExecution, id=task_id)
    
    if request.method == 'POST' and 'delete' in request.POST:
        task.delete()
        messages.success(request, 'Task execution deleted successfully.')
        return redirect('admin_task_executions')
    
    context = {
        'task': task,
    }
    return render(request, 'admin_panel/task_detail.html', context)


@login_required
@user_passes_test(is_staff)
def admin_users(request):
    """Users management."""
    search = request.GET.get('search', '')
    is_staff_filter = request.GET.get('is_staff', '')
    
    users = User.objects.all()
    
    if search:
        users = users.filter(
            Q(username__icontains=search) |
            Q(email__icontains=search) |
            Q(first_name__icontains=search) |
            Q(last_name__icontains=search)
        )
    
    if is_staff_filter == 'yes':
        users = users.filter(is_staff=True)
    elif is_staff_filter == 'no':
        users = users.filter(is_staff=False)
    
    users = users.order_by('username')
    
    paginator = Paginator(users, 25)
    page = request.GET.get('page', 1)
    users_page = paginator.get_page(page)
    
    context = {
        'users': users_page,
        'search': search,
        'is_staff_filter': is_staff_filter,
    }
    return render(request, 'admin_panel/users.html', context)


@login_required
@user_passes_test(is_staff)
def admin_user_detail(request, user_id):
    """User detail and edit."""
    user = get_object_or_404(User, id=user_id)
    
    if request.method == 'POST':
        user.username = request.POST.get('username', user.username)
        user.email = request.POST.get('email', user.email) or ''
        user.first_name = request.POST.get('first_name', user.first_name) or ''
        user.last_name = request.POST.get('last_name', user.last_name) or ''
        user.is_staff = request.POST.get('is_staff') == 'on'
        user.is_superuser = request.POST.get('is_superuser') == 'on'
        user.is_active = request.POST.get('is_active') == 'on'
        
        new_password = request.POST.get('password', '')
        if new_password:
            user.set_password(new_password)
        
        user.save()
        messages.success(request, f'User "{user.username}" updated successfully.')
        return redirect('user_detail', user_id=user.id)
    
    context = {
        'user_obj': user,
    }
    return render(request, 'admin_panel/user_detail.html', context)


@login_required
@user_passes_test(is_staff)
def admin_user_create(request):
    """Create new user."""
    if request.method == 'POST':
        username = request.POST.get('username', '')
        email = request.POST.get('email', '')
        password = request.POST.get('password', '')
        is_staff = request.POST.get('is_staff') == 'on'
        is_superuser = request.POST.get('is_superuser') == 'on'
        
        if not username or not password:
            messages.error(request, 'Username and password are required.')
            return redirect('user_create')
        
        if User.objects.filter(username=username).exists():
            messages.error(request, f'User "{username}" already exists.')
            return redirect('user_create')
        
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            is_staff=is_staff,
            is_superuser=is_superuser,
        )
        messages.success(request, f'User "{user.username}" created successfully.')
        return redirect('user_detail', user_id=user.id)
    
    return render(request, 'admin_panel/user_create.html')
