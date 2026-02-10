"""
Views for inventory web interface.
"""
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse, StreamingHttpResponse
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count, Q
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Host, IPAddress, Service, Alert, InterfaceAttachment, HostSource, TaskExecution, Hostname, SystemConfig, IntegrationConfig, HostStatusEvent
from .config_manager import get_discovery_interval, get_service_scan_interval, get_proxmox_sync_interval, get_adguard_sync_interval, ConfigManager
import csv
import io
import logging

logger = logging.getLogger(__name__)
import subprocess
import json
import threading
import queue


def is_setup_completed():
    """Check if initial setup wizard has been completed."""
    return SystemConfig.get_value('SETUP_WIZARD_COMPLETED', 'false').lower() == 'true'


def setup_required(view_func):
    """Decorator to redirect to setup wizard if setup is not completed."""
    def wrapper(request, *args, **kwargs):
        # Allow access to setup wizard, login, logout, and admin login
        excluded_paths = ['/setup/', '/login/', '/logout/', '/admin/login/', '/admin/logout/']
        if not is_setup_completed() and request.path not in excluded_paths and not request.path.startswith('/static/') and not request.path.startswith('/media/'):
            return redirect('setup_wizard')
        return view_func(request, *args, **kwargs)
    return wrapper


@login_required
def setup_wizard(request):
    """Setup wizard for initial or recurring configuration (Settings)."""
    if request.method == 'POST':
        # Save system configurations
        SystemConfig.set_value('DISCOVERY_CIDR', request.POST.get('discovery_cidr', '192.168.1.0/24'), 'Network CIDR for discovery scans')
        SystemConfig.set_value('DISCOVERY_INTERVAL', request.POST.get('discovery_interval', '10'), 'Discovery scan interval in minutes')
        # All intervals stored in minutes (same as discovery)
        service_scan_minutes = int(request.POST.get('service_scan_interval', '60'))
        SystemConfig.set_value('SERVICE_SCAN_INTERVAL', str(service_scan_minutes), 'Service scan interval in minutes')
        proxmox_sync_minutes = int(request.POST.get('proxmox_sync_interval', '30'))
        SystemConfig.set_value('PROXMOX_SYNC_INTERVAL', str(proxmox_sync_minutes), 'Proxmox sync interval in minutes')
        adguard_sync_minutes = int(request.POST.get('adguard_sync_interval', '60'))
        SystemConfig.set_value('ADGUARD_SYNC_INTERVAL', str(adguard_sync_minutes), 'AdGuard Home sync interval in minutes')
        notify_checked = request.POST.get('notify_new_service') == 'on'
        SystemConfig.set_value('NOTIFY_NEW_SERVICE', 'True' if notify_checked else 'False', 'Send Telegram notifications for new services')
        
        # Save Telegram integration if provided
        telegram_enabled = request.POST.get('telegram_enabled') == 'on'
        telegram_bot_token = request.POST.get('telegram_bot_token', '').strip()
        telegram_chat_id = request.POST.get('telegram_chat_id', '').strip()
        
        telegram_integration = IntegrationConfig.objects.filter(name='telegram').first()
        if telegram_enabled:
            telegram_integration, _ = IntegrationConfig.objects.get_or_create(
                name='telegram',
                display_name='Default',
                defaults={'enabled': False, 'config_data': {}}
            )
            # Keep existing token/chat_id if user left fields empty (e.g. fields were hidden when unchecked)
            existing_token = telegram_integration.get_config('bot_token', '')
            existing_chat_id = telegram_integration.get_config('chat_id', '')
            bot_token = telegram_bot_token or existing_token
            chat_id = telegram_chat_id or existing_chat_id
            if bot_token and chat_id:
                telegram_integration.enabled = True
                telegram_integration.config_data = {'bot_token': bot_token, 'chat_id': chat_id}
                telegram_integration.save()
        elif telegram_integration:
            telegram_integration.enabled = False
            telegram_integration.save()
        
        # Save AdGuard Home integration if provided
        adguard_enabled = request.POST.get('adguard_enabled') == 'on'
        adguard_url = request.POST.get('adguard_url', '').strip()
        adguard_username = request.POST.get('adguard_username', '').strip()
        adguard_password = request.POST.get('adguard_password', '').strip()
        adguard_integration = IntegrationConfig.objects.filter(name='adguard').first()
        if adguard_enabled and adguard_url and adguard_username and adguard_password:
            adguard_integration, _ = IntegrationConfig.objects.get_or_create(
                name='adguard',
                display_name='Default',
                defaults={'enabled': False, 'config_data': {}}
            )
            existing_url = adguard_integration.get_config('url', '')
            existing_username = adguard_integration.get_config('username', '')
            existing_password = adguard_integration.get_config('password', '')
            url = adguard_url or existing_url
            username = adguard_username or existing_username
            password = adguard_password or existing_password
            if url and username and password:
                adguard_integration.enabled = True
                adguard_integration.config_data = {
                    'url': url,
                    'username': username,
                    'password': password,
                }
                adguard_integration.save()
        elif adguard_integration:
            adguard_integration.enabled = False
            adguard_integration.save()
        
        # Save Proxmox integration if provided
        proxmox_enabled = request.POST.get('proxmox_enabled') == 'on'
        proxmox_url = request.POST.get('proxmox_url', '').strip()
        proxmox_token_id = request.POST.get('proxmox_token_id', '').strip()
        proxmox_token_secret = request.POST.get('proxmox_token_secret', '').strip()
        proxmox_node = request.POST.get('proxmox_node', '').strip()
        
        if proxmox_enabled and proxmox_url and proxmox_token_id and proxmox_token_secret:
            proxmox_integration, _ = IntegrationConfig.objects.get_or_create(
                name='proxmox',
                display_name='Default',
                defaults={'enabled': True, 'config_data': {}}
            )
            proxmox_integration.enabled = True
            proxmox_integration.config_data = {
                'url': proxmox_url,
                'token_id': proxmox_token_id,
                'token_secret': proxmox_token_secret,
                'node': proxmox_node
            }
            proxmox_integration.save()
        else:
            proxmox_integration = IntegrationConfig.objects.filter(name='proxmox', display_name='Default').first()
            if proxmox_integration:
                proxmox_integration.enabled = False
                proxmox_integration.save()
        
        # Mark setup as completed
        SystemConfig.set_value('SETUP_WIZARD_COMPLETED', 'true', 'Initial setup wizard completed')
        
        messages.success(request, 'Setup completed successfully!')
        return redirect('settings_index')
    
    # GET: redirect to unified Settings page
    return redirect('settings_index')


def _get_setup_context():
    """Build context dict for initial configuration form (used in unified Settings page)."""
    telegram_integration = IntegrationConfig.objects.filter(name='telegram', display_name='Default').first()
    telegram_enabled = telegram_integration.enabled if telegram_integration else False
    notify_default = 'True' if telegram_enabled else 'False'
    notify_val = SystemConfig.get_value('NOTIFY_NEW_SERVICE', notify_default).lower().strip()
    notify_new_service = notify_val in ('true', 'on', '1', 'yes')
    context = {
        'discovery_cidr': SystemConfig.get_value('DISCOVERY_CIDR', '192.168.1.0/24'),
        'discovery_interval': SystemConfig.get_value('DISCOVERY_INTERVAL', '10'),
        'service_scan_interval': get_service_scan_interval(),
        'proxmox_sync_interval': get_proxmox_sync_interval(),
        'adguard_sync_interval': get_adguard_sync_interval(),
        'notify_new_service': notify_new_service,
    }
    if telegram_integration:
        context['telegram_enabled'] = telegram_integration.enabled
        context['telegram_bot_token'] = telegram_integration.get_config('bot_token', '')
        context['telegram_chat_id'] = telegram_integration.get_config('chat_id', '')
    else:
        context['telegram_enabled'] = False
        context['telegram_bot_token'] = ''
        context['telegram_chat_id'] = ''
    proxmox_integration = IntegrationConfig.objects.filter(name='proxmox', display_name='Default').first()
    if proxmox_integration:
        context['proxmox_enabled'] = proxmox_integration.enabled
        context['proxmox_url'] = proxmox_integration.get_config('url', '')
        context['proxmox_token_id'] = proxmox_integration.get_config('token_id', '')
        context['proxmox_token_secret'] = proxmox_integration.get_config('token_secret', '')
        context['proxmox_node'] = proxmox_integration.get_config('node', '')
    else:
        context['proxmox_enabled'] = False
        context['proxmox_url'] = context['proxmox_token_id'] = context['proxmox_token_secret'] = context['proxmox_node'] = ''
    adguard_integration, _ = IntegrationConfig.objects.get_or_create(
        name='adguard',
        display_name='Default',
        defaults={'enabled': False, 'config_data': {'url': '', 'username': '', 'password': ''}}
    )
    context['adguard_enabled'] = adguard_integration.enabled
    context['adguard_url'] = adguard_integration.get_config('url', '')
    context['adguard_username'] = adguard_integration.get_config('username', '')
    context['adguard_password'] = adguard_integration.get_config('password', '')
    return context


def _get_health_checks():
    """Build health check list for Settings: last executions and integration status."""
    from inventory.config_manager import (
        get_discovery_interval,
        get_service_scan_interval,
        get_proxmox_sync_interval,
        get_adguard_sync_interval,
    )
    checks = []
    now = timezone.now()
    discovery_interval_min = get_discovery_interval()
    service_interval_min = get_service_scan_interval()
    proxmox_interval_min = get_proxmox_sync_interval()
    adguard_interval_min = get_adguard_sync_interval()

    def _task_check(task_name, display_name, interval_min):
        last_run = TaskExecution.get_last_execution(task_name)
        if not last_run or not last_run.completed_at:
            return {'name': display_name, 'status': 'warning', 'last_run': None, 'message': 'Never run or no completion'}
        last_at = last_run.completed_at
        age_min = (now - last_at).total_seconds() / 60
        threshold_min = max(interval_min * 2, 60)
        if age_min <= threshold_min:
            return {'name': display_name, 'status': 'ok', 'last_run': last_at, 'message': f'Last run {int(age_min)} min ago'}
        return {'name': display_name, 'status': 'warning', 'last_run': last_at, 'message': f'Last run {int(age_min)} min ago (expected within ~{threshold_min} min)'}

    checks.append(_task_check('scan_discovery', 'Discovery scan', discovery_interval_min))
    checks.append(_task_check('scan_services', 'Service scan', service_interval_min))
    checks.append(_task_check('sync_proxmox', 'Proxmox sync', proxmox_interval_min))
    checks.append(_task_check('sync_adguard', 'AdGuard sync', adguard_interval_min))

    telegram_integration = IntegrationConfig.objects.filter(name='telegram', enabled=True).first()
    if telegram_integration:
        token = telegram_integration.get_config('bot_token', '').strip()
        chat_id = telegram_integration.get_config('chat_id', '').strip()
        if token and chat_id:
            checks.append({'name': 'Telegram', 'status': 'ok', 'last_run': None, 'message': 'Configured and enabled'})
        else:
            checks.append({'name': 'Telegram', 'status': 'warning', 'last_run': None, 'message': 'Enabled but token or chat ID missing'})
    else:
        checks.append({'name': 'Telegram', 'status': 'ok', 'last_run': None, 'message': 'Not configured (optional)'})

    overall = 'ok' if all(c['status'] == 'ok' for c in checks) else ('error' if any(c['status'] == 'error' for c in checks) else 'warning')
    return {'checks': checks, 'overall': overall}


@login_required
def settings_index(request):
    """Unified Settings page: Initial configuration form + Integrations list + Users (if staff). All on one page, full width."""
    from django.contrib.auth.models import User
    from django.core.paginator import Paginator
    context = _get_setup_context()
    context['health'] = _get_health_checks()
    # Integration groups for list section
    integration_groups = []
    for name, label in INTEGRATION_TYPES:
        integration_groups.append({
            'name': name,
            'label': label,
            'instances': list(IntegrationConfig.objects.filter(name=name).order_by('display_name')),
        })
    context['integration_groups'] = integration_groups
    # Users section (if staff)
    if request.user.is_staff:
        search = request.GET.get('search', '')
        is_staff_filter = request.GET.get('is_staff', '')
        users_qs = User.objects.all()
        if search:
            users_qs = users_qs.filter(
                Q(username__icontains=search) |
                Q(email__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search)
            )
        if is_staff_filter == 'yes':
            users_qs = users_qs.filter(is_staff=True)
        elif is_staff_filter == 'no':
            users_qs = users_qs.filter(is_staff=False)
        users_qs = users_qs.order_by('username')
        paginator = Paginator(users_qs, 25)
        page = request.GET.get('page', 1)
        context['users'] = paginator.get_page(page)
        context['search'] = search
        context['is_staff_filter'] = is_staff_filter
    return render(request, 'inventory/settings_index.html', context)


# --- Integrations (multiple instances per type) ---
INTEGRATION_TYPES = [
    ('telegram', 'Telegram'),
    ('proxmox', 'Proxmox'),
    ('adguard', 'AdGuard Home'),
]


@login_required
def integrations_list(request):
    """Redirect to unified Settings page (integrations section)."""
    return redirect('settings_index')


@login_required
def integration_add(request, integration_type):
    """Add a new integration instance (telegram, proxmox, or adguard)."""
    if integration_type not in [t[0] for t in INTEGRATION_TYPES]:
        messages.error(request, 'Invalid integration type.')
        return redirect('integrations_list')
    from .admin_forms import TelegramIntegrationForm, ProxmoxIntegrationForm, AdGuardIntegrationForm
    form_class = {
        'telegram': TelegramIntegrationForm,
        'proxmox': ProxmoxIntegrationForm,
        'adguard': AdGuardIntegrationForm,
    }[integration_type]
    type_label = dict(INTEGRATION_TYPES)[integration_type]
    if request.method == 'POST':
        form = form_class(request.POST)
        if form.is_valid():
            display_name = (form.cleaned_data.get('display_name') or '').strip() or 'Default'
            if IntegrationConfig.objects.filter(name=integration_type, display_name=display_name).exists():
                messages.error(request, f'An instance with display name "{display_name}" already exists for {type_label}.')
                context = {'form': form, 'integration_type': integration_type, 'type_label': type_label, 'is_edit': False}
                return render(request, 'inventory/integration_form.html', context)
            instance = IntegrationConfig(name=integration_type, display_name=display_name, enabled=False, config_data={})
            instance.save()
            form = form_class(request.POST, instance=instance)
            if form.is_valid():
                form.save()
            messages.success(request, f'{type_label} integration "{display_name}" added.')
            return redirect('integrations_list')
    else:
        form = form_class(initial={'display_name': ''})
    context = {'form': form, 'integration_type': integration_type, 'type_label': type_label, 'is_edit': False, 'integration': None}
    return render(request, 'inventory/integration_form.html', context)


@login_required
def integration_edit(request, pk):
    """Edit an integration instance."""
    integration = get_object_or_404(IntegrationConfig, pk=pk)
    from .admin_forms import TelegramIntegrationForm, ProxmoxIntegrationForm, AdGuardIntegrationForm
    form_class = {
        'telegram': TelegramIntegrationForm,
        'proxmox': ProxmoxIntegrationForm,
        'adguard': AdGuardIntegrationForm,
    }.get(integration.name)
    if not form_class:
        messages.error(request, 'This integration type cannot be edited here.')
        return redirect('integrations_list')
    if request.method == 'POST':
        form = form_class(request.POST, instance=integration)
        if form.is_valid():
            display_name = (form.cleaned_data.get('display_name') or '').strip() or 'Default'
            other = IntegrationConfig.objects.filter(name=integration.name, display_name=display_name).exclude(pk=integration.pk).first()
            if other:
                messages.error(request, f'Another instance already uses the display name "{display_name}".')
            else:
                form.save()
                messages.success(request, f'{integration.get_name_display()} "{display_name}" updated.')
                return redirect('integrations_list')
    else:
        form = form_class(instance=integration)
    test_result = None
    test_message = None
    if request.GET.get('test') == '1':
        from .admin_views import _test_integration
        test_result, test_message = _test_integration(integration)
        integration.last_test = timezone.now()
        integration.last_test_result = test_result
        integration.last_test_message = test_message
        integration.save(update_fields=['last_test', 'last_test_result', 'last_test_message'])
    context = {
        'form': form,
        'integration': integration,
        'type_label': integration.get_name_display(),
        'is_edit': True,
        'test_result': test_result,
        'test_message': test_message,
    }
    return render(request, 'inventory/integration_form.html', context)


@login_required
@require_http_methods(['GET', 'POST'])
def integration_delete(request, pk):
    """Delete an integration instance (POST to confirm)."""
    integration = get_object_or_404(IntegrationConfig, pk=pk)
    if request.method == 'POST':
        name_display = integration.get_name_display()
        display_name = integration.display_name or 'Default'
        integration.delete()
        messages.success(request, f'{name_display} "{display_name}" deleted.')
        return redirect('integrations_list')
    context = {'integration': integration}
    return render(request, 'inventory/integration_confirm_delete.html', context)


def format_duration(total_seconds):
    """
    Format duration from total seconds to human-readable format.
    - Less than 60 minutes: "11m 30s"
    - 60 minutes or more: "1h 15m 30s"
    """
    if total_seconds is None or total_seconds < 0:
        return None
    
    total_seconds = int(total_seconds)
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    
    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if seconds > 0 or (hours == 0 and minutes == 0):  # Always show seconds if no hours/minutes, or if seconds > 0
        parts.append(f"{seconds}s")
    
    return " ".join(parts) if parts else "0s"


@login_required
@setup_required
def dashboard(request):
    """Dashboard with statistics."""
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    
    # Get last task executions
    last_discovery = TaskExecution.get_last_execution('scan_discovery')
    last_services = TaskExecution.get_last_execution('scan_services')
    last_proxmox = TaskExecution.get_last_execution('sync_proxmox')
    last_adguard = TaskExecution.get_last_execution('sync_adguard')
    
    # Calculate durations
    def get_duration(task_exec):
        if task_exec and task_exec.completed_at and task_exec.started_at:
            delta = task_exec.completed_at - task_exec.started_at
            total_seconds = delta.total_seconds()
            return format_duration(total_seconds)
        return None
    
    # Calculate time until next scan
    def get_time_until_next(task_exec, interval_minutes=None, interval_seconds=None):
        """Calculate time until next scan execution."""
        if not task_exec or not task_exec.completed_at:
            return None
        
        # Use completion time as reference
        last_run = task_exec.completed_at
        
        if interval_minutes:
            interval_sec = interval_minutes * 60
        elif interval_seconds:
            interval_sec = interval_seconds
        else:
            return None
        
        # Calculate next run time
        next_run = last_run + timedelta(seconds=interval_sec)
        
        # If the next run time has already passed, calculate the next one from now
        # This handles server restarts and ensures the timer always counts down
        if next_run <= now:
            # Calculate how many intervals have passed since last_run
            elapsed = (now - last_run).total_seconds()
            intervals_passed = int(elapsed / interval_sec) + 1
            # Calculate the next run time as a multiple of the interval from last_run
            next_run = last_run + timedelta(seconds=interval_sec * intervals_passed)
        
        delta = next_run - now
        total_seconds = int(delta.total_seconds())
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        
        return {'minutes': minutes, 'seconds': seconds, 'total_seconds': total_seconds}
    
    # Get intervals
    discovery_interval = get_discovery_interval()  # minutes
    service_scan_interval_min = get_service_scan_interval()
    proxmox_sync_interval_min = get_proxmox_sync_interval()
    adguard_sync_interval_min = get_adguard_sync_interval()
    
    # Prepare data for JavaScript countdown
    def get_countdown_data(task_exec, interval_minutes=None, interval_seconds=None):
        """Get data for JavaScript countdown timer."""
        if not task_exec or not task_exec.completed_at:
            return None
        
        last_run = task_exec.completed_at
        if interval_minutes:
            interval_sec = interval_minutes * 60
        elif interval_seconds:
            interval_sec = interval_seconds
        else:
            return None
        
        # Calculate next run time
        next_run = last_run + timedelta(seconds=interval_sec)
        
        # If the next run time has already passed, calculate the next one from now
        # This handles server restarts and ensures the timer always counts down
        if next_run <= now:
            # Calculate how many intervals have passed since last_run
            elapsed = (now - last_run).total_seconds()
            intervals_passed = int(elapsed / interval_sec) + 1
            # Calculate the next run time as a multiple of the interval from last_run
            next_run = last_run + timedelta(seconds=interval_sec * intervals_passed)
        
        return {
            'next_run_timestamp': int(next_run.timestamp()),
            'interval_seconds': interval_sec,
        }
    
    stats = {
        'active_hosts': Host.objects.filter(is_active=True).count(),
        'total_hosts': Host.objects.count(),
        'online_ips': IPAddress.objects.filter(online=True).count(),
        'total_ips': IPAddress.objects.count(),
        'total_services': Service.objects.count(),
        'alerts_24h': Alert.objects.filter(created_at__gte=last_24h).count(),
        'recent_alerts': Alert.objects.all()[:10],
        'last_discovery': last_discovery,
        'last_services': last_services,
        'last_proxmox': last_proxmox,
        'last_adguard': last_adguard,
        'discovery_duration': get_duration(last_discovery),
        'services_duration': get_duration(last_services),
        'proxmox_duration': get_duration(last_proxmox),
        'adguard_duration': get_duration(last_adguard),
        'next_discovery': get_time_until_next(last_discovery, interval_minutes=discovery_interval),
        'next_services': get_time_until_next(last_services, interval_minutes=service_scan_interval_min),
        'next_proxmox': get_time_until_next(last_proxmox, interval_minutes=proxmox_sync_interval_min),
        'next_adguard': get_time_until_next(last_adguard, interval_minutes=adguard_sync_interval_min),
        'countdown_discovery': get_countdown_data(last_discovery, interval_minutes=discovery_interval),
        'countdown_services': get_countdown_data(last_services, interval_minutes=service_scan_interval_min),
        'countdown_proxmox': get_countdown_data(last_proxmox, interval_minutes=proxmox_sync_interval_min),
        'countdown_adguard': get_countdown_data(last_adguard, interval_minutes=adguard_sync_interval_min),
    }
    
    return render(request, 'inventory/dashboard.html', {'stats': stats})


@login_required
def hosts_list(request):
    """List all hosts with filters and services."""
    hosts = Host.objects.all()
    
    # Filters
    name_filter = request.GET.get('name', '')
    status_filter = request.GET.get('status', '')
    type_filter = request.GET.get('type', '')
    source_filter = request.GET.get('source', '')
    service_filter = request.GET.get('service', '')
    sort_by = request.GET.get('sort', '-last_seen')
    
    # Apply name filter
    if name_filter:
        hosts = hosts.filter(name__icontains=name_filter)
    
    # Apply status filter
    if status_filter == 'active':
        hosts = hosts.filter(is_active=True)
    elif status_filter == 'inactive':
        hosts = hosts.filter(is_active=False)
    
    # Apply type (device_type) filter
    if type_filter:
        hosts = hosts.filter(device_type=type_filter)
    
    # Apply source filter
    if source_filter:
        hosts = hosts.filter(source=source_filter)
    
    # Apply service filter (hosts that have a service with this port/proto)
    if service_filter:
        # service_filter format: "port/proto" or just "port"
        if '/' in service_filter:
            port, proto = service_filter.split('/', 1)
            hosts = hosts.filter(services__port=port, services__proto=proto.lower()).distinct()
        else:
            # Just port number
            hosts = hosts.filter(services__port=service_filter).distinct()
    
    # Prefetch related data first
    hosts = hosts.prefetch_related('ip_addresses', 'interfaces', 'services')
    
    # Apply sorting
    # For IP sorting, we need to sort by IP address
    if sort_by in ['ip', '-ip']:
        import ipaddress
        def get_sort_key(host):
            ips = [ip.ip for ip in host.ip_addresses.all()]
            if not ips:
                return ipaddress.IPv4Address('255.255.255.255') if sort_by == 'ip' else ipaddress.IPv4Address('0.0.0.0')
            try:
                if sort_by == 'ip':
                    return ipaddress.IPv4Address(min(ips))
                else:
                    return ipaddress.IPv4Address(max(ips))
            except:
                return ipaddress.IPv4Address('255.255.255.255') if sort_by == 'ip' else ipaddress.IPv4Address('0.0.0.0')
        
        hosts_list = list(hosts)
        hosts_list.sort(key=get_sort_key, reverse=(sort_by == '-ip'))
        hosts = hosts_list
    else:
        # Standard Django ordering
        hosts = hosts.order_by(sort_by)
    
    # Get unique values for filter dropdowns
    device_types = Host.objects.values_list('device_type', flat=True).distinct().order_by('device_type')
    sources = Host.objects.values_list('source', flat=True).distinct().order_by('source')
    # Get unique services (port/proto combinations)
    services_list = Service.objects.values_list('port', 'proto').distinct().order_by('port', 'proto')
    services_formatted = [f"{port}/{proto.upper()}" for port, proto in services_list]
    
    return render(request, 'inventory/hosts.html', {
        'hosts': hosts,
        'name_filter': name_filter,
        'status_filter': status_filter,
        'type_filter': type_filter,
        'source_filter': source_filter,
        'service_filter': service_filter,
        'sort_by': sort_by,
        'device_types': device_types,
        'sources': sources,
        'services_formatted': services_formatted,
    })


@login_required
@setup_required
def connection_history(request):
    """Connection history: chart of hosts online over time and event log."""
    from django.utils.dateformat import DateFormat
    from datetime import timedelta
    from django.db.models import Count, Q

    host_id_filter = request.GET.get('host_id', '')
    days = min(max(int(request.GET.get('days', 30)), 1), 365)
    since = timezone.now() - timedelta(days=days)

    events_qs = HostStatusEvent.objects.filter(recorded_at__gte=since).select_related('host', 'task_execution')
    if host_id_filter:
        events_qs = events_qs.filter(host_id=host_id_filter)

    # Build chart:
    # - If a host is selected: plot 1/0 over time based on events for that host.
    # - Otherwise: plot "hosts online per execution" using snapshot rows grouped by TaskExecution.
    chart_labels = []
    chart_data = []
    if host_id_filter:
        events_for_chart = events_qs.order_by('recorded_at')[:2000]
        for e in events_for_chart:
            chart_labels.append(DateFormat(e.recorded_at).format('Y-m-d H:i'))
            chart_data.append(1 if e.is_online else 0)
    else:
        # Only snapshot rows tied to a task execution
        rows = (
            events_qs.filter(is_snapshot=True)
            .exclude(task_execution_id__isnull=True)
            .values('task_execution_id', 'task_execution__started_at')
            .annotate(
                online=Count('id', filter=Q(is_online=True)),
                total=Count('id'),
            )
            .order_by('task_execution__started_at')
        )
        for r in rows:
            dt = r.get('task_execution__started_at')
            chart_labels.append(DateFormat(dt).format('Y-m-d H:i') if dt else '—')
            chart_data.append(int(r.get('online') or 0))

    # Recent events for table (last 200): filter before slicing
    events_recent = events_qs.order_by('-recorded_at')[:200]

    hosts_for_filter = Host.objects.order_by('name').values('id', 'name')
    context = {
        'events': events_recent,
        'chart_labels': json.dumps(chart_labels),
        'chart_data': json.dumps(chart_data),
        'days': days,
        'host_id_filter': host_id_filter,
        'hosts_for_filter': hosts_for_filter,
    }
    return render(request, 'inventory/connection_history.html', context)


@login_required
@setup_required
def edit_host(request, host_id):
    """Edit host details."""
    host = get_object_or_404(Host, id=host_id)
    
    if request.method == 'POST':
        logger.info(f"POST request received for host {host_id}")
        logger.info(f"POST data keys: {list(request.POST.keys())}")
        try:
            # Update host fields
            host.name = request.POST.get('name', host.name).strip()
            if not host.name:
                messages.error(request, 'Host name cannot be empty.')
                # Re-render form with error
                device_types = ['unknown', 'server', 'laptop', 'desktop', 'phone', 'tablet', 'console', 
                                'router', 'switch', 'printer', 'iot', 'lxc', 'qemu']
                duplicate_hosts = Host.objects.filter(name__iexact=host.name).exclude(id=host.id)
                return render(request, 'inventory/edit_host.html', {
                    'host': host,
                    'device_types': device_types,
                    'duplicate_hosts': duplicate_hosts,
                })
            
            logger.info(f"Updating host {host.id}: name={host.name}, is_active={request.POST.get('is_active')}")
            
            # Check if status changed before updating
            old_is_active = host.is_active
            
            host.vendor = request.POST.get('vendor', host.vendor)
            host.device_type = request.POST.get('device_type', host.device_type)
            host.notes = request.POST.get('notes', host.notes)
            # Handle is_active checkbox
            # Hidden input sends '1' when checked, '0' when unchecked
            is_active_value = request.POST.get('is_active', '0')
            host.is_active = (is_active_value == '1')
            host.save()

            # Sync IPs' online status with host is_active (so IPs show Online when host is Active)
            host.ip_addresses.update(online=host.is_active)

            # Create alert and status event if status changed
            if old_is_active != host.is_active:
                status_text = "Active" if host.is_active else "Inactive"
                ip_obj = host.ip_addresses.first()  # Get first IP if available
                Alert.objects.create(
                    type='host_status_change',
                    message=f"Host {host.name} status changed to {status_text} (manual edit)",
                    related_host=host,
                    related_ip=ip_obj,
                    details=f"Previous status: {'Active' if old_is_active else 'Inactive'}\nNew status: {status_text}\nChanged by: Manual edit"
                )
                HostStatusEvent.record(host, host.is_active)

            # Handle IP addresses
            # First, handle explicit deletions (checkboxes)
            deleted_ips = set()
            for key, value in request.POST.items():
                if key.startswith('delete_ip_') and value == 'on':
                    ip_to_delete = key.replace('delete_ip_', '')
                    if ip_to_delete:  # Make sure it's not empty
                        IPAddress.objects.filter(ip=ip_to_delete, host=host).delete()
                        deleted_ips.add(ip_to_delete)
            
            # Get existing IPs for this host (refresh after deletions)
            host.refresh_from_db()
            existing_ips = set(ip.ip for ip in host.ip_addresses.all())
            
            # Get IPs from form (all IPs that should be associated with this host)
            # Note: the edit form does not include ip_* inputs; IPs are managed via Add IP / Delete IP only.
            # So we preserve existing IPs by building form_ips from current host IPs when no ip_* in POST.
            form_ips = []
            for key, value in request.POST.items():
                if key.startswith('ip_') and value.strip():
                    ip_str = value.strip()
                    if ip_str and ip_str not in form_ips and '.' in ip_str:
                        form_ips.append(ip_str)
            if not form_ips and not any(k.startswith('ip_') for k in request.POST.keys()):
                # Form did not submit any IP fields (normal case): keep all current IPs
                form_ips = list(host.ip_addresses.values_list('ip', flat=True))

            # Process each IP from the form
            for ip_str in form_ips:
                # Skip if this IP was explicitly deleted
                if ip_str in deleted_ips:
                    continue
                    
                if ip_str not in existing_ips:
                    # This is a new IP for this host
                    # Check if IP already exists in database (maybe assigned to another host)
                    try:
                        existing_ip_obj = IPAddress.objects.get(ip=ip_str)
                        other_host = existing_ip_obj.host
                        
                        if other_host and other_host.id != host.id:
                            # IP exists but assigned to different host
                            # Check if the other host has the same name - if so, merge them
                            if other_host.name.lower() == host.name.lower():
                                # Same name - merge the other host into this one
                                logger.info(f"Auto-merging host {other_host.id} ({other_host.name}) into host {host.id} ({host.name})")
                                
                                # Move all IPs from other host to this host
                                ip_count = IPAddress.objects.filter(host=other_host).count()
                                IPAddress.objects.filter(host=other_host).update(host=host)
                                logger.info(f"Moved {ip_count} IPs from {other_host.name} to {host.name}")
                                
                                # Merge services - handle duplicates
                                from inventory.models import Service
                                services_moved = 0
                                services_merged = 0
                                for service in list(other_host.services.all()):
                                    existing_service = Service.objects.filter(
                                        host=host,
                                        port=service.port,
                                        proto=service.proto
                                    ).first()
                                    
                                    if existing_service:
                                        # Merge service data
                                        updated = False
                                        if not existing_service.name and service.name:
                                            existing_service.name = service.name
                                            updated = True
                                        if not existing_service.product and service.product:
                                            existing_service.product = service.product
                                            updated = True
                                        if not existing_service.version and service.version:
                                            existing_service.version = service.version
                                            updated = True
                                        if not existing_service.extra_info and service.extra_info:
                                            existing_service.extra_info = service.extra_info
                                            updated = True
                                        if updated:
                                            existing_service.save()
                                            services_merged += 1
                                        service.delete()
                                    else:
                                        service.host = host
                                        service.save()
                                        services_moved += 1
                                logger.info(f"Moved {services_moved} services and merged {services_merged} duplicate services")
                                
                                # Merge MAC if we don't have one
                                if not host.mac and other_host.mac:
                                    host.mac = other_host.mac
                                    logger.info(f"Merged MAC: {other_host.mac}")
                                
                                # Merge vendor if we don't have one
                                if not host.vendor and other_host.vendor:
                                    host.vendor = other_host.vendor
                                    logger.info(f"Merged vendor: {other_host.vendor}")
                                
                                # Merge device_type if we don't have one or it's unknown
                                if (not host.device_type or host.device_type == 'unknown') and other_host.device_type and other_host.device_type != 'unknown':
                                    host.device_type = other_host.device_type
                                    logger.info(f"Merged device_type: {other_host.device_type}")
                                
                                # Merge notes
                                if other_host.notes:
                                    if not host.notes:
                                        host.notes = other_host.notes
                                    elif other_host.notes not in host.notes:
                                        host.notes = f"{host.notes}\n{other_host.notes}".strip()
                                    logger.info("Merged notes")
                                
                                # Update last_seen to most recent
                                if other_host.last_seen and (not host.last_seen or other_host.last_seen > host.last_seen):
                                    host.last_seen = other_host.last_seen
                                    logger.info(f"Updated last_seen to {other_host.last_seen}")
                                
                                old_active = host.is_active
                                host.is_active = host.is_active or other_host.is_active
                                host.save()
                                if old_active != host.is_active:
                                    HostStatusEvent.record(host, host.is_active)
                                
                                # Delete the duplicate host
                                other_host_name = other_host.name
                                other_host.delete()
                                logger.info(f"Deleted duplicate host {other_host_name}")
                                
                                messages.success(request, f'Hosts "{host.name}" automatically merged. IP {ip_str} assigned. {ip_count} IPs and {services_moved + services_merged} services moved.')
                            else:
                                # Different names - just move the IP and warn
                                existing_ip_obj.host = host
                                existing_ip_obj.online = host.is_active
                                existing_ip_obj.save()
                                messages.warning(request, f'IP {ip_str} moved from "{other_host.name}" to "{host.name}".')
                        else:
                            # IP exists but assigned to same host (shouldn't happen) or no host
                            existing_ip_obj.host = host
                            existing_ip_obj.online = host.is_active
                            existing_ip_obj.save()
                    except IPAddress.DoesNotExist:
                        # IP doesn't exist - create new one (online follows host is_active)
                        IPAddress.objects.create(
                            ip=ip_str,
                            host=host,
                            online=host.is_active,
                        )
                else:
                    # IP already exists for this host - keep in sync with host is_active
                    try:
                        ip_obj = IPAddress.objects.get(ip=ip_str, host=host)
                        ip_obj.online = host.is_active
                        ip_obj.save()
                    except IPAddress.DoesNotExist:
                        # Shouldn't happen, but handle it
                        IPAddress.objects.create(
                            ip=ip_str,
                            host=host,
                            online=host.is_active,
                        )

            # Remove IPs that are no longer in the form (but weren't explicitly deleted)
            # Only run when form actually sent IP list (form_ips was from POST), not when we kept current IPs
            form_ips_set = set(form_ips)
            for ip_obj in list(host.ip_addresses.all()):
                if ip_obj.ip not in form_ips_set and ip_obj.ip not in deleted_ips:
                    ip_obj.delete()

            messages.success(request, f'Host {host.name} updated successfully')
            # Refresh host data
            host.refresh_from_db()
            # Redirect to same page with success parameter
            return redirect(f'{request.path}?saved=1')
        except Exception as e:
            import traceback
            logger.error(f"Error processing host edit: {e}\n{traceback.format_exc()}")
            messages.error(request, f'Error updating host: {str(e)}')
            # Re-render form with error
            device_types = ['unknown', 'server', 'laptop', 'desktop', 'phone', 'tablet', 'console', 
                            'router', 'switch', 'printer', 'iot', 'lxc', 'qemu']
            duplicate_hosts = Host.objects.filter(name__iexact=host.name).exclude(id=host.id)
            return render(request, 'inventory/edit_host.html', {
                'host': host,
                'device_types': device_types,
                'duplicate_hosts': duplicate_hosts,
            })
    
    # Sync IPs' online status with host is_active so Active host always shows IPs as Online
    host.ip_addresses.update(online=host.is_active)
    
    # Get available device types
    device_types = ['unknown', 'server', 'laptop', 'desktop', 'phone', 'tablet', 'console', 
                    'router', 'switch', 'printer', 'iot', 'lxc', 'qemu']
    
    # Find duplicate hosts (same name, different ID)
    duplicate_hosts = Host.objects.filter(name__iexact=host.name).exclude(id=host.id)
    
    return render(request, 'inventory/edit_host.html', {
        'host': host,
        'device_types': device_types,
        'duplicate_hosts': duplicate_hosts,
    })


@login_required
@setup_required
@require_http_methods(["POST"])
def add_host_ip(request, host_id):
    """Add an IP address to a host via AJAX."""
    import json
    from django.core.validators import validate_ipv4_address
    from django.core.exceptions import ValidationError
    
    host = get_object_or_404(Host, id=host_id)
    
    try:
        data = json.loads(request.body)
        ip_address = data.get('ip', '').strip()
        
        if not ip_address:
            return JsonResponse({'success': False, 'error': 'IP address is required'}, status=400)
        
        # Validate IP address
        try:
            validate_ipv4_address(ip_address)
        except ValidationError:
            return JsonResponse({'success': False, 'error': 'Invalid IP address format'}, status=400)
        
        # Check if IP already exists
        try:
            existing_ip = IPAddress.objects.get(ip=ip_address)
            if existing_ip.host and existing_ip.host.id == host.id:
                return JsonResponse({'success': False, 'error': 'IP address already assigned to this host'}, status=400)
            elif existing_ip.host:
                # IP exists but assigned to different host
                # Move it to this host (online follows host is_active)
                existing_ip.host = host
                existing_ip.online = host.is_active
                existing_ip.save()
                return JsonResponse({'success': True, 'message': 'IP address moved to this host'})
        except IPAddress.DoesNotExist:
            pass

        # Create new IP address (online follows host is_active)
        ip_obj = IPAddress.objects.create(
            ip=ip_address,
            host=host,
            assignment='static',
            online=host.is_active
        )
        
        return JsonResponse({'success': True, 'message': 'IP address added successfully', 'ip_id': ip_obj.id})
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error adding IP to host {host_id}: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@login_required
@setup_required
@require_http_methods(["POST"])
def delete_host_ip(request, host_id):
    """Delete an IP address from a host via AJAX."""
    import json
    
    host = get_object_or_404(Host, id=host_id)
    
    try:
        data = json.loads(request.body)
        ip_id = data.get('ip_id')
        
        if not ip_id:
            return JsonResponse({'success': False, 'error': 'IP ID is required'}, status=400)
        
        # Get IP address
        try:
            ip_obj = IPAddress.objects.get(id=ip_id, host=host)
        except IPAddress.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'IP address not found'}, status=404)
        
        # Delete IP address
        ip_obj.delete()
        
        return JsonResponse({'success': True, 'message': 'IP address deleted successfully'})
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error deleting IP from host {host_id}: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@login_required
@setup_required
@require_http_methods(["POST"])
def add_host_hostname(request, host_id):
    """Add a hostname to a host via AJAX."""
    import json
    
    host = get_object_or_404(Host, id=host_id)
    
    try:
        data = json.loads(request.body)
        hostname_name = data.get('hostname', '').strip()
        source_type = data.get('source_type', 'manual')
        
        if not hostname_name:
            return JsonResponse({'success': False, 'error': 'Hostname is required'}, status=400)
        
        # Basic hostname validation (allow letters, numbers, dots, hyphens)
        import re
        if not re.match(r'^[a-zA-Z0-9.-]+$', hostname_name):
            return JsonResponse({'success': False, 'error': 'Invalid hostname format'}, status=400)
        
        # Check if hostname already exists for this host
        try:
            existing_hostname = Hostname.objects.get(host=host, name=hostname_name)
            return JsonResponse({'success': False, 'error': 'Hostname already exists for this host'}, status=400)
        except Hostname.DoesNotExist:
            pass
        
        # Create new hostname
        hostname_obj = Hostname.objects.create(
            host=host,
            name=hostname_name,
            source_type=source_type
        )
        
        return JsonResponse({'success': True, 'message': 'Hostname added successfully', 'hostname_id': hostname_obj.id})
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error adding hostname to host {host_id}: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@login_required
@setup_required
@require_http_methods(["POST"])
def delete_host_hostname(request, host_id):
    """Delete a hostname from a host via AJAX."""
    import json
    
    host = get_object_or_404(Host, id=host_id)
    
    try:
        data = json.loads(request.body)
        hostname_id = data.get('hostname_id')
        
        if not hostname_id:
            return JsonResponse({'success': False, 'error': 'Hostname ID is required'}, status=400)
        
        # Get hostname
        try:
            hostname_obj = Hostname.objects.get(id=hostname_id, host=host)
        except Hostname.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Hostname not found'}, status=404)
        
        # Delete hostname
        hostname_obj.delete()
        
        return JsonResponse({'success': True, 'message': 'Hostname deleted successfully'})
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error deleting hostname from host {host_id}: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@login_required
@setup_required
def merge_hosts(request, host_id, other_host_id):
    """Merge another host into the current host."""
    host = get_object_or_404(Host, id=host_id)
    other_host = get_object_or_404(Host, id=other_host_id)
    
    if request.method == 'POST':
        try:
            logger.info(f"Merging host {other_host_id} ({other_host.name}) into host {host_id} ({host.name})")
            
            # Move all IPs from other host to this host (if any)
            ip_count = IPAddress.objects.filter(host=other_host).count()
            if ip_count > 0:
                IPAddress.objects.filter(host=other_host).update(host=host)
                logger.info(f"Moved {ip_count} IPs from {other_host.name} to {host.name}")
            else:
                logger.info(f"No IPs to move from {other_host.name} (it has no IPs)")
            
            # Move all services from other host to this host
            # Handle duplicate services (same port/proto) by merging data
            services_moved = 0
            services_merged = 0
            for service in list(other_host.services.all()):  # Use list() to avoid queryset issues
                existing_service = Service.objects.filter(
                    host=host,
                    port=service.port,
                    proto=service.proto
                ).first()
                
                if existing_service:
                    # Merge service data
                    updated = False
                    if not existing_service.name and service.name:
                        existing_service.name = service.name
                        updated = True
                    if not existing_service.product and service.product:
                        existing_service.product = service.product
                        updated = True
                    if not existing_service.version and service.version:
                        existing_service.version = service.version
                        updated = True
                    if not existing_service.extra_info and service.extra_info:
                        existing_service.extra_info = service.extra_info
                        updated = True
                    if updated:
                        existing_service.save()
                        services_merged += 1
                    service.delete()
                else:
                    # Move service to this host
                    service.host = host
                    service.save()
                    services_moved += 1
            logger.info(f"Moved {services_moved} services and merged {services_merged} duplicate services")
            
            # Merge MAC if we don't have one
            if not host.mac and other_host.mac:
                # Check if MAC is already assigned to another host
                existing_mac_host = Host.objects.filter(mac=other_host.mac).exclude(id__in=[host.id, other_host.id]).first()
                if not existing_mac_host:
                    host.mac = other_host.mac
                    logger.info(f"Merged MAC {other_host.mac}")
                else:
                    logger.warning(f'MAC {other_host.mac} is already assigned to another host, not merged.')
                    messages.warning(request, f'MAC {other_host.mac} is already assigned to another host, not merged.')
            
            # Merge vendor if we don't have one
            if not host.vendor and other_host.vendor:
                host.vendor = other_host.vendor
                logger.info(f"Merged vendor: {other_host.vendor}")
            
            # Merge device_type if we don't have one or it's unknown
            if (not host.device_type or host.device_type == 'unknown') and other_host.device_type and other_host.device_type != 'unknown':
                host.device_type = other_host.device_type
                logger.info(f"Merged device_type: {other_host.device_type}")
            
            # Merge notes
            if other_host.notes:
                if not host.notes:
                    host.notes = other_host.notes
                elif other_host.notes not in host.notes:
                    host.notes = f"{host.notes}\n{other_host.notes}".strip()
                logger.info("Merged notes")
            
            # Update last_seen to most recent
            if other_host.last_seen and (not host.last_seen or other_host.last_seen > host.last_seen):
                host.last_seen = other_host.last_seen
                logger.info(f"Updated last_seen to {other_host.last_seen}")
            
            old_active = host.is_active
            host.is_active = host.is_active or other_host.is_active
            
            # Save host before deleting other_host
            host.save()
            if old_active != host.is_active:
                HostStatusEvent.record(host, host.is_active)
            logger.info(f"Saved host {host.id} with merged data")
            
            # Delete the duplicate host
            other_host_name = other_host.name
            other_host_id_to_delete = other_host.id
            other_host.delete()
            logger.info(f"Deleted duplicate host {other_host_id_to_delete} ({other_host_name})")
            
            # Build success message
            success_parts = [f'Host "{other_host_name}" successfully merged into "{host.name}".']
            if ip_count > 0:
                success_parts.append(f'{ip_count} IPs moved.')
            if services_moved + services_merged > 0:
                success_parts.append(f'{services_moved + services_merged} services moved.')
            if ip_count == 0 and services_moved + services_merged == 0:
                success_parts.append('All data merged.')
            
            messages.success(request, ' '.join(success_parts))
            logger.info(f"Merge completed successfully: {' '.join(success_parts)}")
        except Exception as e:
            import traceback
            error_msg = f'Error merging hosts: {str(e)}'
            logger.error(f"{error_msg}\n{traceback.format_exc()}")
            messages.error(request, error_msg)
    
    return redirect('edit_host', host_id=host.id)


def scan_host_ip_stream(host_id, ip_address, scan_type='complete'):
    """Generator that yields nmap scan output in real-time.
    
    scan_type options:
    - 'quick': nmap -T4 -O -F (fast scan, top 100 ports, OS detection)
    - 'quick_plus': nmap -sV -T4 -O -F --version-light (quick + version detection)
    - 'intense': nmap -T4 -A -v (aggressive scan with OS and version detection)
    - 'discover_hostname': nmap -p 53,80,443,139,445,5353 -R --script nbstat,dns-service-discovery,ssl-cert,http-title (hostname discovery)
    - 'complete': Full scan with all ports and maximum information gathering
    """
    import subprocess
    import threading
    import queue
    import logging
    from inventory.services.nmap_parser import parse_nmap_xml
    from inventory.models import Service
    
    logger = logging.getLogger(__name__)
    
    host = Host.objects.get(id=host_id)
    
    # Verify IP belongs to host
    ip_obj = host.ip_addresses.filter(ip=ip_address).first()
    if not ip_obj:
        yield f"data: {json.dumps({'type': 'error', 'message': f'IP {ip_address} does not belong to host {host.name}'})}\n\n"
        return
    
    # Map scan types to descriptions
    scan_descriptions = {
        'quick': 'Quick Scan (Fast, Top 100 ports, OS detection)',
        'quick_plus': 'Quick Scan Plus (Fast, Top 100 ports, OS + Version detection)',
        'intense': 'Intense Scan (Aggressive, OS + Version + Scripts)',
        'complete': 'Complete Scan (All ports, Maximum information gathering)',
        'discover_hostname': 'Discover Hostname (DNS, NetBIOS, SSL, HTTP hostname discovery)'
    }
    
    scan_description = scan_descriptions.get(scan_type, scan_descriptions['complete'])
    yield f"data: {json.dumps({'type': 'start', 'message': f'Starting {scan_description} for {ip_address}...'})}\n\n"
    
    # Run nmap scan based on scan type
    # Strategy: Use stderr for verbose output (real-time), stdout for XML only
    # We'll use a temp file for XML to avoid mixing with verbose output
    import tempfile
    import os
    temp_xml_file = tempfile.NamedTemporaryFile(mode='w+', suffix='.xml', delete=False)
    temp_xml_path = temp_xml_file.name
    temp_xml_file.close()
    
    # Base options for all scans: OS detection, hostname resolution, XML output
    base_options = [
        '-O',  # OS detection (enabled for all scans)
        '--resolve-all',  # Resolve all hostnames (DNS, NetBIOS, etc.)
        '-oX', temp_xml_path,  # XML output to temp file
    ]
    
    # Build command based on scan type
    if scan_type == 'quick':
        # Quick scan: -T4 -O -F
        cmd = [
            'nmap',
            '-T4',  # Aggressive timing
            '-O',  # OS detection
            '-F',  # Fast scan (top 100 ports)
            '--resolve-all',  # Resolve hostnames
            '-vv',  # Very verbose
            '--stats-every', '5s',  # Progress updates
            '-oX', temp_xml_path,
            ip_address,
        ]
    elif scan_type == 'quick_plus':
        # Quick scan plus: -sV -T4 -O -F --version-light
        cmd = [
            'nmap',
            '-sV',  # Version detection
            '-T4',  # Aggressive timing
            '-O',  # OS detection
            '-F',  # Fast scan (top 100 ports)
            '--version-light',  # Light version detection (faster)
            '--resolve-all',  # Resolve hostnames
            '-vv',  # Very verbose
            '--stats-every', '5s',  # Progress updates
            '-oX', temp_xml_path,
            ip_address,
        ]
    elif scan_type == 'intense':
        # Intense scan: -T4 -A -v
        cmd = [
            'nmap',
            '-T4',  # Aggressive timing
            '-A',  # Aggressive mode: OS detection, version detection, script scanning, traceroute
            '-v',  # Verbose (less verbose than -vv but still informative)
            '--resolve-all',  # Resolve hostnames
            '--stats-every', '5s',  # Progress updates
            '-oX', temp_xml_path,
            ip_address,
        ]
    elif scan_type == 'discover_hostname':
        # Discover Hostname scan: Focused on hostname discovery via DNS, NetBIOS, SSL, HTTP
        cmd = [
            'nmap',
            '-p', '53,80,443,139,445,5353',  # Specific ports: DNS, HTTP, HTTPS, NetBIOS, SMB, mDNS
            '-R',  # Force reverse DNS resolution
            '--script', 'nbstat,dns-service-discovery,ssl-cert,http-title',  # Hostname discovery scripts
            '-vv',  # Very verbose
            '--resolve-all',  # Resolve all hostnames (DNS, NetBIOS, etc.)
            '--stats-every', '5s',  # Progress updates
            '-oX', temp_xml_path,
            ip_address,
        ]
    else:  # complete (default)
        # Complete scan: Full scan with all ports and maximum information
        cmd = [
            'nmap',
            '-sS',  # SYN scan (stealth)
            '-A',   # Aggressive mode: OS detection, version detection, script scanning, traceroute
            '-sC',  # Run default scripts (safe and useful)
            '-vv',  # Very verbose output (shows more progress information) - goes to stderr
            '--version-intensity=9',  # Maximum version detection intensity (0-9)
            '--version-all',  # Try every single version detection probe
            '-p-',  # Scan ALL ports (1-65535)
            '--reason',  # Show reason why ports are in certain states
            '--resolve-all',  # Resolve hostnames
            '--stats-every', '5s',  # Show progress every 5 seconds
            '-oX', temp_xml_path,  # XML output to temp file
            ip_address,
        ]
    
    try:
        output_queue = queue.Queue()
        error_queue = queue.Queue()
        
        # Use unbuffered mode for real-time output
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=0,  # Unbuffered for real-time output
            universal_newlines=True,
            env=env
        )
        
        # Set stdout and stderr to unbuffered
        import sys
        if hasattr(process.stdout, 'reconfigure'):
            process.stdout.reconfigure(line_buffering=True)
        if hasattr(process.stderr, 'reconfigure'):
            process.stderr.reconfigure(line_buffering=True)
        
        def read_stdout():
            # With XML going to file, stdout should be mostly empty, but read it anyway
            try:
                logger.info("Starting to read stdout from nmap process")
                line_count = 0
                while True:
                    line = process.stdout.readline()
                    if not line:
                        logger.info(f"Stdout read complete, read {line_count} lines")
                        break
                    if line:
                        line_count += 1
                        line_stripped = line.strip()
                        # Any stdout output (should be minimal) - show it
                        if line_stripped:
                            logger.debug(f"Stdout line {line_count}: {line_stripped[:100]}")
                            output_queue.put(('stdout', line_stripped))
            except Exception as e:
                logger.error(f"Error reading stdout: {e}", exc_info=True)
            finally:
                output_queue.put(('stdout', None))  # Sentinel
        
        def read_stderr():
            # Capture verbose output (nmap sends verbose output to stderr with -vv)
            try:
                logger.info("Starting to read stderr from nmap process")
                line_count = 0
                while True:
                    line = process.stderr.readline()
                    if not line:
                        logger.info(f"Stderr read complete, read {line_count} lines")
                        break
                    if line:
                        line_count += 1
                        # Send all stderr output to be displayed (this is the verbose output)
                        line_clean = line.rstrip()
                        if line_clean:  # Only send non-empty lines
                            logger.debug(f"Stderr line {line_count}: {line_clean[:100]}")
                            error_queue.put(('stderr', line_clean))
            except Exception as e:
                logger.error(f"Error reading stderr: {e}", exc_info=True)
            finally:
                error_queue.put(('stderr', None))  # Sentinel
        
        # Start threads
        logger.info(f"Starting nmap process for IP {ip_address}")
        stdout_thread = threading.Thread(target=read_stdout, daemon=True)
        stderr_thread = threading.Thread(target=read_stderr, daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        logger.info("Started stdout and stderr reading threads")
        
        # Process output in real-time
        stdout_done = False
        stderr_done = False
        
        # Send initial message
        yield f"data: {json.dumps({'type': 'output', 'line': f'Starting comprehensive nmap scan of {ip_address}...'})}\n\n"
        yield f"data: {json.dumps({'type': 'output', 'line': 'This may take several minutes. Progress updates will appear below.'})}\n\n"
        yield f"data: {json.dumps({'type': 'output', 'line': 'Waiting for nmap output (this may take a moment to start)...'})}\n\n"
        
        # Small delay to let nmap start
        import time
        time.sleep(0.5)
        logger.info("Starting to process output queues")
        
        last_output_time = time.time()
        no_output_count = 0
        
        while not (stdout_done and stderr_done):
            current_time = time.time()
            got_output = False
            
            # Check stderr first (verbose output from nmap) - this is where ALL progress goes
            if not stderr_done:
                try:
                    item = error_queue.get(timeout=0.1)
                    if item[1] is None:
                        stderr_done = True
                        logger.info("Stderr reading completed")
                    else:
                        # Show all stderr output (this is the verbose nmap output)
                        line = item[1]
                        if line:  # Only send non-empty lines
                            yield f"data: {json.dumps({'type': 'output', 'line': line})}\n\n"
                            last_output_time = current_time
                            got_output = True
                            no_output_count = 0
                except queue.Empty:
                    pass
            
            # Check stdout (should be minimal now)
            if not stdout_done:
                try:
                    item = output_queue.get(timeout=0.05)
                    if item[1] is None:
                        stdout_done = True
                        logger.info("Stdout reading completed")
                    else:
                        # Display any stdout output
                        line = item[1]
                        if line:
                            yield f"data: {json.dumps({'type': 'output', 'line': line})}\n\n"
                            last_output_time = current_time
                            got_output = True
                            no_output_count = 0
                except queue.Empty:
                    pass
            
            # Only show "still scanning" if we haven't had output for 30 seconds
            if not got_output:
                no_output_count += 1
                if no_output_count > 300:  # 30 seconds at 0.1s intervals
                    yield f"data: {json.dumps({'type': 'output', 'line': 'Still scanning... (this may take a while for all ports)'})}\n\n"
                    no_output_count = 0
        
        process.wait()
        
        if process.returncode != 0:
            yield f"data: {json.dumps({'type': 'error', 'message': f'Nmap scan failed with exit code {process.returncode}'})}\n\n"
            # Clean up temp file
            try:
                os.unlink(temp_xml_path)
            except:
                pass
            return
        
        # Read XML from temp file
        yield f"data: {json.dumps({'type': 'output', 'line': 'Parsing scan results...'})}\n\n"
        
        try:
            with open(temp_xml_path, 'r', encoding='utf-8') as f:
                xml_content = f.read()
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': f'Error reading XML file: {str(e)}'})}\n\n"
            try:
                os.unlink(temp_xml_path)
            except:
                pass
            return
        
        # Clean up temp file
        try:
            os.unlink(temp_xml_path)
        except:
            pass
        
        if not xml_content or not xml_content.strip():
            yield f"data: {json.dumps({'type': 'error', 'message': 'No XML output captured from nmap scan'})}\n\n"
            yield f"data: {json.dumps({'type': 'output', 'line': f'XML content length: {len(xml_content)}'})}\n\n"
            return
        
        try:
            parsed = parse_nmap_xml(xml_content)
            hosts_data = parsed.get('hosts', [])
            
            if not hosts_data:
                yield f"data: {json.dumps({'type': 'error', 'message': 'No hosts data parsed from XML'})}\n\n"
                yield f"data: {json.dumps({'type': 'output', 'line': f'XML preview (first 500 chars): {xml_content[:500]}...'})}\n\n"
                return
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': f'Error parsing XML: {str(e)}'})}\n\n"
            yield f"data: {json.dumps({'type': 'output', 'line': f'XML content length: {len(xml_content)}'})}\n\n"
            logger.error(f"Error parsing nmap XML: {e}")
            logger.error(f"XML content preview: {xml_content[:1000]}")
            return
        
        host_data = hosts_data[0]
        
        # Update host information
        updates = []
        if host_data.get('hostname') and (not host.name or host.name == 'unknown'):
            host.name = host_data['hostname']
            updates.append(f"Hostname: {host_data['hostname']}")
        
        # Save all hostnames found
        hostnames_found = host_data.get('hostnames', [])
        if hostnames_found:
            hostnames_saved = 0
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
                    else:
                        hostnames_saved += 1
            if hostnames_saved > 0:
                updates.append(f"Found {hostnames_saved} new hostname(s)")
            elif hostnames_found:
                updates.append(f"Updated {len(hostnames_found)} hostname(s)")
        
        if host_data.get('mac') and not host.mac:
            host.mac = host_data['mac'].lower()
            updates.append(f"MAC: {host_data['mac']}")
        
        if host_data.get('vendor') and not host.vendor:
            host.vendor = host_data['vendor']
            updates.append(f"Vendor: {host_data['vendor']}")
        
        # Update OS information if available
        if host_data.get('os'):
            if not host.notes:
                host.notes = f"OS: {host_data['os']}\n"
            elif 'OS:' not in host.notes:
                host.notes += f"\nOS: {host_data['os']}\n"
            updates.append(f"OS: {host_data['os']}")
        
        # Check if status changed before updating
        old_is_active = host.is_active
        
        host.last_seen = timezone.now()
        # Check host status from nmap - mark as inactive if down
        host_status = host_data.get('status', 'down')
        services = host_data.get('services', [])
        open_services = [s for s in services if s.get('state') in ['open', 'open|filtered']]
        # Host is active if it's up OR has open ports
        host.is_active = (host_status == 'up' or len(open_services) > 0)
        host.save()
        
        if not host.is_active:
            updates.append("⚠️ Host detected as DOWN - marked as inactive")
        
        # Create alert and record status event if status changed
        if old_is_active != host.is_active:
            status_text = "Active" if host.is_active else "Inactive"
            ip_address = host_data.get('ip', 'unknown')
            try:
                ip_obj = host.ip_addresses.filter(ip=ip_address).first()
            except:
                ip_obj = None
            Alert.objects.create(
                type='host_status_change',
                message=f"Host {host.name} ({ip_address}) status changed to {status_text}",
                related_host=host,
                related_ip=ip_obj,
                details=f"Previous status: {'Active' if old_is_active else 'Inactive'}\nNew status: {status_text}\nNmap status: {host_status}\nOpen ports: {len(open_services)}"
            )
            HostStatusEvent.record(host, host.is_active)
            updates.append(f"📢 Alert created: Status changed to {status_text}")
        
        if updates:
            yield f"data: {json.dumps({'type': 'output', 'line': 'Updated host information:'})}\n\n"
            for update in updates:
                yield f"data: {json.dumps({'type': 'output', 'line': f'  - {update}'})}\n\n"
        
        # Update or create services
        services_updated = 0
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
            
            if not created:
                # Update existing service
                service.name = service_data.get('name', '') or service.name
                service.product = service_data.get('product', '') or service.product
                service.version = service_data.get('version', '') or service.version
                service.extra_info = service_data.get('extra_info', '') or service.extra_info
                service.save()
            
            services_updated += 1
        
        # Create alert when scan completes successfully (from host edit or from "Click to rescan" on inactive)
        status_text = "Active" if host.is_active else "Inactive"
        detail_lines = [
            f"Scan type: {scan_description}",
            f"Host: {host.name}",
            f"IP: {ip_address}",
            f"Status: {status_text}",
            f"Nmap status: {host_status}",
            f"Open ports: {len(open_services)}",
            f"Services found/updated: {services_updated}",
        ]
        if open_services:
            detail_lines.append("Open services:")
            for s in open_services[:20]:
                port = s.get('port', '')
                proto = s.get('proto', 'tcp')
                name = s.get('name', '') or s.get('product', '') or 'unknown'
                detail_lines.append(f"  - {port}/{proto} ({name})")
            if len(open_services) > 20:
                detail_lines.append(f"  ... and {len(open_services) - 20} more")
        Alert.objects.create(
            type='task_completed',
            message=f"Scan completed: {host.name} ({ip_address}) - {scan_description}. {services_updated} service(s), status: {status_text}",
            related_host=host,
            related_ip=ip_obj,
            details="\n".join(detail_lines),
        )
        
        yield f"data: {json.dumps({'type': 'output', 'line': f'Found {services_updated} service(s)'})}\n\n"
        yield f"data: {json.dumps({'type': 'success', 'message': f'Scan completed successfully. Found {services_updated} service(s).', 'host_id': host_id})}\n\n"
        
    except subprocess.TimeoutExpired:
        err_msg = 'Nmap scan timed out (max 10 minutes)'
        Alert.objects.create(
            type='error',
            message=f"Scan failed: {host.name} ({ip_address}) - {err_msg}",
            related_host=host,
            related_ip=ip_obj,
            details=err_msg,
        )
        yield f"data: {json.dumps({'type': 'error', 'message': err_msg})}\n\n"
    except FileNotFoundError:
        err_msg = 'nmap not found. Please install nmap.'
        Alert.objects.create(
            type='error',
            message=f"Scan failed: {host.name} ({ip_address}) - {err_msg}",
            related_host=host,
            related_ip=ip_obj,
            details=err_msg,
        )
        yield f"data: {json.dumps({'type': 'error', 'message': err_msg})}\n\n"
    except Exception as e:
        err_msg = str(e)
        Alert.objects.create(
            type='error',
            message=f"Scan failed: {host.name} ({ip_address}) - {err_msg}",
            related_host=host,
            related_ip=ip_obj,
            details=err_msg,
        )
        yield f"data: {json.dumps({'type': 'error', 'message': err_msg})}\n\n"


@login_required
@setup_required
def scan_host_ip(request, host_id, ip_address):
    """API endpoint to run nmap scan on a specific IP and stream output."""
    host = get_object_or_404(Host, id=host_id)
    
    # Verify IP belongs to host
    ip_obj = host.ip_addresses.filter(ip=ip_address).first()
    if not ip_obj:
        return JsonResponse({'error': f'IP {ip_address} does not belong to host {host.name}'}, status=400)
    
    # Get scan type from query parameter, default to 'complete'
    scan_type = request.GET.get('scan_type', 'complete')
    # Validate scan_type
    valid_scan_types = ['quick', 'quick_plus', 'intense', 'complete', 'discover_hostname']
    if scan_type not in valid_scan_types:
        scan_type = 'complete'
    
    response = StreamingHttpResponse(
        scan_host_ip_stream(host_id, ip_address, scan_type=scan_type),
        content_type='text/event-stream'
    )
    response['Cache-Control'] = 'no-cache'
    response['X-Accel-Buffering'] = 'no'  # Disable nginx buffering
    return response


@require_http_methods(["POST"])
@login_required
@setup_required
def host_rescan(request, host_id):
    """Queue a quick discovery scan for the host (first IP). Returns 202; scan runs in background."""
    host = get_object_or_404(Host, id=host_id)
    ip_obj = host.ip_addresses.first()
    if not ip_obj:
        return JsonResponse({'error': 'Host has no IP address'}, status=400)
    ip_address = ip_obj.ip

    def run_scan():
        for _ in scan_host_ip_stream(host_id, ip_address, scan_type='quick'):
            pass

    threading.Thread(target=run_scan, daemon=True).start()
    return JsonResponse({'status': 'queued', 'message': f'Quick discovery queued for {host.name}'}, status=202)


@require_http_methods(["GET"])
@login_required
@setup_required
def host_status(request, host_id):
    """Return host status (is_active) for polling after rescan."""
    host = get_object_or_404(Host, id=host_id)
    return JsonResponse({'id': host.id, 'is_active': host.is_active})


@login_required
@setup_required
def delete_host(request, host_id):
    """Delete a host and all related data (IPs, services, hostnames, etc.)."""
    host = get_object_or_404(Host, id=host_id)
    if request.method == 'POST':
        name = host.name
        host.delete()
        messages.success(request, f'Host "{name}" deleted successfully.')
        return redirect('hosts')
    # GET: show confirmation or redirect
    return redirect('edit_host', host_id=host_id)


@login_required
@setup_required
def merge_duplicates(request):
    """Merge duplicate hosts."""
    from django.core.management import call_command
    from io import StringIO
    
    if request.method == 'POST':
        dry_run = request.POST.get('dry_run') == 'on'
        
        output = StringIO()
        try:
            call_command('merge_duplicates', dry_run=dry_run, stdout=output)
            output_text = output.getvalue()
            messages.success(request, 'Merge completed successfully')
        except Exception as e:
            messages.error(request, f'Error merging duplicates: {str(e)}')
            output_text = str(e)
        
        return render(request, 'inventory/merge_duplicates.html', {
            'output': output_text,
            'dry_run': dry_run,
        })
    
    return render(request, 'inventory/merge_duplicates.html')


@require_http_methods(["POST"])
@login_required
@setup_required
def delete_alert(request, alert_id):
    """Delete a single alert."""
    alert = get_object_or_404(Alert, id=alert_id)
    alert.delete()
    messages.success(request, 'Alert deleted successfully.')
    return redirect('alerts')


@require_http_methods(["POST"])
@login_required
@setup_required
def delete_all_alerts(request):
    """Delete all alerts."""
    try:
        count = Alert.objects.count()
        Alert.objects.all().delete()
        messages.success(request, f'{count} alert(s) deleted successfully.')
    except Exception as e:
        logger.error(f"Error deleting all alerts: {e}")
        messages.error(request, f'Error deleting alerts: {str(e)}')
    return redirect('alerts')


@login_required
@setup_required
def alerts_list(request):
    """List all alerts."""
    alerts = Alert.objects.select_related('related_host', 'related_ip').all()
    
    type_filter = request.GET.get('type')
    if type_filter:
        alerts = alerts.filter(type=type_filter)
    
    return render(request, 'inventory/alerts.html', {
        'alerts': alerts,
        'type_filter': type_filter,
    })


@login_required
@setup_required
def export_hosts_csv(request):
    """Export hosts as CSV."""
    hosts = Host.objects.prefetch_related('ip_addresses', 'interfaces', 'services').all()
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="hosts.csv"'
    
    writer = csv.writer(response)
    writer.writerow([
        'Name', 'MAC', 'Vendor', 'Device Type', 'Source',
        'IP Addresses', 'Medium', 'SSID', 'Services',
        'First Seen', 'Last Seen', 'Active'
    ])
    
    for host in hosts:
        ips = ', '.join([ip.ip for ip in host.ip_addresses.all()])
        interfaces = host.interfaces.all()
        medium = ', '.join([i.get_medium_display() for i in interfaces])
        ssid = ', '.join([i.ssid for i in interfaces if i.ssid])
        services = ', '.join([f"{s.port}/{s.proto}" for s in host.services.all()])
        
        writer.writerow([
            host.name,
            host.mac or '',
            host.vendor or '',
            host.device_type,
            host.get_source_display(),
            ips,
            medium,
            ssid,
            services,
            host.first_seen,
            host.last_seen,
            host.is_active,
        ])
    
    return response


@login_required
@setup_required
def export_services_csv(request):
    """Export services as CSV."""
    services = Service.objects.select_related('host').all()
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="services.csv"'
    
    writer = csv.writer(response)
    writer.writerow([
        'Host', 'Port', 'Protocol', 'Name', 'Product', 'Version', 'Extra Info',
        'First Seen', 'Last Seen'
    ])
    
    for service in services:
        writer.writerow([
            service.host.name,
            service.port,
            service.proto,
            service.name,
            service.product,
            service.version,
            service.extra_info,
            service.first_seen,
            service.last_seen,
        ])
    
    return response


@login_required
@setup_required
def tasks_view(request):
    """View for running tasks and viewing results."""
    from inventory.models import TaskExecution
    from inventory.config_manager import (
        get_discovery_interval,
        get_service_scan_interval,
        get_proxmox_sync_interval,
        get_adguard_sync_interval,
    )
    from django.utils import timezone
    from datetime import timedelta
    
    # Get last executions for each task
    last_discovery = TaskExecution.get_last_execution('scan_discovery')
    last_services = TaskExecution.get_last_execution('scan_services')
    last_proxmox = TaskExecution.get_last_execution('sync_proxmox')
    last_adguard = TaskExecution.get_last_execution('sync_adguard')
    
    # Get intervals
    discovery_interval = get_discovery_interval()  # minutes
    service_interval = get_service_scan_interval()
    proxmox_interval = get_proxmox_sync_interval()
    adguard_interval = get_adguard_sync_interval()
    
    # Calculate next execution times with offsets (staggered by 20 minutes)
    def get_next_execution_with_offset(last_exec, interval_seconds, offset_minutes):
        """Calculate next execution time with offset (e.g., at minute 0, 20, or 40 of each hour)."""
        if not last_exec or not last_exec.completed_at:
            return None
        
        from zoneinfo import ZoneInfo
        madrid_tz = ZoneInfo('Europe/Madrid')
        now_madrid = timezone.now().astimezone(madrid_tz)
        last_exec_madrid = last_exec.completed_at.astimezone(madrid_tz)
        
        # Get current time components
        current_hour = now_madrid.hour
        current_minute = now_madrid.minute
        current_second = now_madrid.second
        
        # Calculate target minute for this hour
        target_minute = offset_minutes
        
        # Calculate next execution time
        if current_minute < target_minute or (current_minute == target_minute and current_second < 0):
            # Target is later today
            next_exec = now_madrid.replace(minute=target_minute, second=0, microsecond=0)
        else:
            # Target is in next hour
            next_exec = now_madrid.replace(hour=(current_hour + 1) % 24, minute=target_minute, second=0, microsecond=0)
            if next_exec.hour < current_hour:  # Wrapped to next day
                next_exec = next_exec + timedelta(days=1)
        
        return next_exec
    
    # Offsets: Discovery at minute 0, Services at minute 20, Proxmox at minute 40, AdGuard at minute 50
    next_discovery = get_next_execution_with_offset(last_discovery, discovery_interval * 60, 0) if last_discovery else None
    next_services = get_next_execution_with_offset(last_services, service_interval, 20) if last_services else None
    next_proxmox = get_next_execution_with_offset(last_proxmox, proxmox_interval, 40) if last_proxmox else None
    next_adguard = get_next_execution_with_offset(last_adguard, adguard_interval * 60, 50) if last_adguard else None
    
    # Initial batch of executions for the table (infinite scroll loads more), with optional filters
    EXECUTIONS_PAGE_SIZE = 25
    filter_task_name = request.GET.get('task_name', '').strip()
    filter_status = request.GET.get('status', '').strip().lower()
    executions_qs = TaskExecution.objects.all().order_by('-started_at')
    if filter_task_name:
        executions_qs = executions_qs.filter(task_name=filter_task_name)
    if filter_status == 'completed':
        executions_qs = executions_qs.filter(status__in=['success', 'error'])
    elif filter_status in ('pending', 'running'):
        executions_qs = executions_qs.filter(status='running')
    elif filter_status and filter_status not in ('all', ''):
        executions_qs = executions_qs.filter(status=filter_status)
    recent_executions = []
    for exec in executions_qs[:EXECUTIONS_PAGE_SIZE]:
        duration_str = None
        if exec.completed_at and exec.started_at:
            delta = exec.completed_at - exec.started_at
            total_seconds = delta.total_seconds()
            duration_str = format_duration(total_seconds)
        recent_executions.append({
            'exec': exec,
            'duration': duration_str,
        })
    
    # Check if any task is currently running
    running_tasks = TaskExecution.objects.filter(status='running')
    
    context = {
        'last_discovery': last_discovery,
        'last_services': last_services,
        'last_proxmox': last_proxmox,
        'last_adguard': last_adguard,
        'next_discovery': next_discovery,
        'next_services': next_services,
        'next_proxmox': next_proxmox,
        'next_adguard': next_adguard,
        'discovery_interval': discovery_interval,
        'service_interval': service_interval,
        'proxmox_interval': proxmox_interval,
        'adguard_interval': adguard_interval,
        'recent_executions': recent_executions,
        'running_tasks': running_tasks,
        'executions_page_size': EXECUTIONS_PAGE_SIZE,
        'filter_task_name': filter_task_name,
        'filter_status': filter_status,
        'task_choices': TaskExecution.TASK_CHOICES,
    }
    
    return render(request, 'inventory/tasks.html', context)


@login_required
@setup_required
def task_executions_list_api(request):
    """API: paginated task executions for infinite scroll (JSON). Supports task_name and status filters."""
    offset = int(request.GET.get('offset', 0))
    limit = min(int(request.GET.get('limit', 25)), 100)
    task_name = request.GET.get('task_name', '').strip()
    status_filter = request.GET.get('status', '').strip().lower()

    qs = TaskExecution.objects.all().order_by('-started_at')
    if task_name:
        qs = qs.filter(task_name=task_name)
    if status_filter == 'completed':
        qs = qs.filter(status__in=['success', 'error'])
    elif status_filter == 'pending' or status_filter == 'running':
        qs = qs.filter(status='running')
    elif status_filter and status_filter not in ('all', ''):
        qs = qs.filter(status=status_filter)

    total = qs.count()
    qs = qs[offset:offset + limit]
    has_more = offset + limit < total
    executions = []
    from zoneinfo import ZoneInfo
    madrid_tz = ZoneInfo('Europe/Madrid')
    for exec in qs:
        duration_str = None
        if exec.completed_at and exec.started_at:
            delta = exec.completed_at - exec.started_at
            duration_str = format_duration(delta.total_seconds())
        started_at_str = '—'
        if exec.started_at:
            started_dt = exec.started_at
            if getattr(started_dt, 'tzinfo', None) and started_dt.tzinfo:
                started_at_str = started_dt.astimezone(madrid_tz).strftime('%H:%M:%S')
            else:
                started_at_str = started_dt.strftime('%H:%M:%S')
        executions.append({
            'id': exec.id,
            'task_name': exec.task_name,
            'task_name_display': exec.get_task_name_display(),
            'status': exec.status,
            'started_at': started_at_str,
            'duration': duration_str or '—',
            'items_processed': exec.items_processed,
        })
    return JsonResponse({'executions': executions, 'has_more': has_more})


@login_required
@setup_required
@require_http_methods(["POST"])
def delete_task_execution(request, task_id):
    """Delete a task execution record."""
    task = get_object_or_404(TaskExecution, id=task_id)
    task.delete()
    messages.success(request, 'Task execution deleted successfully.')
    return redirect('tasks')


class _QueueWriter:
    """Writes to a queue line-by-line so a generator can stream output (used with call_command)."""
    def __init__(self, q):
        self._q = q
        self._buf = ''

    def write(self, s):
        if s is None:
            return
        if not isinstance(s, str):
            s = str(s)
        self._buf += s
        while '\n' in self._buf:
            line, self._buf = self._buf.split('\n', 1)
            line = line.rstrip('\r')
            self._q.put(line)

    def flush(self):
        if self._buf.strip():
            self._q.put(self._buf.strip())
            self._buf = ''

    def close(self):
        self.flush()


def run_command_stream(command_name, *args):
    """Generator that yields command output in real-time. Uses call_command in a thread (same as scheduler)."""
    import time
    from django.core.management import call_command

    if command_name not in ('scan_discovery', 'scan_services', 'sync_proxmox', 'sync_adguard'):
        yield f"data: {json.dumps({'type': 'error', 'message': f'Unknown command: {command_name}'})}\n\n"
        return

    # Resolve CIDR for discovery (same logic as scheduler)
    cidr = '192.168.1.0/24'
    if command_name == 'scan_discovery':
        try:
            from inventory.config_manager import get_discovery_cidr
            cidr = (args[0] if args and len(args) > 0 and isinstance(args[0], str) and '/' in str(args[0]) else None) or get_discovery_cidr()
        except Exception:
            cidr = '192.168.1.0/24'
        if not cidr or '/' not in cidr:
            cidr = '192.168.1.0/24'

    yield f"data: {json.dumps({'type': 'start', 'command': command_name})}\n\n"

    output_queue = queue.Queue()
    writer = _QueueWriter(output_queue)
    command_error = [None]  # use list so thread can set from inner scope

    def run_in_thread():
        try:
            if command_name == 'scan_discovery':
                call_command('scan_discovery', '--cidr', cidr, verbosity=1, stdout=writer, stderr=writer)
            elif command_name == 'scan_services':
                call_command('scan_services', '--targets', 'from_db', '--top-ports', '200', '--version-detect', verbosity=1, stdout=writer, stderr=writer)
            elif command_name == 'sync_proxmox':
                call_command('sync_proxmox', verbosity=1, stdout=writer, stderr=writer)
            elif command_name == 'sync_adguard':
                call_command('sync_adguard', verbosity=1, stdout=writer, stderr=writer)
            else:
                command_error[0] = f'Unknown command: {command_name}'
        except Exception as e:
            logger.error("run_command_stream thread error: %s", e, exc_info=True)
            command_error[0] = str(e)
        finally:
            try:
                writer.close()
            except Exception:
                pass
            output_queue.put(None)  # sentinel

    thread = threading.Thread(target=run_in_thread, daemon=True)
    thread.start()

    last_heartbeat = time.monotonic()
    heartbeat_interval = 15
    done = False

    while not done:
        try:
            line = output_queue.get(timeout=0.2)
            if line is None:
                done = True
                break
            yield f"data: {json.dumps({'type': 'output', 'line': line})}\n\n"
            last_heartbeat = time.monotonic()
        except queue.Empty:
            pass
        now = time.monotonic()
        if now - last_heartbeat >= heartbeat_interval:
            yield ": keepalive\n\n"
            last_heartbeat = now

    thread.join(timeout=0.5)

    if command_error[0]:
        yield f"data: {json.dumps({'type': 'error', 'message': command_error[0]})}\n\n"
    else:
        yield f"data: {json.dumps({'type': 'success', 'message': 'Command completed successfully'})}\n\n"


@require_http_methods(["POST"])
@login_required
@setup_required
def run_command(request):
    """API endpoint to run a command and stream output."""
    try:
        data = json.loads(request.body)
        command_name = data.get('command')
        
        if not command_name:
            return JsonResponse({'error': 'Command name required'}, status=400)

        # Normalize args: must be a list (frontend sends none; API might send string for single cidr)
        args = data.get('args', [])
        if isinstance(args, str):
            args = [args]
        if not isinstance(args, list):
            args = []

        response = StreamingHttpResponse(
            run_command_stream(command_name, *args),
            content_type='text/event-stream'
        )
        response['Cache-Control'] = 'no-cache'
        response['X-Accel-Buffering'] = 'no'  # Disable nginx buffering
        return response
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["POST"])
@login_required
@setup_required
def telegram_test_notification(request):
    """Simulate a new IP or new service notification to test Telegram."""
    from inventory.services.telegram import send_telegram, escape_telegram_html, inline_keyboard_setname
    try:
        data = json.loads(request.body) if request.body else {}
        notif_type = (data.get('type') or '').strip().lower()
        if notif_type not in ('new_ip', 'new_service'):
            return JsonResponse({'error': 'type must be "new_ip" or "new_service"'}, status=400)

        if notif_type == 'new_ip':
            message_parts = [
                "🔍 <b>New IP Detected</b> (test)",
                "",
                "<b>IP:</b> <code>192.168.1.99</code>",
                "<b>Hostname:</b> <code>test-device.local</code>",
                "<b>MAC:</b> <code>aa:bb:cc:dd:ee:ff</code> (Vendor Inc.)",
                "<b>OS:</b> Linux 4.x (accuracy: 95%)",
                "<b>Open Ports/Services:</b>",
                "  • <code>22/tcp</code> - ssh (OpenSSH 8.2)",
                "  • <code>80/tcp</code> - http (nginx 1.18)",
                f"<b>Time:</b> {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ]
            text = "\n".join(message_parts)
            reply_markup = inline_keyboard_setname('192.168.1.99')
        else:
            text = (
                "🔌 <b>New Service Detected</b> (test)\n"
                "Host: <code>test-server</code>\n"
                "Service: <code>443/tcp</code> (https)\n"
                f"Product: nginx 1.20\n"
                f"Time: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            reply_markup = inline_keyboard_setname('192.168.1.99')
        ok = send_telegram(text, reply_markup=reply_markup)
        return JsonResponse({'ok': ok, 'message': 'Notification sent' if ok else 'No Telegram integration enabled'})
    except Exception as e:
        logger.exception("telegram_test_notification failed")
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def telegram_webhook(request, integration_id):
    """Receive Telegram bot updates (set this URL as webhook for the bot)."""
    from inventory.telegram_bot import handle_update
    integration = get_object_or_404(IntegrationConfig, pk=integration_id, name='telegram')
    if not integration.enabled:
        return HttpResponse(status=200)
    try:
        update = json.loads(request.body)
        handle_update(integration, update)
    except Exception as e:
        logger.exception("Telegram webhook error: %s", e)
    return HttpResponse(status=200)


@login_required
@setup_required
def telegram_set_webhook(request, integration_id):
    """Register the Telegram webhook URL for this integration (redirect back to settings)."""
    import requests
    integration = get_object_or_404(IntegrationConfig, pk=integration_id, name='telegram')
    token = integration.get_config('bot_token', '').strip()
    if not token:
        messages.error(request, 'Bot token not configured.')
        return redirect('settings_index')
    url = request.build_absolute_uri(f'/api/telegram/webhook/{integration_id}/')
    try:
        r = requests.post(f'https://api.telegram.org/bot{token}/setWebhook', json={'url': url}, timeout=10)
        r.raise_for_status()
        data = r.json()
        if data.get('ok'):
            messages.success(request, f'Webhook set to {url}')
        else:
            messages.error(request, data.get('description', 'Unknown error'))
    except requests.RequestException as e:
        messages.error(request, str(e))
    return redirect('integration_edit', pk=integration_id)
