"""
Django admin configuration for inventory models.
"""
from django.utils.html import format_html
from django.urls import path, reverse
from django.shortcuts import redirect
from django.contrib import messages
from django import forms
from django.contrib import admin
from .models import (
    Host, InterfaceAttachment, IPAddress, Service, Alert,
    SystemConfig, IntegrationConfig, TaskExecution, Hostname
)
from .services.telegram import send_telegram
from .services.proxmox_client import get_proxmox_client
from .services.adguard_client import get_adguard_client
from .config_manager import ConfigManager
import logging
import requests

logger = logging.getLogger(__name__)

# Ocultar InterfaceAttachment del admin
admin.site.unregister(InterfaceAttachment) if InterfaceAttachment in admin.site._registry else None


class IntegrationConfigForm(forms.ModelForm):
    """Form for integration configuration."""
    
    # Telegram fields
    telegram_bot_token = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={'style': 'width: 100%;'}),
        help_text="Telegram bot token from @BotFather"
    )
    telegram_chat_id = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'style': 'width: 100%;'}),
        help_text="Telegram chat ID"
    )
    
    # Proxmox fields
    proxmox_url = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'style': 'width: 100%;'}),
        help_text="Proxmox URL (e.g., https://proxmox:8006)"
    )
    proxmox_token_id = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'style': 'width: 100%;'}),
        help_text="Proxmox token ID (e.g., user@pam!token_name)"
    )
    proxmox_token_secret = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={'style': 'width: 100%;'}),
        help_text="Proxmox token secret"
    )
    proxmox_node = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'style': 'width: 100%;'}),
        help_text="Proxmox node name (optional)"
    )
    
    # AdGuard Home fields
    adguard_url = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'style': 'width: 100%;'}),
        help_text="AdGuard Home URL (e.g., https://adguard:80)"
    )
    adguard_username = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'style': 'width: 100%;'}),
        help_text="AdGuard Home username"
    )
    adguard_password = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={'style': 'width: 100%;'}),
        help_text="AdGuard Home password"
    )
    
    
    class Meta:
        model = IntegrationConfig
        fields = ['name', 'enabled']
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            config = self.instance.config_data
            if self.instance.name == 'telegram':
                self.fields['telegram_bot_token'].initial = config.get('bot_token', '')
                self.fields['telegram_chat_id'].initial = config.get('chat_id', '')
            elif self.instance.name == 'proxmox':
                self.fields['proxmox_url'].initial = config.get('url', '')
                self.fields['proxmox_token_id'].initial = config.get('token_id', '')
                self.fields['proxmox_token_secret'].initial = config.get('token_secret', '')
                self.fields['proxmox_node'].initial = config.get('node', '')
            elif self.instance.name == 'adguard':
                self.fields['adguard_url'].initial = config.get('url', '')
                self.fields['adguard_username'].initial = config.get('username', '')
                self.fields['adguard_password'].initial = config.get('password', '')
    
    def save(self, commit=True):
        instance = super().save(commit=False)
        if self.instance.name == 'telegram':
            instance.config_data['bot_token'] = self.cleaned_data.get('telegram_bot_token', '')
            instance.config_data['chat_id'] = self.cleaned_data.get('telegram_chat_id', '')
        elif self.instance.name == 'proxmox':
            instance.config_data['url'] = self.cleaned_data.get('proxmox_url', '')
            instance.config_data['token_id'] = self.cleaned_data.get('proxmox_token_id', '')
            instance.config_data['token_secret'] = self.cleaned_data.get('proxmox_token_secret', '')
            instance.config_data['node'] = self.cleaned_data.get('proxmox_node', '')
        elif self.instance.name == 'adguard':
            instance.config_data['url'] = self.cleaned_data.get('adguard_url', '')
            instance.config_data['username'] = self.cleaned_data.get('adguard_username', '')
            instance.config_data['password'] = self.cleaned_data.get('adguard_password', '')
        
        if commit:
            instance.save()
        return instance


@admin.register(IntegrationConfig)
class IntegrationConfigAdmin(admin.ModelAdmin):
    from .admin_forms import TelegramIntegrationForm, ProxmoxIntegrationForm, AdGuardIntegrationForm
    
    list_display = ['name', 'enabled', 'status_badge', 'last_test', 'test_button']
    list_filter = ['enabled', 'name', 'last_test_result']
    search_fields = ['name']
    readonly_fields = ['name', 'last_test', 'last_test_result', 'last_test_message', 'updated_at', 'test_button']
    
    def get_form(self, request, obj=None, **kwargs):
        """Usar formulario específico según el tipo de integración."""
        if obj and obj.name == 'telegram':
            return TelegramIntegrationForm
        elif obj and obj.name == 'proxmox':
            return ProxmoxIntegrationForm
        elif obj and obj.name == 'adguard':
            return AdGuardIntegrationForm
        return super().get_form(request, obj, **kwargs)
    
    def get_fieldsets(self, request, obj=None):
        """Fieldsets dinámicos según el tipo de integración."""
        if obj and obj.name == 'telegram':
            return (
                ('Telegram Integration', {
                    'fields': ('enabled', 'bot_token', 'chat_id'),
                    'description': 'Configure your Telegram bot to receive notifications from BANKAI.'
                }),
                ('Test Connection', {
                    'fields': ('test_button', 'last_test', 'last_test_result', 'last_test_message'),
                }),
            )
        elif obj and obj.name == 'proxmox':
            return (
                ('Proxmox Integration', {
                    'fields': ('enabled', 'url', 'token_id', 'token_secret', 'node'),
                    'description': 'Connect BANKAI to your Proxmox server to automatically import VMs and containers.'
                }),
                ('Test Connection', {
                    'fields': ('test_button', 'last_test', 'last_test_result', 'last_test_message'),
                }),
            )
        elif obj and obj.name == 'adguard':
            return (
                ('AdGuard Home Integration', {
                    'fields': ('enabled', 'url', 'username', 'password', 'default_tags'),
                    'description': 'Sync BANKAI hosts to AdGuard Home as persistent clients.'
                }),
                ('Test Connection', {
                    'fields': ('test_button', 'last_test', 'last_test_result', 'last_test_message'),
                }),
            )
        return (
            ('Basic', {
                'fields': ('name', 'enabled')
            }),
        )
    
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                '<int:integration_id>/test/',
                admin.site.admin_view(self.test_integration),
                name='inventory_integrationconfig_test',
            ),
        ]
        return custom_urls + urls
    
    def test_integration(self, request, integration_id):
        """Test integration connection."""
        try:
            integration = IntegrationConfig.objects.get(pk=integration_id)
            result = False
            message = ""
            
            if integration.name == 'telegram':
                result, message = self._test_telegram(integration)
            elif integration.name == 'proxmox':
                result, message = self._test_proxmox(integration)
            elif integration.name == 'adguard':
                result, message = self._test_adguard(integration)
            else:
                message = "Unknown integration type"
            
            # Update integration with test results
            from django.utils import timezone
            integration.last_test = timezone.now()
            integration.last_test_result = result
            integration.last_test_message = message
            integration.save()
            
            if result:
                messages.success(request, f"✓ Test successful: {message}")
            else:
                messages.error(request, f"✗ Test failed: {message}")
                
        except Exception as e:
            logger.error(f"Error testing integration: {e}")
            messages.error(request, f"Error testing integration: {str(e)}")
        
        return redirect('admin:inventory_integrationconfig_change', integration_id)
    
    def _test_telegram(self, integration):
        """Test Telegram integration."""
        bot_token = integration.get_config('bot_token', '')
        chat_id = integration.get_config('chat_id', '')
        
        if not bot_token or not chat_id:
            return False, "Bot token or chat ID not configured"
        
        # Temporarily set in settings for test
        from django.conf import settings
        original_token = getattr(settings, 'TELEGRAM_BOT_TOKEN', '')
        original_chat = getattr(settings, 'TELEGRAM_CHAT_ID', '')
        
        settings.TELEGRAM_BOT_TOKEN = bot_token
        settings.TELEGRAM_CHAT_ID = chat_id
        
        try:
            result = send_telegram("🧪 BANKAI Integration Test - Connection successful!")
            if result:
                return True, "Telegram notification sent successfully"
            else:
                return False, "Failed to send Telegram message"
        except Exception as e:
            return False, f"Error: {str(e)}"
        finally:
            settings.TELEGRAM_BOT_TOKEN = original_token
            settings.TELEGRAM_CHAT_ID = original_chat
    
    def _test_proxmox(self, integration):
        """Test Proxmox integration."""
        url = integration.get_config('url', '')
        token_id = integration.get_config('token_id', '')
        token_secret = integration.get_config('token_secret', '')
        
        if not all([url, token_id, token_secret]):
            return False, "Proxmox credentials not fully configured"
        
        # Temporarily set in settings
        from django.conf import settings
        original_url = getattr(settings, 'PROXMOX_URL', '')
        original_token_id = getattr(settings, 'PROXMOX_TOKEN_ID', '')
        original_token_secret = getattr(settings, 'PROXMOX_TOKEN_SECRET', '')
        
        settings.PROXMOX_URL = url
        settings.PROXMOX_TOKEN_ID = token_id
        settings.PROXMOX_TOKEN_SECRET = token_secret
        
        try:
            client = get_proxmox_client()
            if client:
                # Try to get nodes
                nodes = client.nodes.get()
                return True, f"Connected successfully. Found {len(nodes)} node(s)"
            else:
                return False, "Failed to create Proxmox client"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
        finally:
            settings.PROXMOX_URL = original_url
            settings.PROXMOX_TOKEN_ID = original_token_id
            settings.PROXMOX_TOKEN_SECRET = original_token_secret
    
    def _test_adguard(self, integration):
        """Test AdGuard Home integration."""
        url = integration.get_config('url', '')
        username = integration.get_config('username', '')
        password = integration.get_config('password', '')
        
        if not all([url, username, password]):
            return False, "AdGuard Home credentials not fully configured"
        
        # Temporarily set in config for test
        from django.conf import settings
        original_url = getattr(settings, 'ADGUARD_URL', '')
        original_username = getattr(settings, 'ADGUARD_USERNAME', '')
        original_password = getattr(settings, 'ADGUARD_PASSWORD', '')
        
        # Set temporary config values
        integration.config_data['url'] = url
        integration.config_data['username'] = username
        integration.config_data['password'] = password
        integration.save()
        
        try:
            session = get_adguard_client()
            if session:
                # Try to get status
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
            else:
                return False, "Failed to create AdGuard Home client (check URL and credentials)"
        except requests.exceptions.ConnectionError as e:
            return False, f"Connection error: Cannot reach AdGuard Home at {url}"
        except requests.exceptions.Timeout as e:
            return False, f"Connection timeout: AdGuard Home did not respond"
        except Exception as e:
            return False, f"Error: {str(e)}"
        finally:
            # Restore original config
            if original_url:
                integration.config_data['url'] = original_url
            if original_username:
                integration.config_data['username'] = original_username
            if original_password:
                integration.config_data['password'] = original_password
            integration.save()
    
    def status_badge(self, obj):
        """Show status badge."""
        if obj.enabled:
            return format_html('<span style="color: green; font-weight: bold;">● Enabled</span>')
        return format_html('<span style="color: red; font-weight: bold;">● Disabled</span>')
    status_badge.short_description = 'Status'
    
    def test_button(self, obj):
        """Show test button."""
        if obj.pk:
            url = reverse('admin:inventory_integrationconfig_test', args=[obj.pk])
            return format_html(
                '<a class="button" href="{}" style="background: #417690; color: white; padding: 10px 15px; text-decoration: none; border-radius: 4px;">Test Connection</a>',
                url
            )
        return "-"
    test_button.short_description = 'Actions'
    
    def last_test_result_badge(self, obj):
        """Show last test result."""
        if obj.last_test_result is None:
            return format_html('<span style="color: gray;">Not tested</span>')
        if obj.last_test_result:
            return format_html('<span style="color: green; font-weight: bold;">✓ Success</span>')
        return format_html('<span style="color: red; font-weight: bold;">✗ Failed</span>')
    last_test_result_badge.short_description = 'Last Test'


class SchedulerConfigForm(forms.Form):
    """Form for scheduler configuration."""
    # Start time (hour:minute)
    scheduler_start_hour = forms.IntegerField(
        min_value=0, max_value=23,
        help_text="Hour when tasks start (0-23)",
        widget=forms.NumberInput(attrs={'style': 'width: 100px;'})
    )
    scheduler_start_minute = forms.IntegerField(
        min_value=0, max_value=59,
        help_text="Minute when tasks start (0-59)",
        widget=forms.NumberInput(attrs={'style': 'width: 100px;'})
    )
    
    # Task intervals (in minutes)
    discovery_interval = forms.IntegerField(
        min_value=1,
        help_text="Discovery scan interval in minutes",
        widget=forms.NumberInput(attrs={'style': 'width: 150px;'})
    )
    service_scan_interval = forms.IntegerField(
        min_value=1,
        help_text="Service scan interval in minutes",
        widget=forms.NumberInput(attrs={'style': 'width: 150px;'})
    )
    proxmox_sync_interval = forms.IntegerField(
        min_value=1,
        help_text="Proxmox sync interval in minutes",
        widget=forms.NumberInput(attrs={'style': 'width: 150px;'})
    )
    adguard_sync_interval = forms.IntegerField(
        min_value=1,
        help_text="AdGuard Home sync interval in minutes",
        widget=forms.NumberInput(attrs={'style': 'width: 150px;'})
    )
    
    # Delays between tasks (in minutes)
    discovery_delay = forms.IntegerField(
        min_value=0,
        help_text="Delay after start time for Discovery (minutes)",
        widget=forms.NumberInput(attrs={'style': 'width: 150px;'})
    )
    service_delay = forms.IntegerField(
        min_value=0,
        help_text="Delay after start time for Service Scan (minutes)",
        widget=forms.NumberInput(attrs={'style': 'width: 150px;'})
    )
    proxmox_delay = forms.IntegerField(
        min_value=0,
        help_text="Delay after start time for Proxmox Sync (minutes)",
        widget=forms.NumberInput(attrs={'style': 'width: 150px;'})
    )
    adguard_delay = forms.IntegerField(
        min_value=0,
        help_text="Delay after start time for AdGuard Sync (minutes)",
        widget=forms.NumberInput(attrs={'style': 'width: 150px;'})
    )


@admin.register(SystemConfig)
class SystemConfigAdmin(admin.ModelAdmin):
    from .admin_forms import SystemConfigForm, FRIENDLY_NAMES
    form = SystemConfigForm
    list_display = ['friendly_name', 'value_preview', 'description', 'updated_at']
    search_fields = ['key', 'description']
    list_filter = ['updated_at']
    fields = ['key', 'value', 'description']
    
    def friendly_name(self, obj):
        """Mostrar nombre amigable en lugar de la clave técnica."""
        from .admin_forms import FRIENDLY_NAMES
        return FRIENDLY_NAMES.get(obj.key, obj.key)
    friendly_name.short_description = 'Configuration'
    
    def changelist_view(self, request, extra_context=None):
        """Add scheduler config link to changelist."""
        extra_context = extra_context or {}
        extra_context['scheduler_config_url'] = reverse('admin:inventory_systemconfig_scheduler_config')
        return super().changelist_view(request, extra_context=extra_context)
    
    def value_preview(self, obj):
        """Show truncated value."""
        if len(obj.value) > 50:
            return f"{obj.value[:50]}..."
        return obj.value
    value_preview.short_description = 'Value'
    
    def get_fieldsets(self, request, obj=None):
        """Group scan interval configs together."""
        if obj and obj.key in ['DISCOVERY_INTERVAL', 'SERVICE_SCAN_INTERVAL', 'PROXMOX_SYNC_INTERVAL', 'ADGUARD_SYNC_INTERVAL']:
            return (
                ('Configuration', {
                    'fields': ('key', 'value', 'description'),
                    'description': 'Interval in minutes for all scan intervals'
                }),
            )
        return super().get_fieldsets(request, obj)
    
    def get_urls(self):
        urls = super().get_urls()
        from django.urls import path
        custom_urls = [
            path(
                'scheduler-config/',
                admin.site.admin_view(self.scheduler_config_view),
                name='inventory_systemconfig_scheduler_config',
            ),
        ]
        return custom_urls + urls
    
    def scheduler_config_view(self, request):
        """Custom view for scheduler configuration."""
        from django.template.response import TemplateResponse
        from django.contrib.admin import site
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
                return redirect('admin:inventory_systemconfig_scheduler_config')
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
            **site.each_context(request),
            'title': 'Scheduler Configuration',
            'form': form,
            'opts': SystemConfig._meta,
            'has_view_permission': True,
        }
        return TemplateResponse(request, 'admin/inventory/scheduler_config.html', context)


@admin.register(TaskExecution)
class TaskExecutionAdmin(admin.ModelAdmin):
    list_display = ['task_name', 'status_badge', 'started_at', 'completed_at', 'duration', 'items_processed']
    list_filter = ['task_name', 'status', 'started_at']
    search_fields = ['task_name', 'error_message']
    readonly_fields = ['started_at', 'completed_at', 'status', 'output', 'error_message', 'items_processed']
    date_hierarchy = 'started_at'
    ordering = ['-started_at']
    
    def status_badge(self, obj):
        """Show status badge."""
        if obj.status == 'success':
            return format_html('<span style="color: green; font-weight: bold;">✓ Success</span>')
        elif obj.status == 'error':
            return format_html('<span style="color: red; font-weight: bold;">✗ Error</span>')
        else:
            return format_html('<span style="color: orange; font-weight: bold;">⏳ Running</span>')
    status_badge.short_description = 'Status'
    
    def duration(self, obj):
        """Calculate duration in human-readable format."""
        from inventory.views import format_duration
        if obj.completed_at and obj.started_at:
            delta = obj.completed_at - obj.started_at
            total_seconds = delta.total_seconds()
            formatted = format_duration(total_seconds)
            return formatted if formatted else "—"
        return "—"
    duration.short_description = 'Duration'
    
    fieldsets = (
        ('Task Info', {
            'fields': ('task_name', 'status', 'started_at', 'completed_at', 'duration')
        }),
        ('Results', {
            'fields': ('items_processed', 'output', 'error_message')
        }),
    )


class IPAddressInline(admin.TabularInline):
    """Inline admin for IP addresses."""
    model = IPAddress
    extra = 0
    readonly_fields = ['first_seen', 'last_seen']
    fields = ['ip', 'assignment', 'online', 'first_seen', 'last_seen']
    can_delete = True


class ServiceInline(admin.TabularInline):
    """Inline admin for services."""
    model = Service
    extra = 0
    readonly_fields = ['first_seen', 'last_seen']
    fields = ['port', 'proto', 'name', 'product', 'version', 'first_seen', 'last_seen']
    can_delete = True


class HostnameInline(admin.TabularInline):
    """Inline admin for hostnames."""
    model = Hostname
    extra = 0
    readonly_fields = ['first_seen', 'last_seen']
    fields = ['name', 'source_type', 'first_seen', 'last_seen']
    can_delete = True


@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = ['name', 'mac', 'vendor', 'device_type', 'source', 'is_active', 'last_seen']
    list_filter = ['source', 'device_type', 'is_active', 'first_seen']
    search_fields = ['name', 'mac', 'vendor']
    readonly_fields = ['first_seen', 'last_seen']
    inlines = [IPAddressInline, ServiceInline, HostnameInline]
    fieldsets = (
        ('Basic Info', {
            'fields': ('name', 'mac', 'vendor', 'device_type', 'source')
        }),
        ('Status', {
            'fields': ('is_active', 'first_seen', 'last_seen')
        }),
        ('Notes', {
            'fields': ('notes',)
        }),
    )


# InterfaceAttachment - No se muestra en admin (no aporta valor según usuario)
# @admin.register(InterfaceAttachment)
# class InterfaceAttachmentAdmin(admin.ModelAdmin):
#     pass


# IPAddress, Service, Hostname ahora están como inlines en HostAdmin
# Se mantienen registrados por si se necesitan acceder directamente, pero no aparecen en el índice
@admin.register(IPAddress)
class IPAddressAdmin(admin.ModelAdmin):
    list_display = ['ip', 'host', 'assignment', 'online', 'last_seen']
    list_filter = ['assignment', 'online', 'first_seen']
    search_fields = ['ip', 'host__name']
    readonly_fields = ['first_seen', 'last_seen']
    
    def get_model_perms(self, request):
        """Ocultar del índice del admin."""
        return {}


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ['host', 'port', 'proto', 'name', 'product', 'last_seen']
    list_filter = ['proto', 'name', 'first_seen']
    search_fields = ['host__name', 'name', 'product', 'port']
    readonly_fields = ['first_seen', 'last_seen']
    
    def get_model_perms(self, request):
        """Ocultar del índice del admin."""
        return {}


@admin.register(Hostname)
class HostnameAdmin(admin.ModelAdmin):
    list_display = ['name', 'host', 'source_type', 'first_seen', 'last_seen']
    list_filter = ['source_type', 'first_seen']
    search_fields = ['name', 'host__name']
    readonly_fields = ['first_seen', 'last_seen']
    date_hierarchy = 'first_seen'
    
    def get_model_perms(self, request):
        """Ocultar del índice del admin."""
        return {}


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ['type', 'message', 'related_host', 'related_ip', 'created_at']
    list_filter = ['type', 'created_at']
    search_fields = ['message', 'related_host__name']
    readonly_fields = ['created_at']
    date_hierarchy = 'created_at'
