"""
Custom forms for admin interface.
"""
from django import forms
from .models import SystemConfig, IntegrationConfig
from .config_manager import ConfigManager


class SchedulerConfigForm(forms.Form):
    """Form for scheduler configuration."""
    # Start time (hour:minute)
    scheduler_start_hour = forms.IntegerField(
        min_value=0, max_value=23,
        label="Start Hour",
        help_text="Hour when tasks start (0-23)",
        widget=forms.NumberInput(attrs={'class': 'form-input'})
    )
    scheduler_start_minute = forms.IntegerField(
        min_value=0, max_value=59,
        label="Start Minute",
        help_text="Minute when tasks start (0-59)",
        widget=forms.NumberInput(attrs={'class': 'form-input'})
    )
    
    # Task intervals (in minutes)
    discovery_interval = forms.IntegerField(
        min_value=1,
        label="Discovery Interval (minutes)",
        help_text="Discovery scan interval in minutes",
        widget=forms.NumberInput(attrs={'class': 'form-input'})
    )
    service_scan_interval = forms.IntegerField(
        min_value=1,
        label="Service Scan Interval (minutes)",
        help_text="Service scan interval in minutes",
        widget=forms.NumberInput(attrs={'class': 'form-input'})
    )
    proxmox_sync_interval = forms.IntegerField(
        min_value=1,
        label="Proxmox Sync Interval (minutes)",
        help_text="Proxmox sync interval in minutes",
        widget=forms.NumberInput(attrs={'class': 'form-input'})
    )
    adguard_sync_interval = forms.IntegerField(
        min_value=1,
        label="AdGuard Sync Interval (minutes)",
        help_text="AdGuard Home sync interval in minutes",
        widget=forms.NumberInput(attrs={'class': 'form-input'})
    )
    
    # Delays between tasks (in minutes)
    discovery_delay = forms.IntegerField(
        min_value=0,
        label="Discovery Delay (minutes)",
        help_text="Delay after start time for Discovery (minutes)",
        widget=forms.NumberInput(attrs={'class': 'form-input'})
    )
    service_delay = forms.IntegerField(
        min_value=0,
        label="Service Scan Delay (minutes)",
        help_text="Delay after start time for Service Scan (minutes)",
        widget=forms.NumberInput(attrs={'class': 'form-input'})
    )
    proxmox_delay = forms.IntegerField(
        min_value=0,
        label="Proxmox Sync Delay (minutes)",
        help_text="Delay after start time for Proxmox Sync (minutes)",
        widget=forms.NumberInput(attrs={'class': 'form-input'})
    )
    adguard_delay = forms.IntegerField(
        min_value=0,
        label="AdGuard Sync Delay (minutes)",
        help_text="Delay after start time for AdGuard Sync (minutes)",
        widget=forms.NumberInput(attrs={'class': 'form-input'})
    )


# Mapping de nombres técnicos a nombres amigables
FRIENDLY_NAMES = {
    'DISCOVERY_CIDR': 'Network Range (CIDR)',
    'DISCOVERY_INTERVAL': 'Discovery Scan Interval (minutes)',
    'SERVICE_SCAN_INTERVAL': 'Service Scan Interval (minutes)',
    'PROXMOX_SYNC_INTERVAL': 'Proxmox Sync Interval (minutes)',
    'ADGUARD_SYNC_INTERVAL': 'AdGuard Home Sync Interval (minutes)',
    'NOTIFY_NEW_SERVICE': 'Notify New Services via Telegram',
}


class SystemConfigForm(forms.ModelForm):
    """Formulario amigable para SystemConfig."""
    
    class Meta:
        model = SystemConfig
        fields = ['key', 'value', 'description']
        widgets = {
            'key': forms.TextInput(attrs={
                'class': 'vTextField',
                'readonly': True,
                'style': 'background-color: #f5f5f5;'
            }),
            'value': forms.TextInput(attrs={
                'class': 'vTextField',
                'style': 'width: 100%;'
            }),
            'description': forms.Textarea(attrs={
                'class': 'vLargeTextField',
                'rows': 3,
                'style': 'width: 100%;'
            }),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            # Mostrar nombre amigable si existe
            friendly_name = FRIENDLY_NAMES.get(self.instance.key, self.instance.key)
            if friendly_name != self.instance.key:
                self.fields['key'].help_text = f"Technical key: {self.instance.key}"


class TelegramIntegrationForm(forms.ModelForm):
    """Formulario específico para Telegram."""
    
    bot_token = forms.CharField(
        label='Bot Token',
        required=False,
        widget=forms.PasswordInput(attrs={
            'style': 'width: 100%; padding: 8px;',
            'placeholder': 'Token from @BotFather'
        }),
        help_text='Get your bot token from @BotFather on Telegram'
    )
    chat_id = forms.CharField(
        label='Chat ID',
        required=False,
        widget=forms.TextInput(attrs={
            'style': 'width: 100%; padding: 8px;',
            'placeholder': 'Your Telegram chat ID'
        }),
        help_text='Your Telegram chat ID or channel ID'
    )
    
    class Meta:
        model = IntegrationConfig
        fields = ['display_name', 'enabled']
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            config = self.instance.config_data
            self.fields['bot_token'].initial = config.get('bot_token', '')
            self.fields['chat_id'].initial = config.get('chat_id', '')
    
    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.config_data['bot_token'] = self.cleaned_data.get('bot_token', '')
        instance.config_data['chat_id'] = self.cleaned_data.get('chat_id', '')
        if commit:
            instance.save()
        return instance


class ProxmoxIntegrationForm(forms.ModelForm):
    """Formulario específico para Proxmox."""
    
    url = forms.CharField(
        label='Proxmox URL',
        required=False,
        widget=forms.URLInput(attrs={
            'style': 'width: 100%; padding: 8px;',
            'placeholder': 'https://proxmox.example.com:8006'
        }),
        help_text='Full URL to your Proxmox server (including port)'
    )
    token_id = forms.CharField(
        label='Token ID',
        required=False,
        widget=forms.TextInput(attrs={
            'style': 'width: 100%; padding: 8px;',
            'placeholder': 'user@pam!token_name'
        }),
        help_text='Format: user@pam!token_name'
    )
    token_secret = forms.CharField(
        label='Token Secret',
        required=False,
        widget=forms.PasswordInput(attrs={
            'style': 'width: 100%; padding: 8px;',
            'placeholder': 'Your token secret'
        }),
        help_text='Token secret from Proxmox'
    )
    node = forms.CharField(
        label='Node Name (Optional)',
        required=False,
        widget=forms.TextInput(attrs={
            'style': 'width: 100%; padding: 8px;',
            'placeholder': 'Leave empty to sync all nodes'
        }),
        help_text='Specific node to sync (leave empty for all nodes)'
    )
    
    class Meta:
        model = IntegrationConfig
        fields = ['display_name', 'enabled']
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            config = self.instance.config_data
            self.fields['url'].initial = config.get('url', '')
            self.fields['token_id'].initial = config.get('token_id', '')
            self.fields['token_secret'].initial = config.get('token_secret', '')
            self.fields['node'].initial = config.get('node', '')
    
    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.config_data['url'] = self.cleaned_data.get('url', '')
        instance.config_data['token_id'] = self.cleaned_data.get('token_id', '')
        instance.config_data['token_secret'] = self.cleaned_data.get('token_secret', '')
        instance.config_data['node'] = self.cleaned_data.get('node', '')
        if commit:
            instance.save()
        return instance


class AdGuardIntegrationForm(forms.ModelForm):
    """Formulario específico para AdGuard Home."""
    
    url = forms.CharField(
        label='AdGuard Home URL',
        required=False,
        widget=forms.URLInput(attrs={
            'style': 'width: 100%; padding: 8px;',
            'placeholder': 'http://adguard.example.com:80'
        }),
        help_text='Full URL to your AdGuard Home instance (including port)'
    )
    username = forms.CharField(
        label='Username',
        required=False,
        widget=forms.TextInput(attrs={
            'style': 'width: 100%; padding: 8px;',
            'placeholder': 'Your AdGuard Home username'
        }),
        help_text='AdGuard Home admin username'
    )
    password = forms.CharField(
        label='Password',
        required=False,
        widget=forms.PasswordInput(attrs={
            'style': 'width: 100%; padding: 8px;',
            'placeholder': 'Your AdGuard Home password'
        }),
        help_text='AdGuard Home admin password'
    )
    default_tags = forms.CharField(
        label='Default Tags (Optional)',
        required=False,
        widget=forms.TextInput(attrs={
            'style': 'width: 100%; padding: 8px;',
            'placeholder': 'tag1, tag2, tag3'
        }),
        help_text='Comma-separated list of tags to apply to synced clients'
    )
    
    class Meta:
        model = IntegrationConfig
        fields = ['display_name', 'enabled']
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            config = self.instance.config_data
            self.fields['url'].initial = config.get('url', '')
            self.fields['username'].initial = config.get('username', '')
            self.fields['password'].initial = config.get('password', '')
            self.fields['default_tags'].initial = config.get('default_tags', '')
    
    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.config_data['url'] = self.cleaned_data.get('url', '')
        instance.config_data['username'] = self.cleaned_data.get('username', '')
        instance.config_data['password'] = self.cleaned_data.get('password', '')
        instance.config_data['default_tags'] = self.cleaned_data.get('default_tags', '')
        if commit:
            instance.save()
        return instance
