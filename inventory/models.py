"""
Models for network inventory management.
"""
from django.db import models
from django.utils import timezone
from typing import Optional


class HostSource(models.TextChoices):
    MANUAL = 'manual', 'Manual'
    NMAP = 'nmap', 'Nmap Scan'
    PROXMOX = 'proxmox', 'Proxmox'
    DOCKER = 'docker', 'Docker'


class MediumType(models.TextChoices):
    WIFI = 'wifi', 'WiFi'
    ETHERNET = 'ethernet', 'Ethernet'
    UNKNOWN = 'unknown', 'Unknown'


class IPAssignment(models.TextChoices):
    DHCP = 'dhcp', 'DHCP'
    STATIC = 'static', 'Static'
    RESERVED = 'reserved', 'Reserved'
    UNKNOWN = 'unknown', 'Unknown'


class AlertType(models.TextChoices):
    NEW_IP = 'new_ip', 'New IP Detected'
    NEW_SERVICE = 'new_service', 'New Service Detected'
    HOST_DOWN = 'host_down', 'Host Down'
    HOST_STATUS_CHANGE = 'host_status_change', 'Host Status Changed'
    ERROR = 'error', 'Error'
    TASK_COMPLETED = 'task_completed', 'Task Completed'


class SystemConfig(models.Model):
    """System configuration stored in database."""
    key = models.CharField(max_length=100, unique=True, help_text="Configuration key")
    value = models.TextField(blank=True, help_text="Configuration value")
    description = models.TextField(blank=True, help_text="Description of this setting")
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['key']
        verbose_name = 'System Configuration'
        verbose_name_plural = 'System Configurations'
    
    def __str__(self) -> str:
        return f"{self.key} = {self.value[:50] if len(self.value) > 50 else self.value}"
    
    @classmethod
    def get_value(cls, key: str, default: str = '') -> str:
        """Get configuration value by key."""
        try:
            return cls.objects.get(key=key).value
        except cls.DoesNotExist:
            return default
    
    @classmethod
    def set_value(cls, key: str, value: str, description: str = ''):
        """Set configuration value."""
        config, created = cls.objects.get_or_create(
            key=key,
            defaults={'value': value, 'description': description}
        )
        if not created:
            config.value = value
            if description:
                config.description = description
            config.save()
        return config


class TaskExecution(models.Model):
    """Track execution of management commands/tasks."""
    TASK_CHOICES = [
        ('scan_discovery', 'Discovery Scan (Nmap)'),
        ('scan_services', 'Service Scan (Nmap)'),
        ('sync_proxmox', 'Proxmox Sync'),
        ('sync_docker', 'Docker Sync'),
        ('sync_adguard', 'AdGuard Home Sync'),
    ]
    
    task_name = models.CharField(max_length=50, choices=TASK_CHOICES, help_text="Task/command name")
    started_at = models.DateTimeField(auto_now_add=True, help_text="When the task started")
    completed_at = models.DateTimeField(null=True, blank=True, help_text="When the task completed")
    status = models.CharField(
        max_length=20,
        choices=[('running', 'Running'), ('success', 'Success'), ('error', 'Error')],
        default='running',
        help_text="Task status"
    )
    output = models.TextField(blank=True, help_text="Task output/logs")
    error_message = models.TextField(blank=True, help_text="Error message if failed")
    items_processed = models.IntegerField(default=0, help_text="Number of items processed (hosts, services, etc.)")
    
    class Meta:
        ordering = ['-started_at']
        verbose_name = 'Task Execution'
        verbose_name_plural = 'Task Executions'
        indexes = [
            models.Index(fields=['task_name', '-started_at']),
        ]
    
    def __str__(self) -> str:
        status_icon = '🟢' if self.status == 'success' else '🔴' if self.status == 'error' else '🟡'
        return f"{status_icon} {self.get_task_name_display()} - {self.started_at.strftime('%Y-%m-%d %H:%M:%S')}"
    
    @classmethod
    def record_start(cls, task_name: str) -> 'TaskExecution':
        """Record that a task has started."""
        return cls.objects.create(task_name=task_name, status='running')
    
    def record_success(self, items_processed: int = 0, output: str = ''):
        """Record that a task completed successfully."""
        from django.utils import timezone
        self.status = 'success'
        self.completed_at = timezone.now()
        self.items_processed = items_processed
        if output:
            self.output = output
        self.save()
    
    def record_error(self, error_message: str, output: str = ''):
        """Record that a task failed."""
        from django.utils import timezone
        self.status = 'error'
        self.completed_at = timezone.now()
        self.error_message = error_message
        if output:
            self.output = output
        self.save()
    
    @classmethod
    def get_last_execution(cls, task_name: str) -> Optional['TaskExecution']:
        """Get the last execution of a task."""
        return cls.objects.filter(task_name=task_name).order_by('-started_at').first()


class IntegrationConfig(models.Model):
    """Integration configuration and status. Multiple instances per type allowed (e.g. 2 Telegram, 2 Proxmox)."""
    INTEGRATION_CHOICES = [
        ('telegram', 'Telegram'),
        ('proxmox', 'Proxmox'),
        ('docker', 'Docker'),
        ('adguard', 'AdGuard Home'),
    ]
    
    name = models.CharField(max_length=50, choices=INTEGRATION_CHOICES, help_text="Integration type")
    display_name = models.CharField(max_length=100, default='Default', blank=True, help_text="Label for this instance (e.g. Main, Alerts)")
    enabled = models.BooleanField(default=False, help_text="Enable this integration")
    config_data = models.JSONField(default=dict, help_text="Configuration as JSON")
    last_test = models.DateTimeField(null=True, blank=True, help_text="Last test timestamp")
    last_test_result = models.BooleanField(null=True, blank=True, help_text="Last test result")
    last_test_message = models.TextField(blank=True, help_text="Last test message")
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name', 'display_name']
        verbose_name = 'Integration Configuration'
        verbose_name_plural = 'Integration Configurations'
        constraints = [
            models.UniqueConstraint(fields=['name', 'display_name'], name='unique_integration_name_display'),
        ]
    
    def __str__(self) -> str:
        status = "✓" if self.enabled else "✗"
        return f"{status} {self.get_name_display()}"
    
    def get_config(self, key: str, default: str = '') -> str:
        """Get configuration value from config_data."""
        return self.config_data.get(key, default)
    
    def set_config(self, key: str, value: str):
        """Set configuration value in config_data."""
        self.config_data[key] = value
        self.save()


class Host(models.Model):
    """Network host/device."""
    name = models.CharField(max_length=255, help_text="Friendly hostname")
    mac = models.CharField(max_length=17, unique=True, null=True, blank=True, help_text="MAC address")
    vendor = models.CharField(max_length=255, null=True, blank=True, help_text="Vendor/OUI")
    device_type = models.CharField(max_length=100, default='unknown', help_text="Device type")
    source = models.CharField(max_length=20, choices=HostSource.choices, default=HostSource.MANUAL)
    notes = models.TextField(blank=True, help_text="Additional notes")
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-last_seen', 'name']
        indexes = [
            models.Index(fields=['mac']),
            models.Index(fields=['source']),
            models.Index(fields=['is_active']),
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.mac or 'no MAC'})"


class InterfaceAttachment(models.Model):
    """Network interface attachment (WiFi/Ethernet)."""
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='interfaces')
    medium = models.CharField(max_length=20, choices=MediumType.choices, default=MediumType.UNKNOWN)
    ssid = models.CharField(max_length=255, null=True, blank=True, help_text="WiFi SSID")
    switch_port = models.CharField(max_length=50, null=True, blank=True, help_text="Switch port")
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-last_seen']

    def __str__(self) -> str:
        return f"{self.host.name} - {self.get_medium_display()}"


class IPAddress(models.Model):
    """IP address assignment."""
    host = models.ForeignKey(Host, on_delete=models.SET_NULL, null=True, blank=True, related_name='ip_addresses')
    ip = models.GenericIPAddressField(unique=True)
    assignment = models.CharField(max_length=20, choices=IPAssignment.choices, default=IPAssignment.UNKNOWN)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    online = models.BooleanField(default=True)

    class Meta:
        ordering = ['-last_seen', 'ip']
        indexes = [
            models.Index(fields=['ip']),
            models.Index(fields=['assignment']),
            models.Index(fields=['online']),
        ]

    def __str__(self) -> str:
        return f"{self.ip} ({self.host.name if self.host else 'no host'})"


class Hostname(models.Model):
    """Hostname discovered from nmap scans (DNS, NetBIOS, etc.)."""
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='hostnames')
    name = models.CharField(max_length=255, help_text="Hostname discovered from scan")
    source_type = models.CharField(
        max_length=50,
        default='dns',
        help_text="Source of hostname: dns, PTR, user, service, script, etc."
    )
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-last_seen', 'name']
        unique_together = [['host', 'name']]  # One hostname per host (no duplicates)
        indexes = [
            models.Index(fields=['host', 'name']),
            models.Index(fields=['source_type']),
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.source_type}) - {self.host.name if self.host else 'no host'}"


class Service(models.Model):
    """Network service/port."""
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='services')
    port = models.IntegerField()
    proto = models.CharField(max_length=10, default='tcp', choices=[('tcp', 'TCP'), ('udp', 'UDP')])
    name = models.CharField(max_length=255, blank=True, help_text="Service name")
    product = models.CharField(max_length=255, blank=True, help_text="Product name")
    version = models.CharField(max_length=255, blank=True, help_text="Version")
    extra_info = models.TextField(blank=True, help_text="Additional info")
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['host', 'port', 'proto']
        unique_together = [['host', 'port', 'proto']]
        indexes = [
            models.Index(fields=['port']),
            models.Index(fields=['name']),
        ]

    def __str__(self) -> str:
        return f"{self.host.name}:{self.port}/{self.proto} ({self.name or 'unknown'})"


class HostStatusEvent(models.Model):
    """Record when a host is observed online/offline for connection history and charts.

    Important: we now record both "changes" and "snapshots" (e.g., one row per host per scan/sync run)
    so charts can show meaningful host counts per execution.
    """
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='status_events')
    recorded_at = models.DateTimeField(default=timezone.now, db_index=True)
    is_online = models.BooleanField(help_text="True = came online, False = went offline")
    source = models.CharField(max_length=50, blank=True, default='', help_text="Origin of this observation (scan/sync/manual)")
    task_execution = models.ForeignKey(
        TaskExecution,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='status_events',
        help_text="TaskExecution that produced this event (if any)"
    )
    is_snapshot = models.BooleanField(default=False, help_text="True if recorded as part of a full snapshot (not only changes)")

    class Meta:
        ordering = ['-recorded_at']
        indexes = [
            models.Index(fields=['host', '-recorded_at']),
            models.Index(fields=['-recorded_at']),
            models.Index(fields=['source', '-recorded_at']),
        ]
        verbose_name = 'Host status event'
        verbose_name_plural = 'Host status events'

    def __str__(self) -> str:
        status = 'online' if self.is_online else 'offline'
        return f"{self.host.name} {status} at {self.recorded_at}"

    @staticmethod
    def record(
        host: 'Host',
        is_online: bool,
        *,
        source: str = '',
        task_execution: Optional['TaskExecution'] = None,
        is_snapshot: bool = False,
        recorded_at=None,
    ):
        """Record a host online/offline observation.

        Use `is_snapshot=True` for "full snapshot" runs (e.g. discovery scan of N hosts).
        """
        HostStatusEvent.objects.create(
            host=host,
            is_online=is_online,
            source=source or '',
            task_execution=task_execution,
            is_snapshot=is_snapshot,
            recorded_at=recorded_at or timezone.now(),
        )

    @staticmethod
    def record_snapshot_for_hosts(
        host_ids,
        *,
        source: str,
        task_execution: Optional['TaskExecution'] = None,
        recorded_at=None,
        batch_size: int = 1000,
    ):
        """Bulk-record a snapshot (one event per host)."""
        now = recorded_at or timezone.now()
        host_ids = list({int(h) for h in host_ids if h})
        if not host_ids:
            return 0
        # Fetch current statuses in one query
        host_statuses = Host.objects.filter(id__in=host_ids).values_list('id', 'is_active')
        events = [
            HostStatusEvent(
                host_id=hid,
                is_online=bool(is_active),
                source=source or '',
                task_execution=task_execution,
                is_snapshot=True,
                recorded_at=now,
            )
            for hid, is_active in host_statuses
        ]
        HostStatusEvent.objects.bulk_create(events, batch_size=batch_size)
        return len(events)


class Alert(models.Model):
    """System alerts and events."""
    type = models.CharField(max_length=20, choices=AlertType.choices)
    message = models.TextField()
    details = models.TextField(blank=True, help_text="Detailed results/output from the task")
    created_at = models.DateTimeField(auto_now_add=True)
    related_host = models.ForeignKey(Host, on_delete=models.SET_NULL, null=True, blank=True, related_name='alerts')
    related_ip = models.ForeignKey(IPAddress, on_delete=models.SET_NULL, null=True, blank=True, related_name='alerts')

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['type']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self) -> str:
        return f"{self.get_type_display()} - {self.message[:50]}"
