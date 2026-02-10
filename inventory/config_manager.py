"""
Configuration manager for reading settings from database.
"""
from typing import Optional, List
from .models import SystemConfig, IntegrationConfig


class ConfigManager:
    """Manager for system configuration."""
    
    @staticmethod
    def get(key: str, default: str = '') -> str:
        """Get configuration value."""
        return SystemConfig.get_value(key, default)
    
    @staticmethod
    def get_bool(key: str, default: bool = False) -> bool:
        """Get boolean configuration value."""
        value = SystemConfig.get_value(key, str(default).lower())
        return value.lower() in ('true', '1', 'yes', 'on')
    
    @staticmethod
    def get_int(key: str, default: int = 0) -> int:
        """Get integer configuration value."""
        try:
            return int(SystemConfig.get_value(key, str(default)))
        except ValueError:
            return default
    
    @staticmethod
    def set(key: str, value: str, description: str = ''):
        """Set configuration value."""
        return SystemConfig.set_value(key, value, description)
    
    @staticmethod
    def get_integration(name: str, display_name: Optional[str] = None) -> Optional[IntegrationConfig]:
        """Get one integration by type (and optional display_name). Returns first match."""
        qs = IntegrationConfig.objects.filter(name=name)
        if display_name is not None:
            qs = qs.filter(display_name=display_name)
        return qs.first()
    
    @staticmethod
    def get_integrations(name: str, enabled_only: bool = False) -> List[IntegrationConfig]:
        """Get all integrations of a given type (e.g. all Telegram configs)."""
        qs = IntegrationConfig.objects.filter(name=name).order_by('display_name')
        if enabled_only:
            qs = qs.filter(enabled=True)
        return list(qs)
    
    @staticmethod
    def get_integration_config(name: str, key: str, default: str = '') -> str:
        """Get integration configuration value (from first enabled integration of this type)."""
        integration = ConfigManager.get_integration(name)
        if integration and integration.enabled:
            return integration.get_config(key, default)
        return default


# Convenience functions for settings (single-instance: first enabled)
def get_telegram_token() -> str:
    """Get Telegram bot token (first enabled)."""
    integration = ConfigManager.get_integration('telegram')
    if integration and integration.enabled:
        return integration.get_config('bot_token', '')
    return ''


def get_telegram_chat_id() -> str:
    """Get Telegram chat ID (first enabled)."""
    integration = ConfigManager.get_integration('telegram')
    if integration and integration.enabled:
        return integration.get_config('chat_id', '')
    return ''


def get_telegram_integrations() -> List[IntegrationConfig]:
    """Get all enabled Telegram integrations (for sending to multiple)."""
    return ConfigManager.get_integrations('telegram', enabled_only=True)


def get_proxmox_url() -> str:
    """Get Proxmox URL (first enabled)."""
    integration = ConfigManager.get_integration('proxmox')
    if integration and integration.enabled:
        return integration.get_config('url', '')
    return ''


def get_proxmox_token_id() -> str:
    """Get Proxmox token ID (first enabled)."""
    integration = ConfigManager.get_integration('proxmox')
    if integration and integration.enabled:
        return integration.get_config('token_id', '')
    return ''


def get_proxmox_token_secret() -> str:
    """Get Proxmox token secret (first enabled)."""
    integration = ConfigManager.get_integration('proxmox')
    if integration and integration.enabled:
        return integration.get_config('token_secret', '')
    return ''


def get_proxmox_node() -> str:
    """Get Proxmox node (first enabled)."""
    integration = ConfigManager.get_integration('proxmox')
    if integration and integration.enabled:
        return integration.get_config('node', '')
    return ''


def get_proxmox_integrations() -> List[IntegrationConfig]:
    """Get all enabled Proxmox integrations."""
    return ConfigManager.get_integrations('proxmox', enabled_only=True)


def get_adguard_url() -> str:
    """Get AdGuard Home URL (first enabled)."""
    integration = ConfigManager.get_integration('adguard')
    if integration and integration.enabled:
        return integration.get_config('url', '')
    return ''


def get_adguard_username() -> str:
    """Get AdGuard Home username (first enabled)."""
    integration = ConfigManager.get_integration('adguard')
    if integration and integration.enabled:
        return integration.get_config('username', '')
    return ''


def get_adguard_password() -> str:
    """Get AdGuard Home password (first enabled)."""
    integration = ConfigManager.get_integration('adguard')
    if integration and integration.enabled:
        return integration.get_config('password', '')
    return ''


def get_adguard_integrations() -> List[IntegrationConfig]:
    """Get all enabled AdGuard Home integrations."""
    return ConfigManager.get_integrations('adguard', enabled_only=True)




def should_notify_new_service() -> bool:
    """Check if new service notifications are enabled."""
    return ConfigManager.get_bool('NOTIFY_NEW_SERVICE', False)


def get_discovery_cidr() -> str:
    """Get discovery CIDR."""
    return ConfigManager.get('DISCOVERY_CIDR', '192.168.1.0/24')


def get_discovery_interval() -> int:
    """Get discovery interval in minutes."""
    return ConfigManager.get_int('DISCOVERY_INTERVAL', 10)


def get_service_scan_interval() -> int:
    """Get service scan interval in minutes (config is always stored in minutes)."""
    value = ConfigManager.get_int('SERVICE_SCAN_INTERVAL', 60)
    if value >= 1000:
        return value // 60  # legacy: was stored as seconds
    return value


def get_proxmox_sync_interval() -> int:
    """Get Proxmox sync interval in minutes (config is always stored in minutes)."""
    value = ConfigManager.get_int('PROXMOX_SYNC_INTERVAL', 30)
    if value >= 1000:
        return value // 60  # legacy: was stored as seconds
    return value


def get_adguard_sync_interval() -> int:
    """Get AdGuard Home sync interval in minutes (config is always stored in minutes)."""
    value = ConfigManager.get_int('ADGUARD_SYNC_INTERVAL', 60)
    if value >= 1000:
        return value // 60  # legacy: was stored as seconds
    return value
