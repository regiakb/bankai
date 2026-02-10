"""
AdGuard Home API client.
Supports optional integration instance for multiple AdGuard Home configs.
"""
import logging
import requests
from requests.auth import HTTPBasicAuth
from typing import List, Dict, Optional, Any
from inventory.config_manager import (
    get_adguard_url, get_adguard_username, get_adguard_password
)

logger = logging.getLogger(__name__)


def _get_credentials(integration: Optional[Any] = None) -> tuple:
    """Return (url, username, password) from config or from integration."""
    if integration is not None:
        url = (integration.get_config('url', '') or '').strip()
        username = (integration.get_config('username', '') or '').strip()
        password = integration.get_config('password', '') or ''
        return url, username, password
    return get_adguard_url(), get_adguard_username(), get_adguard_password()


def get_adguard_client(integration: Optional[Any] = None) -> Optional[requests.Session]:
    """Get AdGuard Home API client session. If integration is given, use that instance's config."""
    url, username, password = _get_credentials(integration)
    
    if not all([url, username, password]):
        logger.warning("AdGuard Home not configured")
        return None
    
    url = url.rstrip('/')
    
    try:
        session = requests.Session()
        session.auth = HTTPBasicAuth(username, password)
        session.verify = False
        response = session.get(f"{url}/control/status", timeout=10)
        if response.status_code == 200:
            logger.info("AdGuard Home connection successful")
            return session
        elif response.status_code == 401:
            logger.error("AdGuard Home authentication failed: Invalid username or password")
            return None
        else:
            logger.error(f"AdGuard Home connection failed: {response.status_code} - {response.text[:200]}")
            return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to create AdGuard Home client: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to create AdGuard Home client: {e}")
        return None


def get_adguard_clients(integration: Optional[Any] = None) -> List[Dict]:
    """
    Get all clients from AdGuard Home.
    
    Returns:
        List of client dictionaries (always returns a list, never None)
    """
    session = get_adguard_client(integration)
    if not session:
        logger.warning("AdGuard Home session not available")
        return []
    
    url, _, _ = _get_credentials(integration)
    url = (url or '').rstrip('/')
    
    try:
        response = session.get(f"{url}/control/clients", timeout=10)
        if response.status_code == 200:
            clients = response.json()
            # Ensure we return a list
            if isinstance(clients, dict):
                return clients.get('clients', [])
            elif isinstance(clients, list):
                return clients
            else:
                logger.warning(f"Unexpected response format from AdGuard Home: {type(clients)}")
                return []
        else:
            logger.error(f"Failed to get clients: {response.status_code} - {response.text}")
            return []
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error getting AdGuard Home clients: {e}")
        return []
    except Exception as e:
        logger.error(f"Error getting AdGuard Home clients: {e}")
        return []


def add_adguard_client(
    name: str,
    identifiers: List[str],
    tags: Optional[List[str]] = None,
    use_global_settings: bool = True,
    use_global_blocked_services: bool = True,
    filtering_enabled: bool = True,
    integration: Optional[Any] = None,
) -> bool:
    """
    Add a new client to AdGuard Home.

    Args:
        name: Client name
        identifiers: List of identifiers (IP, MAC, CIDR, or client_id)
        tags: Optional list of tags
        use_global_settings: Use global settings
        use_global_blocked_services: Use global blocked services
        filtering_enabled: Enable filtering
        integration: Optional IntegrationConfig instance (for multiple AdGuard)

    Returns:
        True if successful, False otherwise
    """
    session = get_adguard_client(integration)
    if not session:
        return False

    url, _, _ = _get_credentials(integration)
    url = (url or '').rstrip('/')
    
    client_data = {
        "name": name,
        "ids": identifiers,
        "use_global_settings": use_global_settings,
        "use_global_blocked_services": use_global_blocked_services,
        "filtering_enabled": filtering_enabled,
        "parental_enabled": False,
        "safebrowsing_enabled": False,
        "safesearch_enabled": False,
        "use_global_safe_search": True,
        "querylog_enabled": True,
        "upstreams": []
    }
    
    # Only include tags if they are provided and not empty
    # Tags must exist in AdGuard Home before they can be used
    has_tags = False
    if tags:
        # Filter out None and empty strings
        valid_tags = [tag for tag in tags if tag and isinstance(tag, str) and tag.strip()]
        if valid_tags:
            client_data["tags"] = valid_tags
            has_tags = True
    
    try:
        # AdGuard Home uses /control/clients/add for adding clients
        response = session.post(
            f"{url}/control/clients/add",
            json=client_data,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code in [200, 201]:
            logger.info(f"Successfully added AdGuard Home client: {name}")
            return True
        elif response.status_code == 400 and "invalid tag" in response.text.lower() and has_tags:
            # If tags are invalid, try again without tags
            logger.warning(f"Invalid tags for client {name}, retrying without tags")
            client_data_no_tags = client_data.copy()
            client_data_no_tags.pop("tags", None)
            
            response = session.post(
                f"{url}/control/clients/add",
                json=client_data_no_tags,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"Successfully added AdGuard Home client: {name} (without tags)")
                return True
            else:
                logger.error(f"Failed to add client without tags: {response.status_code} - {response.text}")
                return False
        else:
            logger.error(f"Failed to add client: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error adding AdGuard Home client: {e}")
        return False


def update_adguard_client(
    client_name: str,
    name: Optional[str] = None,
    identifiers: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    integration: Optional[Any] = None,
    **kwargs
) -> bool:
    """
    Update an existing client in AdGuard Home.
    
    Args:
        client_name: Client name (used to find and update the client)
        name: New client name (if different)
        identifiers: New list of identifiers
        tags: New list of tags
        integration: Optional IntegrationConfig instance (for multiple AdGuard)
        **kwargs: Other client properties to update
    
    Returns:
        True if successful, False otherwise
    """
    session = get_adguard_client(integration)
    if not session:
        return False
    
    url, _, _ = _get_credentials(integration)
    url = (url or '').rstrip('/')
    
    clients = get_adguard_clients(integration)
    client = None
    for c in clients:
        if c.get('name') == client_name:
            client = c
            break
    
    if not client:
        logger.error(f"Client not found: {client_name}")
        return False
    
    # Update client data
    client_data = client.copy()
    if name:
        client_data['name'] = name
    if identifiers:
        client_data['ids'] = identifiers
    # Only update tags if they are provided and not empty
    # Tags must exist in AdGuard Home before they can be used
    if tags is not None:
        # Filter out None and empty strings
        valid_tags = [tag for tag in tags if tag and isinstance(tag, str) and tag.strip()]
        if valid_tags:
            client_data['tags'] = valid_tags
        elif tags == []:
            # Explicitly set to empty list if tags is empty list
            client_data['tags'] = []
    
    # Update other properties
    for key, value in kwargs.items():
        client_data[key] = value
    
    # Track if we have tags to retry without them if needed
    has_tags = 'tags' in client_data and client_data.get('tags')
    
    try:
        # AdGuard Home uses POST /control/clients/update with specific structure
        # The update endpoint requires: {"name": "...", "data": {...}}
        update_payload = {
            "name": client_name,
            "data": client_data
        }
        
        response = session.post(
            f"{url}/control/clients/update",
            json=update_payload,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            logger.info(f"Successfully updated AdGuard Home client: {client_name}")
            return True
        elif response.status_code == 400 and "invalid tag" in response.text.lower() and has_tags:
            # If tags are invalid, try again without tags
            logger.warning(f"Invalid tags for client {client_name}, retrying without tags")
            client_data_no_tags = client_data.copy()
            client_data_no_tags.pop("tags", None)
            
            update_payload_no_tags = {
                "name": client_name,
                "data": client_data_no_tags
            }
            
            response = session.post(
                f"{url}/control/clients/update",
                json=update_payload_no_tags,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully updated AdGuard Home client: {client_name} (without tags)")
                return True
            else:
                logger.error(f"Failed to update client without tags: {response.status_code} - {response.text}")
                return False
        else:
            logger.error(f"Failed to update client: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error updating AdGuard Home client: {e}")
        return False


def delete_adguard_client(client_id: str, integration: Optional[Any] = None) -> bool:
    """
    Delete a client from AdGuard Home.
    
    Args:
        client_id: Client ID (name or identifier)
        integration: Optional IntegrationConfig instance (for multiple AdGuard)
    
    Returns:
        True if successful, False otherwise
    """
    session = get_adguard_client(integration)
    if not session:
        return False
    
    url, _, _ = _get_credentials(integration)
    url = (url or '').rstrip('/')
    
    try:
        response = session.delete(f"{url}/control/clients/{client_id}")
        
        if response.status_code in [200, 204]:
            logger.info(f"Successfully deleted AdGuard Home client: {client_id}")
            return True
        else:
            logger.error(f"Failed to delete client: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error deleting AdGuard Home client: {e}")
        return False


def sync_bankai_hosts_to_adguard(
    hosts: List[Dict],
    default_tags: Optional[List[str]] = None,
    integration: Optional[Any] = None,
) -> Dict[str, int]:
    """
    Sync Bankai hosts to AdGuard Home clients.
    
    Args:
        hosts: List of host dictionaries with 'name', 'mac', 'ips', etc.
        default_tags: Optional default tags to apply to all clients
        integration: Optional IntegrationConfig instance (for multiple AdGuard)
    
    Returns:
        Dictionary with sync statistics
    """
    stats = {
        'added': 0,
        'updated': 0,
        'skipped': 0,
        'errors': 0
    }
    
    existing_clients = get_adguard_clients(integration)
    if not isinstance(existing_clients, list):
        logger.warning("get_adguard_clients() returned non-list, using empty list")
        existing_clients = []
    existing_names = {c.get('name') for c in existing_clients if c and isinstance(c, dict)}
    
    for host in hosts:
        name = host.get('name', 'unknown')
        mac = host.get('mac', '')
        ips = host.get('ips', [])
        
        identifiers = []
        if mac:
            identifiers.append(mac)
        for ip in ips:
            if ip:
                identifiers.append(ip)
        
        if not identifiers:
            logger.warning(f"Host {name} has no MAC or IP identifiers, skipping")
            stats['skipped'] += 1
            continue
        
        tags = list(default_tags or [])
        if host.get('device_type'):
            tags.append(host.get('device_type'))
        if host.get('source'):
            tags.append(host.get('source'))
        
        if name in existing_names:
            if update_adguard_client(name, identifiers=identifiers, tags=tags, integration=integration):
                stats['updated'] += 1
            else:
                stats['errors'] += 1
        else:
            if add_adguard_client(name, identifiers, tags=tags, integration=integration):
                stats['added'] += 1
            else:
                stats['errors'] += 1
    
    return stats
