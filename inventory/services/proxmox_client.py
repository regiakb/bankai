"""
Proxmox API client.
Supports optional integration instance for multiple Proxmox configs.
"""
import logging
from typing import List, Dict, Optional, Any
from proxmoxer import ProxmoxAPI
from inventory.config_manager import (
    get_proxmox_url, get_proxmox_token_id, get_proxmox_token_secret, get_proxmox_node
)

logger = logging.getLogger(__name__)


def _get_credentials(integration: Optional[Any] = None) -> tuple:
    """Return (url, token_id, token_secret, node) from config or from integration."""
    if integration is not None:
        url = (integration.get_config('url', '') or '').strip()
        token_id = (integration.get_config('token_id', '') or '').strip()
        token_secret = integration.get_config('token_secret', '') or ''
        node = integration.get_config('node', '') or ''
        return url, token_id, token_secret, node
    return get_proxmox_url(), get_proxmox_token_id(), get_proxmox_token_secret(), get_proxmox_node()


def get_proxmox_client(integration: Optional[Any] = None) -> Optional[ProxmoxAPI]:
    """Get Proxmox API client. If integration is given, use that instance's config."""
    url, token_id, token_secret, _ = _get_credentials(integration)
    
    if not all([url, token_id, token_secret]):
        logger.warning("Proxmox not configured")
        return None
    
    if url:
        # Remove http:// or https:// if present
        url = url.replace('https://', '').replace('http://', '')
        # Ensure it's in hostname:port format
        if ':' not in url:
            url = f'{url}:8006'  # Default Proxmox port
        logger.debug(f"Proxmox URL formatted: {url}")
    
    try:
        # Parse token_id format: user@pam!token_name
        # Split into user and token_name
        if '!' in token_id:
            user, token_name = token_id.rsplit('!', 1)
        else:
            # If no ! found, log warning and use token_id as user
            # This might indicate misconfiguration
            logger.warning(f"Proxmox token_id '{token_id}' doesn't contain '!'. Expected format: user@pam!token_name")
            user = token_id
            token_name = None
        
        # Build client parameters
        # ProxmoxAPI accepts host as first positional or keyword argument
        client_params = {
            'user': user,
            'token_value': token_secret,
            'verify_ssl': False,  # For self-signed certs
        }
        
        # Only add token_name if it exists (for token-based auth)
        if token_name:
            client_params['token_name'] = token_name
        
        # Pass host as first positional argument (URL)
        client = ProxmoxAPI(url, **client_params)
        return client
    except Exception as e:
        logger.error(f"Failed to create Proxmox client: {e}")
        return None


def sync_proxmox_vms(integration: Optional[Any] = None) -> List[Dict]:
    """
    Fetch VMs and LXC containers from Proxmox.
    
    Args:
        integration: Optional IntegrationConfig instance (for multiple Proxmox)
    
    Returns:
        List of VM/LXC info dictionaries
    """
    client = get_proxmox_client(integration)
    if not client:
        return []
    
    results = []
    # Always get all nodes, ignore node_name filter to sync from all nodes
    nodes = client.nodes.get()
    logger.info(f"Syncing from all nodes: {[n.get('node') for n in nodes]}")
    
    # Try to get resources from cluster first (works with limited permissions)
    # Note: type='vm' includes both QEMU VMs and LXC containers in Proxmox
    try:
        cluster_resources = client.cluster.resources.get(type='vm')
        logger.info(f"Found {len(cluster_resources)} VM resources in cluster (includes LXC)")
        
        # If we got resources from cluster, process them
        if cluster_resources:
            for resource in cluster_resources:
                vmid = resource.get('vmid')
                node_name = resource.get('node', '')
                resource_type = resource.get('type', '')
                name = resource.get('name', f'{resource_type}-{vmid}')
                
                if not node_name or not vmid:
                    continue
                
                try:
                    if resource_type == 'qemu':
                        # Get VM config
                        try:
                            vm_info = client.nodes(node_name).qemu(vmid).config.get()
                            ips = _get_vm_ips(client, node_name, vmid, 'qemu')
                            macs = _extract_macs(vm_info)
                            results.append({
                                'name': vm_info.get('name') or name,
                                'vmid': vmid,
                                'type': 'qemu',
                                'macs': macs,
                                'ips': ips,
                                'tags': vm_info.get('tags', ''),
                                'node': node_name,
                                'status': resource.get('status', 'unknown'),
                            })
                        except Exception as e:
                            logger.warning(f"Error getting config for VM {vmid} on {node_name}: {e}")
                    
                    elif resource_type == 'lxc':
                        # Get LXC config
                        try:
                            lxc_info = client.nodes(node_name).lxc(vmid).config.get()
                            # Try to get status for additional IP info
                            try:
                                lxc_status = client.nodes(node_name).lxc(vmid).status.current.get()
                                if lxc_status:
                                    lxc_info.update(lxc_status)
                            except:
                                pass
                            
                            ips = _get_lxc_ips(lxc_info)
                            macs = _extract_macs(lxc_info)
                            results.append({
                                'name': lxc_info.get('hostname') or name,
                                'vmid': vmid,
                                'type': 'lxc',
                                'macs': macs,
                                'ips': ips,
                                'tags': lxc_info.get('tags', ''),
                                'node': node_name,
                                'status': resource.get('status', 'unknown'),
                            })
                        except Exception as e:
                            logger.warning(f"Error getting config for LXC {vmid} on {node_name}: {e}")
                except Exception as e:
                    logger.warning(f"Error processing resource {vmid}: {e}")
    except Exception as e:
        logger.warning(f"Error getting cluster resources: {e}, trying node-by-node approach")
    
    # Always try node-by-node approach as well (in case cluster endpoint doesn't work)
    # This is more reliable for getting LXC containers
    if not results:
        logger.info("Trying node-by-node approach to find VMs/LXC...")
        
        try:
            # Fallback: try node-by-node approach
            for node in nodes:
                node_name = node.get('node', '') if isinstance(node, dict) else str(node)
                logger.info(f"Processing Proxmox node: {node_name}")
                
                # Get VMs
                try:
                    vms = client.nodes(node_name).qemu.get()
                    logger.info(f"Found {len(vms)} QEMU VMs on node {node_name}")
                    for vm in vms:
                        vm_id = vm.get('vmid')
                        try:
                            vm_info = client.nodes(node_name).qemu(vm_id).config.get()
                            ips = _get_vm_ips(client, node_name, vm_id, 'qemu')
                            name = vm_info.get('name') or vm.get('name') or f'vm-{vm_id}'
                            macs = _extract_macs(vm_info)
                            
                            results.append({
                                'name': name,
                                'vmid': vm_id,
                                'type': 'qemu',
                                'macs': macs,
                                'ips': ips,
                                'tags': vm_info.get('tags', ''),
                                'node': node_name,
                                'status': vm.get('status', 'unknown'),
                            })
                            logger.debug(f"VM {vm_id} ({name}): IPs={ips}, MACs={macs}")
                        except Exception as e:
                            logger.warning(f"Error getting config for VM {vm_id}: {e}", exc_info=True)
                except Exception as e:
                    logger.warning(f"Error getting VMs from node {node_name}: {e}", exc_info=True)
                
                # Get LXC containers
                try:
                    lxcs = client.nodes(node_name).lxc.get()
                    logger.info(f"Found {len(lxcs)} LXC containers on node {node_name}")
                    for lxc in lxcs:
                        lxc_id = lxc.get('vmid')
                        try:
                            lxc_info = client.nodes(node_name).lxc(lxc_id).config.get()
                            try:
                                lxc_status = client.nodes(node_name).lxc(lxc_id).status.current.get()
                                if lxc_status:
                                    lxc_info.update(lxc_status)
                            except:
                                pass
                            
                            ips = _get_lxc_ips(lxc_info)
                            name = lxc_info.get('hostname') or lxc.get('name') or f'lxc-{lxc_id}'
                            macs = _extract_macs(lxc_info)
                            
                            results.append({
                                'name': name,
                                'vmid': lxc_id,
                                'type': 'lxc',
                                'macs': macs,
                                'ips': ips,
                                'tags': lxc_info.get('tags', ''),
                                'node': node_name,
                                'status': lxc.get('status', 'unknown'),
                            })
                            logger.debug(f"LXC {lxc_id} ({name}): IPs={ips}, MACs={macs}")
                        except Exception as e:
                            logger.warning(f"Error getting config for LXC {lxc_id}: {e}", exc_info=True)
                except Exception as e:
                    logger.warning(f"Error getting LXC containers from node {node_name}: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Error in node-by-node approach: {e}", exc_info=True)
    
    logger.info(f"Total VMs/LXCs synced: {len(results)}")
    return results


def _extract_macs(config: Dict) -> List[str]:
    """Extract MAC addresses from Proxmox config."""
    macs = []
    for key, value in config.items():
        if key.startswith('net') and isinstance(value, str):
            # Format: model=virtio,bridge=vmbr0,mac=XX:XX:XX:XX:XX:XX
            parts = value.split(',')
            for part in parts:
                if part.startswith('mac='):
                    mac = part.split('=')[1]
                    if mac:
                        macs.append(mac.lower())
    return macs


def _get_vm_ips(client: ProxmoxAPI, node_name: str, vm_id: int, vm_type: str) -> List[str]:
    """Try to get IP addresses from VM using QEMU agent."""
    ips = []
    try:
        # Try to get IPs via QEMU agent (requires qemu-guest-agent installed in VM)
        agent_info = client.nodes(node_name).qemu(vm_id).agent('network-get-interfaces').get()
        if agent_info and 'result' in agent_info:
            for interface in agent_info['result']:
                ip_addresses = interface.get('ip-addresses', [])
                for ip_addr in ip_addresses:
                    if ip_addr.get('ip-address-type') == 'ipv4':
                        ip = ip_addr.get('ip-address')
                        if ip and ip not in ips:
                            ips.append(ip)
    except Exception as e:
        # QEMU agent might not be available or enabled
        logger.debug(f"Could not get IPs via QEMU agent for VM {vm_id}: {e}")
    return ips


def _get_lxc_ips(config: Dict) -> List[str]:
    """Extract IP addresses from LXC container config."""
    ips = []
    # LXC containers may have IP addresses in net* config keys
    for key, value in config.items():
        if key.startswith('net') and isinstance(value, str):
            # Format: name=eth0,bridge=vmbr0,ip=192.168.1.100/24
            # Or: name=eth0,bridge=vmbr0,hwaddr=XX:XX:XX:XX:XX:XX,ip=192.168.1.100/24
            parts = value.split(',')
            for part in parts:
                if part.startswith('ip='):
                    ip_part = part.split('=')[1]
                    # Extract IP from CIDR notation (e.g., 192.168.1.100/24 -> 192.168.1.100)
                    ip = ip_part.split('/')[0]
                    if ip and ip not in ips:
                        ips.append(ip)
    
    # Also check for IP addresses in the status/current config
    # Some LXC containers store IPs differently
    for key, value in config.items():
        if 'ip' in key.lower() and isinstance(value, str) and '/' in value:
            # Direct IP field
            ip = value.split('/')[0]
            if ip and ip not in ips and '.' in ip:  # Basic IPv4 validation
                ips.append(ip)
    
    return ips
