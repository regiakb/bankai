"""
Nmap XML parser utilities.
"""
import logging
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


def parse_nmap_xml(xml_content: str) -> Dict:
    """
    Parse nmap XML output.
    
    Returns:
        Dictionary with 'hosts' list containing host info
    """
    try:
        # Clean XML content - ensure it's valid
        # Remove any incomplete XML at the end
        xml_content = xml_content.strip()
        
        # Check if XML is complete
        if not xml_content.endswith('</nmaprun>'):
            # Try to find the last complete host element
            last_host_end = xml_content.rfind('</host>')
            if last_host_end > 0:
                # Find the start of nmaprun to get proper closing
                nmaprun_start = xml_content.find('<nmaprun')
                if nmaprun_start >= 0:
                    # Extract up to last complete host and add closing tags
                    xml_content = xml_content[:last_host_end + 7] + '\n</nmaprun>'
                else:
                    # Just take up to last complete host
                    xml_content = xml_content[:last_host_end + 7]
            else:
                # No complete hosts found, try to wrap what we have
                if '<nmaprun' in xml_content:
                    xml_content = xml_content + '\n</nmaprun>'
        
        # Parse XML
        root = ET.fromstring(xml_content)
        hosts = []
        
        for host_elem in root.findall('.//host'):
            host_info = {
                'ip': None,
                'hostname': None,  # Best hostname (for backward compatibility)
                'hostnames': [],  # All hostnames found with their source types
                'mac': None,
                'vendor': None,
                'status': 'down',
                'services': [],
                'os': None,
                'os_accuracy': None,
            }
            
            # IP address
            address_elem = host_elem.find('.//address[@addrtype="ipv4"]')
            if address_elem is not None:
                host_info['ip'] = address_elem.get('addr')
            
            # Status
            status_elem = host_elem.find('status')
            if status_elem is not None:
                host_info['status'] = status_elem.get('state', 'down')
            
            # Hostname - try multiple sources
            hostname_candidates = []
            
            # 1. Direct hostname element (from DNS reverse lookup)
            hostname_elem = host_elem.find('.//hostname')
            if hostname_elem is not None:
                hostname_name = hostname_elem.get('name')
                if hostname_name:
                    hostname_candidates.append(('dns', hostname_name))
            
            # 2. Check all hostname elements (can have multiple)
            for hostname_elem in host_elem.findall('.//hostname'):
                hostname_name = hostname_elem.get('name')
                hostname_type = hostname_elem.get('type', 'user')  # user, PTR, etc.
                if hostname_name:
                    hostname_candidates.append((hostname_type, hostname_name))
            
            # 3. Check service fingerprints for hostnames/identifiers
            for port_elem in host_elem.findall('.//port'):
                service_elem = port_elem.find('service')
                if service_elem is not None:
                    # Check for hostname in service name or product
                    service_name = service_elem.get('name', '')
                    service_product = service_elem.get('product', '')
                    service_hostname = service_elem.get('hostname', '')
                    
                    if service_hostname:
                        hostname_candidates.append(('service', service_hostname))
                    
                    # Check for hostname patterns in product/version
                    if service_product:
                        # Some services include hostname in product string
                        if '.' in service_product and not any(c.isdigit() for c in service_product.split('.')[0]):
                            # Might be a hostname
                            parts = service_product.split()
                            for part in parts:
                                if '.' in part and not part.startswith('http'):
                                    hostname_candidates.append(('service_product', part.split('.')[0]))
                    
                    # Check script output for hostnames
                    for script_elem in port_elem.findall('.//script'):
                        script_output = script_elem.get('output', '')
                        # Look for common hostname patterns in script output
                        # Look for patterns like "hostname: xxx" or "Host: xxx"
                        hostname_matches = re.findall(r'(?:hostname|Host|host|name)[:=]\s*([a-zA-Z0-9\-\.]+)', script_output, re.IGNORECASE)
                        for match in hostname_matches:
                            if '.' in match or len(match) > 3:  # Likely a hostname
                                hostname_candidates.append(('script', match))
            
            # 4. Check hostscript output for hostnames
            hostscript_elem = host_elem.find('hostscript')
            if hostscript_elem is not None:
                for script_elem in hostscript_elem.findall('.//script'):
                    script_output = script_elem.get('output', '')
                    hostname_matches = re.findall(r'(?:hostname|Host|host|name)[:=]\s*([a-zA-Z0-9\-\.]+)', script_output, re.IGNORECASE)
                    for match in hostname_matches:
                        if '.' in match or len(match) > 3:
                            hostname_candidates.append(('hostscript', match))
            
            # Store all hostnames found (remove duplicates, keep unique names)
            if hostname_candidates:
                seen_names = set()
                unique_hostnames = []
                
                # Priority: dns/PTR > user > service > others
                priority_order = ['dns', 'PTR', 'user', 'service', 'service_product', 'script', 'hostscript']
                
                # First, add hostnames in priority order
                for priority in priority_order:
                    for source, name in hostname_candidates:
                        if source == priority and name not in seen_names:
                            unique_hostnames.append({'name': name, 'source_type': source})
                            seen_names.add(name)
                
                # Then add any remaining hostnames not in priority list
                for source, name in hostname_candidates:
                    if name not in seen_names:
                        unique_hostnames.append({'name': name, 'source_type': source})
                        seen_names.add(name)
                
                # Store all hostnames
                host_info['hostnames'] = unique_hostnames
                
                # Choose best hostname for backward compatibility (first one, which is highest priority)
                if unique_hostnames:
                    host_info['hostname'] = unique_hostnames[0]['name']
            
            # MAC address
            mac_elem = host_elem.find('.//address[@addrtype="mac"]')
            if mac_elem is not None:
                host_info['mac'] = mac_elem.get('addr')
                host_info['vendor'] = mac_elem.get('vendor')
            
            # Services (for service scans)
            for port_elem in host_elem.findall('.//port'):
                service_info = {
                    'port': int(port_elem.get('portid')),
                    'proto': port_elem.get('protocol', 'tcp'),
                    'state': 'closed',
                    'name': '',
                    'product': '',
                    'version': '',
                    'extra_info': '',
                }
                
                state_elem = port_elem.find('state')
                if state_elem is not None:
                    service_info['state'] = state_elem.get('state', 'closed')
                
                service_elem = port_elem.find('service')
                if service_elem is not None:
                    service_info['name'] = service_elem.get('name', '')
                    service_info['product'] = service_elem.get('product', '')
                    service_info['version'] = service_elem.get('version', '')
                    extra = service_elem.get('extrainfo', '')
                    if extra:
                        service_info['extra_info'] = extra
                
                if service_info['state'] in ['open', 'open|filtered']:
                    host_info['services'].append(service_info)
            
            # OS detection
            os_elem = host_elem.find('os')
            if os_elem is not None:
                # Get the best OS match (highest accuracy)
                osmatches = os_elem.findall('osmatch')
                if osmatches:
                    best_match = None
                    best_accuracy = 0
                    for osmatch in osmatches:
                        accuracy = int(osmatch.get('accuracy', 0))
                        if accuracy > best_accuracy:
                            best_accuracy = accuracy
                            best_match = osmatch
                    
                    if best_match:
                        os_name = best_match.get('name', '')
                        os_accuracy = best_match.get('accuracy', '0')
                        host_info['os'] = os_name
                        host_info['os_accuracy'] = os_accuracy
                        
                        # Try to get OS class for more details
                        osclass_elem = best_match.find('osclass')
                        if osclass_elem is not None:
                            os_type = osclass_elem.get('type', '')
                            os_vendor = osclass_elem.get('vendor', '')
                            os_family = osclass_elem.get('osfamily', '')
                            if os_type or os_vendor or os_family:
                                os_details = []
                                if os_vendor:
                                    os_details.append(os_vendor)
                                if os_family:
                                    os_details.append(os_family)
                                if os_type:
                                    os_details.append(os_type)
                                if os_details:
                                    host_info['os'] = f"{os_name} ({', '.join(os_details)})"
            
            if host_info['ip']:
                hosts.append(host_info)
        
        return {'hosts': hosts}
    except ET.ParseError as e:
        logger.error(f"Failed to parse nmap XML: {e}")
        return {'hosts': []}
    except Exception as e:
        logger.error(f"Error parsing nmap XML: {e}")
        return {'hosts': []}
