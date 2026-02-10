"""
Tests for nmap XML parser.
"""
from django.test import TestCase
from inventory.services.nmap_parser import parse_nmap_xml


class NmapParserTestCase(TestCase):
    """Test nmap XML parsing."""
    
    def test_parse_simple_host(self):
        """Test parsing a simple host entry."""
        xml = """<?xml version="1.0"?>
<nmaprun>
    <host>
        <status state="up"/>
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <hostnames>
            <hostname name="router.local"/>
        </hostnames>
    </host>
</nmaprun>"""
        
        result = parse_nmap_xml(xml)
        self.assertEqual(len(result['hosts']), 1)
        self.assertEqual(result['hosts'][0]['ip'], '192.168.1.1')
        self.assertEqual(result['hosts'][0]['hostname'], 'router.local')
        self.assertEqual(result['hosts'][0]['status'], 'up')
    
    def test_parse_host_with_mac(self):
        """Test parsing host with MAC address."""
        xml = """<?xml version="1.0"?>
<nmaprun>
    <host>
        <status state="up"/>
        <address addr="192.168.1.100" addrtype="ipv4"/>
        <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Test Vendor"/>
        <hostnames>
            <hostname name="test.local"/>
        </hostnames>
    </host>
</nmaprun>"""
        
        result = parse_nmap_xml(xml)
        self.assertEqual(len(result['hosts']), 1)
        self.assertEqual(result['hosts'][0]['mac'], 'AA:BB:CC:DD:EE:FF')
        self.assertEqual(result['hosts'][0]['vendor'], 'Test Vendor')
    
    def test_parse_host_with_services(self):
        """Test parsing host with services."""
        xml = """<?xml version="1.0"?>
<nmaprun>
    <host>
        <status state="up"/>
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh" product="OpenSSH" version="8.0"/>
            </port>
            <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="nginx"/>
            </port>
        </ports>
    </host>
</nmaprun>"""
        
        result = parse_nmap_xml(xml)
        self.assertEqual(len(result['hosts']), 1)
        self.assertEqual(len(result['hosts'][0]['services']), 2)
        
        ssh_service = result['hosts'][0]['services'][0]
        self.assertEqual(ssh_service['port'], 22)
        self.assertEqual(ssh_service['proto'], 'tcp')
        self.assertEqual(ssh_service['name'], 'ssh')
        self.assertEqual(ssh_service['product'], 'OpenSSH')
        self.assertEqual(ssh_service['version'], '8.0')
    
    def test_parse_empty_xml(self):
        """Test parsing empty XML."""
        xml = """<?xml version="1.0"?>
<nmaprun>
</nmaprun>"""
        
        result = parse_nmap_xml(xml)
        self.assertEqual(len(result['hosts']), 0)
    
    def test_parse_invalid_xml(self):
        """Test parsing invalid XML."""
        xml = "not valid xml"
        
        result = parse_nmap_xml(xml)
        self.assertEqual(len(result['hosts']), 0)
