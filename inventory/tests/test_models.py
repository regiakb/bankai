"""
Tests for inventory models.
"""
from django.test import TestCase
from django.utils import timezone
from inventory.models import (
    Host, IPAddress, Service, Alert, InterfaceAttachment,
    HostSource, MediumType, IPAssignment, AlertType
)


class HostModelTestCase(TestCase):
    """Test Host model."""
    
    def test_create_host(self):
        """Test creating a host."""
        host = Host.objects.create(
            name='test-host',
            mac='AA:BB:CC:DD:EE:FF',
            vendor='Test Vendor',
            source=HostSource.MANUAL,
        )
        self.assertEqual(str(host), 'test-host (AA:BB:CC:DD:EE:FF)')
        self.assertTrue(host.is_active)
        self.assertIsNotNone(host.first_seen)
        self.assertIsNotNone(host.last_seen)


class IPAddressModelTestCase(TestCase):
    """Test IPAddress model."""
    
    def test_create_ip(self):
        """Test creating an IP address."""
        host = Host.objects.create(name='test-host')
        ip = IPAddress.objects.create(
            ip='192.168.1.100',
            host=host,
            assignment=IPAssignment.DHCP,
        )
        self.assertEqual(str(ip), '192.168.1.100 (test-host)')
        self.assertTrue(ip.online)
    
    def test_create_ip_without_host(self):
        """Test creating an IP without a host."""
        ip = IPAddress.objects.create(
            ip='192.168.1.200',
            assignment=IPAssignment.STATIC,
        )
        self.assertIsNone(ip.host)
        self.assertEqual(str(ip), '192.168.1.200 (no host)')


class ServiceModelTestCase(TestCase):
    """Test Service model."""
    
    def test_create_service(self):
        """Test creating a service."""
        host = Host.objects.create(name='test-host')
        service = Service.objects.create(
            host=host,
            port=22,
            proto='tcp',
            name='ssh',
            product='OpenSSH',
        )
        self.assertEqual(str(service), 'test-host:22/tcp (ssh)')
        self.assertIsNotNone(service.first_seen)


class AlertModelTestCase(TestCase):
    """Test Alert model."""
    
    def test_create_alert(self):
        """Test creating an alert."""
        alert = Alert.objects.create(
            type=AlertType.NEW_IP,
            message='New IP detected: 192.168.1.100',
        )
        self.assertIn('New IP', str(alert))
        self.assertIsNotNone(alert.created_at)
    
    def test_create_alert_with_host(self):
        """Test creating an alert with related host."""
        host = Host.objects.create(name='test-host')
        ip = IPAddress.objects.create(ip='192.168.1.100', host=host)
        alert = Alert.objects.create(
            type=AlertType.NEW_IP,
            message='New IP detected',
            related_host=host,
            related_ip=ip,
        )
        self.assertEqual(alert.related_host, host)
        self.assertEqual(alert.related_ip, ip)
