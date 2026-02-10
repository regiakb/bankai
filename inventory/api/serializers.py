"""
REST API serializers for inventory.
"""
from rest_framework import serializers
from inventory.models import Host, IPAddress, Service, Alert, InterfaceAttachment


class InterfaceAttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = InterfaceAttachment
        fields = ['id', 'medium', 'ssid', 'switch_port', 'last_seen']


class IPAddressSerializer(serializers.ModelSerializer):
    host_name = serializers.CharField(source='host.name', read_only=True)
    
    class Meta:
        model = IPAddress
        fields = ['id', 'ip', 'host', 'host_name', 'assignment', 'first_seen', 'last_seen', 'online']


class ServiceSerializer(serializers.ModelSerializer):
    host_name = serializers.CharField(source='host.name', read_only=True)
    
    class Meta:
        model = Service
        fields = [
            'id', 'host', 'host_name', 'port', 'proto', 'name',
            'product', 'version', 'extra_info', 'first_seen', 'last_seen'
        ]


class HostSerializer(serializers.ModelSerializer):
    ip_addresses = IPAddressSerializer(many=True, read_only=True)
    interfaces = InterfaceAttachmentSerializer(many=True, read_only=True)
    services = ServiceSerializer(many=True, read_only=True)
    
    class Meta:
        model = Host
        fields = [
            'id', 'name', 'mac', 'vendor', 'device_type', 'source',
            'notes', 'first_seen', 'last_seen', 'is_active',
            'ip_addresses', 'interfaces', 'services'
        ]


class AlertSerializer(serializers.ModelSerializer):
    related_host_name = serializers.CharField(source='related_host.name', read_only=True)
    related_ip_address = serializers.CharField(source='related_ip.ip', read_only=True)
    
    class Meta:
        model = Alert
        fields = [
            'id', 'type', 'message', 'created_at',
            'related_host', 'related_host_name',
            'related_ip', 'related_ip_address'
        ]
