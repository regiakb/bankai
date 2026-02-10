"""
REST API views for inventory.
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.http import HttpResponse
from inventory.models import Host, IPAddress, Service, Alert
from .serializers import (
    HostSerializer, IPAddressSerializer, ServiceSerializer, AlertSerializer
)
import csv
import io


class HostViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Host.objects.prefetch_related('ip_addresses', 'interfaces', 'services').all()
    serializer_class = HostSerializer
    
    @action(detail=False, methods=['get'])
    def export_csv(self, request):
        """Export hosts as CSV."""
        hosts = self.get_queryset()
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="hosts.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Name', 'MAC', 'Vendor', 'Device Type', 'Source', 'IP Addresses', 'First Seen', 'Last Seen'])
        
        for host in hosts:
            ips = ', '.join([ip.ip for ip in host.ip_addresses.all()])
            writer.writerow([
                host.name, host.mac or '', host.vendor or '', host.device_type,
                host.get_source_display(), ips, host.first_seen, host.last_seen
            ])
        
        return response


class IPAddressViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = IPAddress.objects.select_related('host').all()
    serializer_class = IPAddressSerializer


class ServiceViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Service.objects.select_related('host').all()
    serializer_class = ServiceSerializer
    
    @action(detail=False, methods=['get'])
    def export_csv(self, request):
        """Export services as CSV."""
        services = self.get_queryset()
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="services.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Host', 'Port', 'Protocol', 'Name', 'Product', 'Version', 'First Seen', 'Last Seen'])
        
        for service in services:
            writer.writerow([
                service.host.name, service.port, service.proto, service.name,
                service.product, service.version, service.first_seen, service.last_seen
            ])
        
        return response


class AlertViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Alert.objects.select_related('related_host', 'related_ip').all()
    serializer_class = AlertSerializer
