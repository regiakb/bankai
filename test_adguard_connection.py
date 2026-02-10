#!/usr/bin/env python
"""
Script de prueba para diagnosticar la conexión con AdGuard Home.
"""
import os
import sys
import django

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bankai.settings')
django.setup()

import requests
from requests.auth import HTTPBasicAuth
from inventory.models import IntegrationConfig

def test_adguard_connection():
    """Test AdGuard Home connection with detailed diagnostics."""
    print("=" * 60)
    print("Test de conexión con AdGuard Home")
    print("=" * 60)
    
    # Get integration config
    try:
        integration = IntegrationConfig.objects.get(name='adguard')
    except IntegrationConfig.DoesNotExist:
        print("❌ Error: No se encontró la configuración de AdGuard Home")
        print("   Por favor, crea la integración en el admin primero.")
        return
    
    if not integration.enabled:
        print("⚠️  Advertencia: La integración está deshabilitada")
    
    url = integration.get_config('url', '')
    username = integration.get_config('username', '')
    password = integration.get_config('password', '')
    
    print(f"\n📋 Configuración:")
    print(f"   URL: {url}")
    print(f"   Username: {username}")
    print(f"   Password: {'*' * len(password) if password else '(vacío)'}")
    
    if not all([url, username, password]):
        print("\n❌ Error: Faltan credenciales")
        print("   Por favor, completa la configuración en el admin.")
        return
    
    # Clean URL
    url = url.rstrip('/')
    
    print(f"\n🔍 Probando conexión a: {url}")
    
    # Test 1: Basic connectivity
    print("\n1️⃣  Test de conectividad básica...")
    try:
        response = requests.get(f"{url}/control/status", timeout=5, verify=False)
        print(f"   Status code: {response.status_code}")
        if response.status_code == 401:
            print("   ✓ El servidor responde (requiere autenticación)")
        elif response.status_code == 200:
            print("   ✓ El servidor responde (sin autenticación requerida)")
        else:
            print(f"   ⚠️  Respuesta inesperada: {response.status_code}")
    except requests.exceptions.ConnectionError:
        print("   ❌ Error: No se puede conectar al servidor")
        print("   Verifica que la URL sea correcta y que AdGuard Home esté ejecutándose")
        return
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return
    
    # Test 2: Authentication with HTTPBasicAuth
    print("\n2️⃣  Test de autenticación con HTTPBasicAuth...")
    try:
        auth = HTTPBasicAuth(username, password)
        response = requests.get(
            f"{url}/control/status",
            auth=auth,
            timeout=10,
            verify=False
        )
        print(f"   Status code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            version = data.get('version', 'unknown')
            dns_enabled = data.get('dns_enabled', False)
            print(f"   ✓ Autenticación exitosa!")
            print(f"   Versión: {version}")
            print(f"   DNS habilitado: {dns_enabled}")
        elif response.status_code == 401:
            print("   ❌ Autenticación fallida: Usuario o contraseña incorrectos")
            print("   Verifica las credenciales en AdGuard Home")
        else:
            print(f"   ⚠️  Respuesta inesperada: {response.status_code}")
            print(f"   Respuesta: {response.text[:200]}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Test 3: Authentication with tuple (old method)
    print("\n3️⃣  Test de autenticación con tupla (método antiguo)...")
    try:
        response = requests.get(
            f"{url}/control/status",
            auth=(username, password),
            timeout=10,
            verify=False
        )
        print(f"   Status code: {response.status_code}")
        if response.status_code == 200:
            print("   ✓ Autenticación exitosa con tupla también")
        elif response.status_code == 401:
            print("   ❌ Autenticación fallida con tupla")
        else:
            print(f"   ⚠️  Respuesta inesperada: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Test 4: Try to get clients list
    print("\n4️⃣  Test de acceso a la API (listar clientes)...")
    try:
        auth = HTTPBasicAuth(username, password)
        response = requests.get(
            f"{url}/control/clients",
            auth=auth,
            timeout=10,
            verify=False
        )
        print(f"   Status code: {response.status_code}")
        if response.status_code == 200:
            clients = response.json()
            client_list = clients.get('clients', [])
            print(f"   ✓ Acceso a la API exitoso!")
            print(f"   Clientes encontrados: {len(client_list)}")
            if client_list:
                print("   Primeros clientes:")
                for client in client_list[:3]:
                    name = client.get('name', 'Sin nombre')
                    print(f"     - {name}")
        elif response.status_code == 401:
            print("   ❌ Autenticación fallida al acceder a la API")
        else:
            print(f"   ⚠️  Respuesta inesperada: {response.status_code}")
            print(f"   Respuesta: {response.text[:200]}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print("\n" + "=" * 60)
    print("Test completado")
    print("=" * 60)

if __name__ == '__main__':
    test_adguard_connection()
