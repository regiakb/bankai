"""
URL configuration for inventory app.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from .api import views as api_views

# Web views
urlpatterns = [
    path('settings/', views.settings_index, name='settings_index'),
    path('settings/db-backup/', views.db_backup, name='db_backup'),
    path('settings/db-restore/', views.db_restore, name='db_restore'),
    path('setup/', views.setup_wizard, name='setup_wizard'),
    path('integrations/', views.integrations_list, name='integrations_list'),
    path('integrations/add/<str:integration_type>/', views.integration_add, name='integration_add'),
    path('integrations/<int:pk>/edit/', views.integration_edit, name='integration_edit'),
    path('integrations/<int:pk>/delete/', views.integration_delete, name='integration_delete'),
    path('', views.dashboard, name='dashboard'),
    path('hosts/', views.hosts_list, name='hosts'),
    path('hosts/connection-history/', views.connection_history, name='connection_history'),
    path('hosts/<int:host_id>/edit/', views.edit_host, name='edit_host'),
    path('hosts/<int:host_id>/delete/', views.delete_host, name='delete_host'),
    path('hosts/<int:host_id>/add-ip/', views.add_host_ip, name='add_host_ip'),
    path('hosts/<int:host_id>/delete-ip/', views.delete_host_ip, name='delete_host_ip'),
    path('hosts/<int:host_id>/add-hostname/', views.add_host_hostname, name='add_host_hostname'),
    path('hosts/<int:host_id>/delete-hostname/', views.delete_host_hostname, name='delete_host_hostname'),
    path('hosts/<int:host_id>/scan/<str:ip_address>/', views.scan_host_ip, name='scan_host_ip'),
    path('hosts/<int:host_id>/rescan/', views.host_rescan, name='host_rescan'),
    path('hosts/<int:host_id>/status/', views.host_status, name='host_status'),
    path('hosts/<int:host_id>/merge/<int:other_host_id>/', views.merge_hosts, name='merge_hosts'),
    path('hosts/merge-duplicates/', views.merge_duplicates, name='merge_duplicates'),
    path('alerts/', views.alerts_list, name='alerts'),
    path('alerts/<int:alert_id>/delete/', views.delete_alert, name='delete_alert'),
    path('alerts/delete-all/', views.delete_all_alerts, name='delete_all_alerts'),
    path('tasks/', views.tasks_view, name='tasks'),
    path('tasks/executions/', views.task_executions_list_api, name='task_executions_api'),
    path('tasks/<int:task_id>/delete/', views.delete_task_execution, name='delete_task_execution'),
    path('export/hosts.csv', views.export_hosts_csv, name='export_hosts_csv'),
    path('export/services.csv', views.export_services_csv, name='export_services_csv'),
    path('api/run-command/', views.run_command, name='run_command'),
    path('api/telegram/test-notification/', views.telegram_test_notification, name='telegram_test_notification'),
    path('api/telegram/webhook/<int:integration_id>/', views.telegram_webhook, name='telegram_webhook'),
    path('api/telegram/set-webhook/<int:integration_id>/', views.telegram_set_webhook, name='telegram_set_webhook'),
]

# Users management (solo apartado de usuarios: crear, editar, cambiar password)
from . import admin_views
urlpatterns += [
    path('users/', admin_views.admin_users, name='users_list'),
    path('users/create/', admin_views.admin_user_create, name='user_create'),
    path('users/<int:user_id>/', admin_views.admin_user_detail, name='user_detail'),
]

# API routes
router = DefaultRouter()
router.register(r'hosts', api_views.HostViewSet, basename='host')
router.register(r'ips', api_views.IPAddressViewSet, basename='ip')
router.register(r'services', api_views.ServiceViewSet, basename='service')
router.register(r'alerts', api_views.AlertViewSet, basename='alert')

urlpatterns += [path('api/', include(router.urls))]
