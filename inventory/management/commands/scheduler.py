"""
Management command to run scheduled tasks.
Replaces the shell script scheduler.
"""
import logging
import time
from zoneinfo import ZoneInfo
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.core.management import call_command
from inventory.config_manager import (
    get_discovery_cidr,
    get_discovery_interval,
    get_service_scan_interval,
    get_proxmox_sync_interval,
    get_adguard_sync_interval,
    ConfigManager
)

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Run scheduled network scans and syncs'

    def add_arguments(self, parser):
        parser.add_argument(
            '--once',
            action='store_true',
            help='Run all tasks once and exit (for testing)',
        )
        parser.add_argument(
            '--test-discovery',
            action='store_true',
            help='Run discovery scan immediately and exit (for testing)',
        )
        parser.add_argument(
            '--test-services',
            action='store_true',
            help='Run service scan immediately and exit (for testing)',
        )
        parser.add_argument(
            '--test-proxmox',
            action='store_true',
            help='Run Proxmox sync immediately and exit (for testing)',
        )
        parser.add_argument(
            '--test-adguard',
            action='store_true',
            help='Run AdGuard Home sync immediately and exit (for testing)',
        )

    def handle(self, *args, **options):
        run_once = options.get('once', False)
        test_discovery = options.get('test_discovery', False)
        test_services = options.get('test_services', False)
        test_proxmox = options.get('test_proxmox', False)
        test_adguard = options.get('test_adguard', False)
        
        # Handle test modes - run specific task immediately and exit
        if test_discovery:
            discovery_cidr = get_discovery_cidr()
            self.stdout.write(self.style.SUCCESS("Running discovery scan (test mode)..."))
            try:
                call_command('scan_discovery', '--cidr', discovery_cidr, verbosity=1)
                self.stdout.write(self.style.SUCCESS("Discovery scan completed"))
            except Exception as e:
                logger.error(f"Discovery scan failed: {e}")
                self.stdout.write(self.style.ERROR(f"Discovery scan failed: {e}"))
            return
        
        if test_services:
            self.stdout.write(self.style.SUCCESS("Running service scan (test mode)..."))
            try:
                call_command('scan_services', '--targets', 'from_db', '--top-ports', '200', '--version-detect', verbosity=1)
                self.stdout.write(self.style.SUCCESS("Service scan completed"))
            except Exception as e:
                logger.error(f"Service scan failed: {e}")
                self.stdout.write(self.style.ERROR(f"Service scan failed: {e}"))
            return
        
        if test_proxmox:
            self.stdout.write(self.style.SUCCESS("Running Proxmox sync (test mode)..."))
            try:
                call_command('sync_proxmox', verbosity=1)
                self.stdout.write(self.style.SUCCESS("Proxmox sync completed"))
            except Exception as e:
                logger.error(f"Proxmox sync failed: {e}")
                self.stdout.write(self.style.ERROR(f"Proxmox sync failed: {e}"))
            return
        
        if test_adguard:
            self.stdout.write(self.style.SUCCESS("Running AdGuard Home sync (test mode)..."))
            try:
                call_command('sync_adguard', verbosity=1)
                self.stdout.write(self.style.SUCCESS("AdGuard Home sync completed"))
            except Exception as e:
                logger.error(f"AdGuard Home sync failed: {e}")
                self.stdout.write(self.style.ERROR(f"AdGuard Home sync failed: {e}"))
            return

        # NOTE: We re-read configuration periodically so changes in Settings take effect without restart.
        scheduler_start_hour = ConfigManager.get_int('SCHEDULER_START_HOUR', 0)
        scheduler_start_minute = ConfigManager.get_int('SCHEDULER_START_MINUTE', 0)
        discovery_offset_min = ConfigManager.get_int('SCHEDULER_DISCOVERY_DELAY', 0)
        service_offset_min = ConfigManager.get_int('SCHEDULER_SERVICE_DELAY', 20)
        proxmox_offset_min = ConfigManager.get_int('SCHEDULER_PROXMOX_DELAY', 40)
        adguard_offset_min = ConfigManager.get_int('SCHEDULER_ADGUARD_DELAY', 50)
        discovery_cidr = get_discovery_cidr()
        discovery_interval = get_discovery_interval()  # minutes
        service_scan_interval = get_service_scan_interval()  # minutes
        proxmox_sync_interval = get_proxmox_sync_interval()  # minutes
        adguard_sync_interval = get_adguard_sync_interval()  # minutes

        self.stdout.write(self.style.SUCCESS("BANKAI Scheduler started"))
        self.stdout.write("=" * 50)
        self.stdout.write(f"Discovery CIDR: {discovery_cidr}")
        self.stdout.write(f"Start time: {scheduler_start_hour:02d}:{scheduler_start_minute:02d}")
        self.stdout.write(f"Discovery interval: {discovery_interval} minutes (delay: {discovery_offset_min} min)")
        self.stdout.write(f"Service scan interval: {service_scan_interval} minutes (delay: {service_offset_min} min)")
        self.stdout.write(f"Proxmox sync interval: {proxmox_sync_interval} minutes (delay: {proxmox_offset_min} min)")
        self.stdout.write(f"AdGuard Home sync interval: {adguard_sync_interval} minutes (delay: {adguard_offset_min} min)")
        self.stdout.write("=" * 50)
        
        # Track last run times (will be set after first execution)
        last_discovery = None
        last_service_scan = None
        last_proxmox_sync = None
        last_adguard_sync = None
        
        madrid_tz = ZoneInfo('Europe/Madrid')
        last_config = None
        
        def should_run_now(offset_minutes, last_run_time, interval_minutes):
            """Check if task should run now based on start time, offset, and interval."""
            from datetime import datetime, timedelta
            now_madrid = timezone.now().astimezone(madrid_tz)
            current_second = now_madrid.second
            
            # If we have a last run time, check if enough time has passed
            if last_run_time:
                last_run_madrid = last_run_time.astimezone(madrid_tz)
                time_since_last = (now_madrid - last_run_madrid).total_seconds() / 60
                # Run if at least 90% of interval has passed (with 5 second tolerance)
                if time_since_last >= (interval_minutes * 0.9) and current_second < 5:
                    return True
                return False
            
            # If no last run, calculate first run time based on start time + offset
            # Calculate target minute: start_minute + offset
            target_minute = (scheduler_start_minute + offset_minutes) % 60
            target_hour_offset = (scheduler_start_minute + offset_minutes) // 60
            target_hour = (scheduler_start_hour + target_hour_offset) % 24
            
            # Check if we're at or past the target time today
            target_time_today = now_madrid.replace(hour=target_hour, minute=target_minute, second=0, microsecond=0)
            if target_hour < scheduler_start_hour or (target_hour == scheduler_start_hour and target_minute < scheduler_start_minute):
                # Target is tomorrow
                target_time_today = target_time_today + timedelta(days=1)
            
            # If we're at or past the target time (with 5 second tolerance), run
            if now_madrid >= target_time_today and current_second < 5:
                return True
            
            return False
        
        try:
            while True:
                now_madrid = timezone.now().astimezone(madrid_tz)

                # Refresh configuration on each loop so DB updates take effect without restart
                scheduler_start_hour = ConfigManager.get_int('SCHEDULER_START_HOUR', scheduler_start_hour)
                scheduler_start_minute = ConfigManager.get_int('SCHEDULER_START_MINUTE', scheduler_start_minute)
                discovery_offset_min = ConfigManager.get_int('SCHEDULER_DISCOVERY_DELAY', discovery_offset_min)
                service_offset_min = ConfigManager.get_int('SCHEDULER_SERVICE_DELAY', service_offset_min)
                proxmox_offset_min = ConfigManager.get_int('SCHEDULER_PROXMOX_DELAY', proxmox_offset_min)
                adguard_offset_min = ConfigManager.get_int('SCHEDULER_ADGUARD_DELAY', adguard_offset_min)
                discovery_cidr = get_discovery_cidr()
                discovery_interval = get_discovery_interval()  # minutes
                service_scan_interval = get_service_scan_interval()  # minutes
                proxmox_sync_interval = get_proxmox_sync_interval()  # minutes
                adguard_sync_interval = get_adguard_sync_interval()  # minutes

                cfg = (
                    scheduler_start_hour,
                    scheduler_start_minute,
                    discovery_offset_min,
                    service_offset_min,
                    proxmox_offset_min,
                    adguard_offset_min,
                    discovery_cidr,
                    discovery_interval,
                    service_scan_interval,
                    proxmox_sync_interval,
                    adguard_sync_interval,
                )
                if last_config is None:
                    last_config = cfg
                elif cfg != last_config:
                    last_config = cfg
                    self.stdout.write(self.style.WARNING("\nScheduler config updated (live reload):"))
                    self.stdout.write(f"  Discovery CIDR: {discovery_cidr}")
                    self.stdout.write(f"  Start time: {scheduler_start_hour:02d}:{scheduler_start_minute:02d}")
                    self.stdout.write(f"  Discovery interval: {discovery_interval} min (delay: {discovery_offset_min} min)")
                    self.stdout.write(f"  Service scan interval: {service_scan_interval} min (delay: {service_offset_min} min)")
                    self.stdout.write(f"  Proxmox sync interval: {proxmox_sync_interval} min (delay: {proxmox_offset_min} min)")
                    self.stdout.write(f"  AdGuard sync interval: {adguard_sync_interval} min (delay: {adguard_offset_min} min)")
                
                # Discovery scan
                if should_run_now(discovery_offset_min, last_discovery, discovery_interval):
                    self.stdout.write(f"\n[{now_madrid.strftime('%Y-%m-%d %H:%M:%S')}] Running discovery scan...")
                    self.stdout.write("=" * 60)
                    try:
                        call_command('scan_discovery', '--cidr', discovery_cidr, verbosity=1, stdout=self.stdout, stderr=self.stdout)
                        last_discovery = timezone.now()
                        now_madrid = timezone.now().astimezone(madrid_tz)
                        self.stdout.write("=" * 60)
                        self.stdout.write(self.style.SUCCESS(f"[{now_madrid.strftime('%Y-%m-%d %H:%M:%S')}] Discovery scan completed"))
                    except Exception as e:
                        logger.error(f"Discovery scan failed: {e}")
                        now_madrid = timezone.now().astimezone(madrid_tz)
                        self.stdout.write("=" * 60)
                        self.stdout.write(self.style.ERROR(f"[{now_madrid.strftime('%Y-%m-%d %H:%M:%S')}] Discovery scan failed: {e}"))
                
                # Service scan
                if should_run_now(service_offset_min, last_service_scan, service_scan_interval):
                    self.stdout.write(f"\n[{now_madrid.strftime('%Y-%m-%d %H:%M:%S')}] Running service scan...")
                    self.stdout.write("=" * 60)
                    try:
                        call_command('scan_services', '--targets', 'from_db', '--top-ports', '200', '--version-detect', verbosity=1, stdout=self.stdout, stderr=self.stdout)
                        last_service_scan = timezone.now()
                        now_madrid = timezone.now().astimezone(madrid_tz)
                        self.stdout.write("=" * 60)
                        self.stdout.write(self.style.SUCCESS(f"[{now_madrid.strftime('%Y-%m-%d %H:%M:%S')}] Service scan completed"))
                    except Exception as e:
                        logger.error(f"Service scan failed: {e}")
                        now_madrid = timezone.now().astimezone(madrid_tz)
                        self.stdout.write("=" * 60)
                        self.stdout.write(self.style.ERROR(f"[{now_madrid.strftime('%Y-%m-%d %H:%M:%S')}] Service scan failed: {e}"))
                
                # Proxmox sync
                if should_run_now(proxmox_offset_min, last_proxmox_sync, proxmox_sync_interval):
                    self.stdout.write(f"\n[{now_madrid.strftime('%Y-%m-%d %H:%M:%S')}] Syncing Proxmox...")
                    self.stdout.write("=" * 60)
                    try:
                        call_command('sync_proxmox', verbosity=1, stdout=self.stdout, stderr=self.stdout)
                        last_proxmox_sync = timezone.now()
                        now_madrid = timezone.now().astimezone(madrid_tz)
                        self.stdout.write("=" * 60)
                        self.stdout.write(self.style.SUCCESS(f"[{now_madrid.strftime('%Y-%m-%d %H:%M:%S')}] Proxmox sync completed"))
                    except Exception as e:
                        logger.error(f"Proxmox sync failed: {e}")
                        now_madrid = timezone.now().astimezone(madrid_tz)
                        self.stdout.write("=" * 60)
                        self.stdout.write(self.style.ERROR(f"[{now_madrid.strftime('%Y-%m-%d %H:%M:%S')}] Proxmox sync failed: {e}"))
                
                # AdGuard Home sync
                if should_run_now(adguard_offset_min, last_adguard_sync, adguard_sync_interval):
                    self.stdout.write(f"\n[{now_madrid.strftime('%Y-%m-%d %H:%M:%S')}] Syncing AdGuard Home...")
                    self.stdout.write("=" * 60)
                    try:
                        call_command('sync_adguard', verbosity=1, stdout=self.stdout, stderr=self.stdout)
                        last_adguard_sync = timezone.now()
                        now_madrid = timezone.now().astimezone(madrid_tz)
                        self.stdout.write("=" * 60)
                        self.stdout.write(self.style.SUCCESS(f"[{now_madrid.strftime('%Y-%m-%d %H:%M:%S')}] AdGuard Home sync completed"))
                    except Exception as e:
                        logger.error(f"AdGuard Home sync failed: {e}")
                        now_madrid = timezone.now().astimezone(madrid_tz)
                        self.stdout.write("=" * 60)
                        self.stdout.write(self.style.ERROR(f"[{now_madrid.strftime('%Y-%m-%d %H:%M:%S')}] AdGuard Home sync failed: {e}"))
                
                if run_once:
                    self.stdout.write(self.style.SUCCESS("\nRun once completed. Exiting."))
                    break
                
                # Sleep for 5 seconds before next check (to catch the exact minute)
                time.sleep(5)
                
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING("\nScheduler stopped by user"))
        except Exception as e:
            logger.error(f"Scheduler error: {e}")
            self.stdout.write(self.style.ERROR(f"Scheduler error: {e}"))
            raise
