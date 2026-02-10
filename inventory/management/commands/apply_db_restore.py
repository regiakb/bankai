"""
Apply a pending database restore (db_restore_pending.sqlite3) if present.
Use when you uploaded a backup via Settings but do not use the Docker entrypoint;
run this command then restart the application.
"""
from pathlib import Path
import shutil

from django.core.management.base import BaseCommand
from django.conf import settings
from django.db import connection


class Command(BaseCommand):
    help = 'Apply pending DB restore from db_restore_pending.sqlite3 (then restart the app)'

    def handle(self, *args, **options):
        db_name = settings.DATABASES['default']['NAME']
        db_path = Path(db_name)
        if not db_path.is_absolute():
            db_path = db_path.resolve()
        pending = db_path.parent / 'db_restore_pending.sqlite3'
        if not pending.exists():
            self.stdout.write(self.style.WARNING('No pending restore file found.'))
            return
        self.stdout.write('Closing DB connection and applying restore...')
        connection.close()
        shutil.copy2(pending, db_path)
        pending.unlink()
        self.stdout.write(self.style.SUCCESS('Restore applied. Restart the application.'))
