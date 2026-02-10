#!/bin/sh
set -e
# Ensure database directory exists when using DATABASE_PATH (e.g. /app/data)
if [ -n "$DATABASE_PATH" ]; then
  mkdir -p "$(dirname "$DATABASE_PATH")"
  DB_FILE="$DATABASE_PATH"
else
  if [ "$(pwd)" = "/app" ]; then
    DB_FILE="/app/data/db.sqlite3"
    mkdir -p /app/data
  else
    DB_FILE="./db.sqlite3"
  fi
fi
DB_DIR="$(dirname "$DB_FILE")"
RESTORE_PENDING="$DB_DIR/db_restore_pending.sqlite3"
# Apply pending restore (uploaded from Settings) before migrations
if [ -f "$RESTORE_PENDING" ]; then
  echo "Applying pending database restore..."
  mv "$RESTORE_PENDING" "$DB_FILE"
  echo "Restore applied. Running migrations..."
fi
# Run migrations and initial setup so the app works on first start (no manual steps)
python manage.py migrate --noinput
python manage.py init_config 2>/dev/null || true
python manage.py create_default_user 2>/dev/null || true
python manage.py collectstatic --noinput 2>/dev/null || true
exec "$@"
