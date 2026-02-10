#!/bin/sh
set -e
# Run migrations and initial setup so the app works after "docker run" or first start
python manage.py migrate --noinput
python manage.py init_config 2>/dev/null || true
python manage.py create_default_user 2>/dev/null || true
python manage.py collectstatic --noinput 2>/dev/null || true
exec "$@"
