#!/bin/sh
# Installs Bankai inside an LXC (Debian/Ubuntu). Run as root.
# Usage: ./install-lxc.sh   (from /opt/bankai after cloning the repo)
#   or:  BANKAI_ROOT=/opt/bankai ./install-lxc.sh

set -e
APP_DIR="${BANKAI_ROOT:-/opt/bankai}"

echo "[*] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv nmap net-tools iputils-ping git

if [ ! -f "$APP_DIR/manage.py" ]; then
  echo "[*] Cloning repository to $APP_DIR..."
  mkdir -p "$(dirname "$APP_DIR")"
  git clone --depth 1 https://github.com/regiakb/bankai.git "$APP_DIR"
fi

cd "$APP_DIR"
echo "[*] Creating venv and installing Python dependencies..."
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q -r requirements.txt

mkdir -p "$APP_DIR/data"
export DATABASE_PATH="$APP_DIR/data/db.sqlite3"
export MEDIA_ROOT="$APP_DIR/data/media"
export STATIC_ROOT="$APP_DIR/data/staticfiles"

echo "[*] Running migrations and default user..."
"$APP_DIR/venv/bin/python" manage.py migrate --noinput
"$APP_DIR/venv/bin/python" manage.py create_default_user 2>/dev/null || true
"$APP_DIR/venv/bin/python" manage.py collectstatic --noinput

echo "[*] Creating startup script and systemd service..."
cat > "$APP_DIR/start-bankai.sh" << 'START'
#!/bin/sh
cd "$(dirname "$0")"
python manage.py run_telegram_bot &
python manage.py scheduler &
exec gunicorn --bind 0.0.0.0:8000 --workers 4 --timeout 1200 --access-logfile - --error-logfile - bankai.wsgi:application
START
chmod +x "$APP_DIR/start-bankai.sh"

cat > /etc/systemd/system/bankai.service << EOF
[Unit]
Description=Bankai - Network inventory
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
Environment=PATH=$APP_DIR/venv/bin:/usr/local/bin:/usr/bin:/bin
Environment=DATABASE_PATH=$APP_DIR/data/db.sqlite3
Environment=MEDIA_ROOT=$APP_DIR/data/media
Environment=STATIC_ROOT=$APP_DIR/data/staticfiles
Environment=ALLOWED_HOSTS=*
ExecStart=$APP_DIR/start-bankai.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable bankai
systemctl start bankai

echo ""
echo "[OK] Bankai installed in $APP_DIR"
echo "     Service: systemctl status bankai"
echo "     Web:     http://<LXC-IP>:8000"
echo "     User:    admin / bankai"
echo "     Data:    $APP_DIR/data/"
echo ""
