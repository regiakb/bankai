# Deploy Bankai in an LXC

Deploying Bankai in an LXC (e.g. on Proxmox) means installing the app on a minimal Linux system: Python, dependencies, Nmap, and a systemd service.

## 0. From the Proxmox node (all-in-one)

To run a script **on the Proxmox host** that creates the LXC and installs Bankai inside (helper-script style):

1. Copy the script to the node (or clone the repo on the node).
2. On the node, as root:

```bash
# Option A: download the script and run it (requires curl and node network)
curl -sSL https://raw.githubusercontent.com/regiakb/bankai/main/scripts/proxmox-create-bankai-lxc.sh -o /tmp/proxmox-create-bankai-lxc.sh
chmod +x /tmp/proxmox-create-bankai-lxc.sh
/tmp/proxmox-create-bankai-lxc.sh

# Option B: clone the repo on the node and run
git clone https://github.com/regiakb/bankai.git /tmp/bankai
/tmp/bankai/scripts/proxmox-create-bankai-lxc.sh
```

**Credentials after creation:** LXC shell **root** / **bankai** (SSH or `pct enter <vmid>`). Bankai web at `http://<LXC-IP>:8000` with **admin** / **bankai**.

Optional environment variables: `VMID`, `STORAGE`, `TEMPLATE`, `HOSTNAME`, `MEMORY`, `BRIDGE`, `ROOT_PASSWORD` (default: bankai). Example: `VMID=200 ROOT_PASSWORD=mypass ./proxmox-create-bankai-lxc.sh`.

The script downloads an LXC template if needed (Debian 12 or Ubuntu).

## 1. Create the LXC manually

- **Proxmox:** Create CT → choose template (Debian 12 or Ubuntu 22.04), set resources (512 MB RAM is usually enough to start), network.
- **Standalone LXC:** Create a container with your base distro (Debian/Ubuntu recommended).

## 2. Inside the LXC: requirements

- Base system: **Debian 12** or **Ubuntu 22.04** (or another with Python 3.11).
- Network so the LXC can run `apt update`, clone the repo, and you can reach it by IP.

## 3. Automatic installation (recommended)

**One-liner** (inside the LXC, as root):

```bash
apt update && apt install -y git && git clone https://github.com/regiakb/bankai.git /opt/bankai && /opt/bankai/scripts/install-lxc.sh
```

Or step by step:

```bash
apt update && apt install -y git
git clone https://github.com/regiakb/bankai.git /opt/bankai
/opt/bankai/scripts/install-lxc.sh
```

(If the repo is already in another path: `BANKAI_ROOT=/path/to/repo ./scripts/install-lxc.sh`)

The script installs system dependencies, Python, creates a venv, installs the app, runs migrations and default user, and sets up a systemd service that runs Gunicorn (plus telegram and scheduler in the background).

## 4. Manual installation (summary)

```bash
# System dependencies
apt update && apt install -y python3 python3-pip python3-venv nmap net-tools git

# App
git clone https://github.com/regiakb/bankai.git /opt/bankai
cd /opt/bankai
python3 -m venv /opt/bankai/venv
/opt/bankai/venv/bin/pip install -r requirements.txt
/opt/bankai/venv/bin/python manage.py migrate --noinput
/opt/bankai/venv/bin/python manage.py create_default_user
/opt/bankai/venv/bin/python manage.py collectstatic --noinput

# systemd service (create /etc/systemd/system/bankai.service as in the script)
systemctl daemon-reload && systemctl enable --now bankai
```

The app listens on port **8000**. Default user: **admin** / **bankai**.

## 5. Access

- **LXC shell:** user **root**, password **bankai** (or the one set with `ROOT_PASSWORD`). Use `ssh root@<LXC-IP>` or from the node `pct enter <vmid>`.
- **Bankai web:** `http://<LXC-IP>:8000` — user **admin**, password **bankai**.
- On Proxmox, ensure port 8000 is reachable (or use a reverse proxy if you prefer).

## 6. Persistence

The database and app data live under `/opt/bankai/data/` (or wherever you installed the app). Back up that directory (or at least `data/db.sqlite3`) for backups.

---

It’s not much more involved than a minimal server: the same app as in Docker, but installed directly in the LXC with systemd.
