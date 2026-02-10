<div align="center">
  <img src="static/images/logo.png" alt="Bankai logo" width="200">
</div>

<div align="center">

# Bankai

**Network inventory & monitoring — discover, scan, alert.**

*One panel for host discovery (Nmap), Proxmox & AdGuard sync, and Telegram alerts.*

</div>

---
<div align="center">
  <img src="https://i.ibb.co/pv6qwSrT/banaki1.png">
  <img src="https://i.ibb.co/gbV7JmSN/banaki2.png">
  <img src="https://i.ibb.co/vxqY0h9j/banaki3.png">
  <img src="https://i.ibb.co/yFfHx91r/banaki4.png">
</div>

## Features

- **Host inventory**: manual hosts, discovered via Nmap, Proxmox or Docker
- **Scans**: discovery and service detection with Nmap
- **Integrations**: Proxmox, AdGuard, Telegram bot for alerts
- **Alerts**: new IP, new service, host down, status changes
- **Scheduled tasks**: scheduler for scans and sync jobs
- **REST API** for integration with other systems

## Tech stack

- **Backend**: Django 5, Django REST Framework
- **Scanning**: Nmap (python-nmap)
- **Integrations**: Proxmox (proxmoxer), AdGuard, Telegram, Docker
- **Server**: Gunicorn
- **Deployment**: Docker / Docker Compose

## Requirements

- Docker and Docker Compose (recommended), or
- Python 3.11+, Nmap installed on the system

## Quick start with Docker

```bash
git clone https://github.com/regiakb/bankai.git
cd bankai
docker compose up -d
```

The app will be available at **http://localhost:8000**.  
On first run, migrations, default user creation and static collection run automatically.

Or pull the image from Docker Hub:

```bash
docker pull regiakb7/bankai:latest
# Use with your own docker-compose or: docker run -p 8000:8000 regiakb7/bankai:latest
```

### Environment variables (optional)

You can use a `.env` file in the project root:

| Variable        | Description                          | Default (example)           |
|-----------------|--------------------------------------|-----------------------------|
| `SECRET_KEY`    | Django secret key                    | (change in production)      |
| `DEBUG`         | Debug mode                           | `True`                      |
| `ALLOWED_HOSTS` | Allowed hosts (comma-separated)      | `localhost,127.0.0.1`      |

These can also be set in `docker-compose.yml` under the `environment` section.

## Run without Docker

```bash
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
pip install -r requirements.txt
# Install Nmap on your system
python manage.py migrate
python manage.py init_config
python manage.py create_default_user
python manage.py runserver
```

## Deploy on LXC (e.g. Proxmox)

**From the Proxmox node** (creates the LXC and installs Bankai inside):

```bash
curl -sSL https://raw.githubusercontent.com/regiakb/bankai/main/scripts/proxmox-create-bankai-lxc.sh -o /tmp/proxmox-create-bankai-lxc.sh && chmod +x /tmp/proxmox-create-bankai-lxc.sh && /tmp/proxmox-create-bankai-lxc.sh
```

**From inside an existing LXC** (one-liner as root):

```bash
apt update && apt install -y git && git clone https://github.com/regiakb/bankai.git /opt/bankai && /opt/bankai/scripts/install-lxc.sh
```

Full guide: **[docs/DEPLOY_LXC.md](docs/DEPLOY_LXC.md)**. App on port 8000, systemd service `bankai`.  
**LXC login:** root / bankai. **Bankai web:** admin / bankai.

## Default credentials

| Where        | User  | Password |
|-------------|-------|----------|
| Bankai web  | admin | bankai   |
| LXC (Proxmox script) | root  | bankai   |

## Project structure

- `bankai/` — Django config (settings, urls, wsgi)
- `inventory/` — Main app: models, views, API, management commands (scans, scheduler, Telegram, etc.)
- `templates/` — Templates (admin panel, login, inventory)
- `static/` — CSS and images

## License

See License.md



