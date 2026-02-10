#!/bin/sh
#
# Run on the Proxmox NODE (as root).
# Creates an LXC, starts it, and installs Bankai inside.
#
# Usage:
#   ./proxmox-create-bankai-lxc.sh
#   VMID=200 ./proxmox-create-bankai-lxc.sh
#
# Requirements on the node:
#   - LXC template (e.g. Debian 12 or Ubuntu 22.04)
#   - Download template if missing: pveam download node local:vztmpl/debian-12-standard_12.2-1_amd64.tar.zst
#

set -e

# --- Configuration (edit or export before running) ---
VMID="${VMID:-110}"
STORAGE="${STORAGE:-local-lvm}"
ROOTFS_SIZE="${ROOTFS_SIZE:-8}"
MEMORY="${MEMORY:-512}"
HOSTNAME="${HOSTNAME:-bankai}"
BRIDGE="${BRIDGE:-vmbr0}"
# Template: short name (searched in local:vztmpl/...) or full path
TEMPLATE="${TEMPLATE:-debian-12-standard}"

# --- Check we are on Proxmox ---
if ! command -v pct >/dev/null 2>&1; then
  echo "Error: 'pct' not found. Run this script on a Proxmox node (as root)."
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Error: run as root."
  exit 1
fi

# --- Resolve template ---
case "$TEMPLATE" in
  */*|*:*) ;;
  *)
    # Look up in local:vztmpl (pveam list usually returns just the filename)
    TPL_FILE=$(pveam list local:vztmpl 2>/dev/null | grep -i "$TEMPLATE" | head -1 | awk '{print $1}')
    if [ -z "$TPL_FILE" ]; then
      # Auto-download Debian 12 template if default and none found
      if [ "$TEMPLATE" = "debian-12-standard" ]; then
        echo "[*] No template found. Updating template list and downloading Debian 12..."
        pveam update >/dev/null 2>&1 || true
        # Template name must come from 'pveam available' (e.g. debian-12-standard_12.7-1_amd64.tar.zst)
        TPL_DOWNLOAD=$(pveam available --section system 2>/dev/null | grep -i "debian-12-standard" | head -1 | awk '{print $1}')
        if [ -n "$TPL_DOWNLOAD" ]; then
          echo "[*] Downloading $TPL_DOWNLOAD (this may take a few minutes)..."
          if pveam download local "$TPL_DOWNLOAD"; then
            TPL_FILE="$TPL_DOWNLOAD"
          fi
        fi
      fi
    fi
    if [ -z "$TPL_FILE" ]; then
      echo "Error: no template found matching '$TEMPLATE'."
      echo "Available on node:"
      pveam list local:vztmpl 2>/dev/null || true
      echo ""
      echo "Download manually: pveam update && pveam available --section system"
      echo "  Then: pveam download local <template_name_from_list>"
      exit 1
    fi
    TEMPLATE="local:vztmpl/${TPL_FILE}"
    ;;
esac

# --- Check VMID does not already exist ---
if pct status "$VMID" >/dev/null 2>&1; then
  echo "Error: container $VMID already exists. Use another VMID: VMID=200 $0"
  exit 1
fi

echo "[*] Creating LXC $VMID ($HOSTNAME) with template $TEMPLATE ..."
pct create "$VMID" "$TEMPLATE" \
  --hostname "$HOSTNAME" \
  --memory "$MEMORY" \
  --cores 1 \
  --rootfs "$STORAGE:${ROOTFS_SIZE}" \
  --net0 "name=eth0,bridge=$BRIDGE,ip=dhcp" \
  --unprivileged 0

echo "[*] Starting container $VMID ..."
pct start "$VMID"

echo "[*] Waiting for network inside container..."
i=0
while [ $i -lt 30 ]; do
  if pct exec "$VMID" -- ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  sleep 2
done
sleep 2

echo "[*] Installing Bankai inside LXC (may take a few minutes)..."
pct exec "$VMID" -- sh -c "apt-get update -qq && apt-get install -y -qq git && git clone --depth 1 https://github.com/regiakb/bankai.git /opt/bankai && /opt/bankai/scripts/install-lxc.sh"

CT_IP=$(pct exec "$VMID" -- hostname -I 2>/dev/null | awk '{print $1}')
echo ""
echo "=============================================="
echo "  Bankai installed in LXC $VMID ($HOSTNAME)"
echo "=============================================="
echo "  IP (approx):  $CT_IP"
echo "  URL:          http://${CT_IP}:8000"
echo "  User:         admin"
echo "  Password:     bankai"
echo ""
echo "  Useful commands:"
echo "    pct enter $VMID   - enter container"
echo "    pct stop $VMID    - stop"
echo "    pct start $VMID   - start"
echo "=============================================="
