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
      echo "[*] No template found. Updating template list..."
      pveam update >/dev/null 2>&1 || true
      # Parse pveam available: each line is "section  template_name" - get the filename (field ending in .tar.zst/.tar.gz/.tar.xz)
      for want in "debian-12-standard" "ubuntu-22.04-standard" "ubuntu-24.04-standard"; do
        TPL_DOWNLOAD=$(pveam available 2>/dev/null | grep "system" | grep -i "$want" | head -1 | awk '{for(i=1;i<=NF;i++) if($i ~ /\.(tar\.zst|tar\.gz|tar\.xz)$/) {print $i; exit}}')
        if [ -n "$TPL_DOWNLOAD" ]; then
          echo "[*] Downloading $TPL_DOWNLOAD (this may take a few minutes)..."
          if pveam download local "$TPL_DOWNLOAD"; then
            TPL_FILE="$TPL_DOWNLOAD"
            break
          fi
        fi
      done
      # Fallback: use exact template name from Proxmox list (debian-12-standard_12.12-1_amd64.tar.zst)
      if [ -z "$TPL_FILE" ]; then
        for exact in "debian-12-standard_12.12-1_amd64.tar.zst" "ubuntu-22.04-standard_22.04-1_amd64.tar.zst" "ubuntu-24.04-standard_24.04-2_amd64.tar.zst"; do
          echo "[*] Downloading $exact (this may take a few minutes)..."
          if pveam download local "$exact" 2>/dev/null; then
            TPL_FILE="$exact"
            break
          fi
        done
      fi
    fi
    if [ -z "$TPL_FILE" ]; then
      echo "Error: no template found matching '$TEMPLATE' and no alternate could be downloaded."
      echo "Available on node:"
      pveam list local:vztmpl 2>/dev/null || true
      echo ""
      echo "Run: pveam available"
      echo "Then: pveam download local <exact_template_name_from_list>"
      exit 1
    fi
    TEMPLATE="local:vztmpl/${TPL_FILE}"
    ;;
esac

# --- Resolve VMID: use next free if default is taken ---
if pct status "$VMID" >/dev/null 2>&1 || [ -f "/etc/pve/lxc/${VMID}.conf" ] 2>/dev/null || [ -f "/etc/pve/qemu-server/${VMID}.conf" ] 2>/dev/null; then
  if [ "${VMID}" = "110" ]; then
    NEXT=$(pvesh get /cluster/nextid 2>/dev/null) || NEXT=111
    VMID=$NEXT
    while pct status "$VMID" >/dev/null 2>&1 || [ -f "/etc/pve/lxc/${VMID}.conf" ] 2>/dev/null || [ -f "/etc/pve/qemu-server/${VMID}.conf" ] 2>/dev/null; do
      VMID=$((VMID + 1))
      [ $VMID -gt 999 ] && { echo "Error: no free VMID found (tried up to 999)."; exit 1; }
    done
    echo "[*] Default VMID 110 in use, using $VMID instead."
  else
    echo "Error: container $VMID already exists. Use another VMID: VMID=200 $0"
    exit 1
  fi
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
pct exec "$VMID" -- sh -c "apt-get update -qq && apt-get install -y -qq git && git clone --depth 1 https://github.com/regiakb/bankai.git /opt/bankai && chmod +x /opt/bankai/scripts/install-lxc.sh && /opt/bankai/scripts/install-lxc.sh"

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
