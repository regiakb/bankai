#!/bin/sh
#
# Run on the Proxmox NODE (as root).
# Creates an LXC, starts it, and installs Bankai inside.
# LXC login: root / bankai (override with ROOT_PASSWORD=other)
#
# Usage:
#   ./proxmox-create-bankai-lxc.sh
#   VMID=200 ./proxmox-create-bankai-lxc.sh
#

set -e

# --- Configuration (edit or export before running) ---
VMID="${VMID:-110}"
STORAGE="${STORAGE:-local-lvm}"
ROOTFS_SIZE="${ROOTFS_SIZE:-8}"
MEMORY="${MEMORY:-512}"
HOSTNAME="${HOSTNAME:-bankai}"
BRIDGE="${BRIDGE:-vmbr0}"
# Root password for the LXC (default: bankai). Override with ROOT_PASSWORD=otherpass
ROOT_PASSWORD="${ROOT_PASSWORD:-bankai}"
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
    TPL_FILE=$(pveam list local:vztmpl 2>/dev/null | grep -i "$TEMPLATE" | head -1 | awk '{print $1}')
    if [ -z "$TPL_FILE" ]; then
      echo "[*] No template found. Updating template list..."
      pveam update >/dev/null 2>&1 || true
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
      echo "Error: no template found. Run: pveam available"
      exit 1
    fi
    TEMPLATE="local:vztmpl/${TPL_FILE}"
    ;;
esac

# --- Resolve VMID: if taken, use next available (so "VM already exists" never happens) ---
_vmid_taken() {
  pct status "$1" >/dev/null 2>&1 || [ -f "/etc/pve/lxc/${1}.conf" ] 2>/dev/null || [ -f "/etc/pve/qemu-server/${1}.conf" ] 2>/dev/null
}
if _vmid_taken "$VMID"; then
  ORIG_VMID="$VMID"
  VMID=$(pvesh get /cluster/nextid 2>/dev/null) || VMID=100
  while _vmid_taken "$VMID"; do
    VMID=$((VMID + 1))
    [ $VMID -gt 999 ] && { echo "Error: no free VMID found (tried up to 999)."; exit 1; }
  done
  echo "[*] VMID $ORIG_VMID in use, using $VMID instead."
fi

echo "[*] Creating LXC $VMID ($HOSTNAME) with template $TEMPLATE ..."
pct create "$VMID" "$TEMPLATE" \
  --hostname "$HOSTNAME" \
  --memory "$MEMORY" \
  --cores 1 \
  --rootfs "$STORAGE:${ROOTFS_SIZE}" \
  --net0 "name=eth0,bridge=$BRIDGE,ip=dhcp" \
  --unprivileged 0 \
  --password "$ROOT_PASSWORD"

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
pct exec "$VMID" -- sh -c "apt-get update -qq && apt-get install -y -qq git && git clone --depth 1 https://github.com/regiakb/bankai.git /opt/bankai && sh /opt/bankai/scripts/install-lxc.sh"

CT_IP=$(pct exec "$VMID" -- hostname -I 2>/dev/null | awk '{print $1}')
echo ""
echo "=============================================="
echo "  Bankai installed in LXC $VMID ($HOSTNAME)"
echo "=============================================="
echo "  LXC login:  root / $ROOT_PASSWORD  (ssh root@$CT_IP or pct enter $VMID)"
echo "  Bankai URL: http://${CT_IP}:8000   (user: admin / bankai)"
echo ""
echo "  Useful commands:"
echo "    pct enter $VMID   - enter container"
echo "    pct stop $VMID    - stop"
echo "    pct start $VMID   - start"
echo "=============================================="
