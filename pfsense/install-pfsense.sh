#!/usr/bin/env bash
# Install APGO onto a pfSense router over SSH.
#
#   bash pfsense/build-freebsd.sh                  # build first
#   bash pfsense/install-pfsense.sh admin@192.168.1.1 [amd64|arm64]
#
# Requires SSH access to the router (System > Advanced > Secure Shell).
set -euo pipefail
cd "$(dirname "$0")"

HOST="${1:?usage: install-pfsense.sh user@router-address [amd64|arm64]}"
ARCH="${2:-amd64}"
BIN="overlay-client-freebsd-${ARCH}"

[ -f "${BIN}" ] || { echo "${BIN} not built — run: bash pfsense/build-freebsd.sh"; exit 1; }

echo "==> Copying files to ${HOST}"
scp "${BIN}" "${HOST}:/tmp/overlay-client"
scp apgo.rc "${HOST}:/tmp/apgo.sh"
scp client.yaml.sample "${HOST}:/tmp/client.yaml.sample"

echo "==> Installing (binary, rc.d service, config dir)"
ssh "${HOST}" sh -s <<'EOF'
set -e
mkdir -p /usr/local/etc/apgo
install -m 0755 /tmp/overlay-client /usr/local/bin/overlay-client
# pfSense only runs rc.d scripts ending in .sh at boot.
install -m 0755 /tmp/apgo.sh /usr/local/etc/rc.d/apgo.sh
[ -f /usr/local/etc/apgo/client.yaml ] || cp /tmp/client.yaml.sample /usr/local/etc/apgo/client.yaml
# Enable at boot (rc.conf.local survives pfSense config changes).
touch /etc/rc.conf.local
grep -q '^apgo_enable=' /etc/rc.conf.local || echo 'apgo_enable="YES"' >> /etc/rc.conf.local
rm -f /tmp/overlay-client /tmp/apgo.sh /tmp/client.yaml.sample
echo "Installed. Edit /usr/local/etc/apgo/client.yaml (network_name + psk),"
echo "then: service apgo.sh start   (log: /var/log/apgo.log)"
EOF

echo "==> Done. See pfsense/README.md for firewall rules and exit-node NAT."
