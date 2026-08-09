#!/bin/sh
set -eu

RELEASE_VERSION=0.3.1
DOMAIN=
ACME_EMAIL=
MASQUERADE_URL=
RELEASE_BASE_URL=https://github.com/mirrage11gpt/rmvpn/releases/download
RELEASE_PUBLIC_KEY=${RISEVPN_RELEASE_PUBLIC_KEY:-}
LOCAL_DIR=
UPGRADE=false

usage() {
  echo "usage: sudo ./install.sh --domain vpn.example.com --acme-email admin@example.com --masquerade-url https://cover.example.com [--version 0.3.1] [--release-public-key RW...]" >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN=${2:-}; shift 2 ;;
    --acme-email) ACME_EMAIL=${2:-}; shift 2 ;;
    --masquerade-url) MASQUERADE_URL=${2:-}; shift 2 ;;
    --version) RELEASE_VERSION=${2:-}; shift 2 ;;
    --release-base-url) RELEASE_BASE_URL=${2:-}; shift 2 ;;
    --release-public-key) RELEASE_PUBLIC_KEY=${2:-}; shift 2 ;;
    --local-dir) LOCAL_DIR=${2:-}; shift 2 ;;
    --upgrade) UPGRADE=true; shift ;;
    *) usage ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
if [ -z "$DOMAIN" ] || [ -z "$ACME_EMAIL" ] || [ -z "$MASQUERADE_URL" ]; then
  usage
fi
case "$DOMAIN" in *[!A-Za-z0-9.-]*|.*|*..*|*.) echo "invalid domain" >&2; exit 1 ;; esac
case "$ACME_EMAIL" in *@*.*) ;; *) echo "invalid ACME email" >&2; exit 1 ;; esac
case "$MASQUERADE_URL" in
  https://* ) ;;
  * ) echo "masquerade URL must use https://" >&2; exit 1 ;;
esac
case "$MASQUERADE_URL" in *[\"\'\`\$\\\|\;\<\>\{\}]*|*' '*) echo "masquerade URL contains unsafe characters" >&2; exit 1 ;; esac

# shellcheck disable=SC1091
. /etc/os-release
if [ "${ID:-}" != ubuntu ] || [ "${VERSION_ID:-}" != 26.04 ]; then
  echo "RiseVPN Node supports Ubuntu 26.04 only (found ${PRETTY_NAME:-unknown})" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl certbot minisign nftables openssl iproute2

getent ahosts "$DOMAIN" >/dev/null || { echo "domain does not resolve: $DOMAIN" >&2; exit 1; }
PUBLIC_V4=$(curl -4 --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 15 https://api.ipify.org || true)
PUBLIC_V6=$(curl -6 --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 15 https://api64.ipify.org || true)
[ -n "$PUBLIC_V4$PUBLIC_V6" ] || { echo "could not determine this server public IP" >&2; exit 1; }
DNS_ADDRESSES=$(
  { getent ahostsv4 "$DOMAIN" 2>/dev/null || true; getent ahostsv6 "$DOMAIN" 2>/dev/null || true; } |
    awk '{print $1}' | sort -u
)
dns_matches=false
for public_ip in $PUBLIC_V4 $PUBLIC_V6; do
  if printf '%s\n' "$DNS_ADDRESSES" | grep -Fqx "$public_ip"; then
    dns_matches=true
    break
  fi
done
[ "$dns_matches" = true ] || {
  echo "DNS for $DOMAIN does not contain this server public IPv4 or IPv6 address" >&2
  exit 1
}
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 15 --output /dev/null "$MASQUERADE_URL"

if [ "$UPGRADE" = false ]; then
  for port in 80 443 8443; do
    if ss -H -lntu | awk '{print $5}' | grep -Eq "(^|:)$port$"; then
      echo "port $port is already in use" >&2
      exit 1
    fi
  done
fi

WORK=$(mktemp -d /tmp/risevpn-install.XXXXXX)
trap 'rm -rf "$WORK"' EXIT INT TERM
AGENT=risevpn-node-linux-$ARCH
HYSTERIA=hysteria-risevpn-linux-$ARCH
XRAY=xray-risevpn-linux-$ARCH
PACKAGE=risevpn-node-packaging.tar.gz
INSTALLER=install.sh

fetch() {
  name=$1
  if [ -n "$LOCAL_DIR" ]; then
    cp "$LOCAL_DIR/$name" "$WORK/$name"
  else
    curl --proto '=https' --tlsv1.2 --fail --location --show-error \
      "$RELEASE_BASE_URL/v$RELEASE_VERSION/$name" -o "$WORK/$name"
  fi
}

fetch "$AGENT"
fetch "$HYSTERIA"
fetch "$XRAY"
fetch "$PACKAGE"
fetch "$INSTALLER"
fetch checksums.txt
fetch checksums.txt.minisig

[ -n "$RELEASE_PUBLIC_KEY" ] || {
  echo "a trusted minisign public key is required via --release-public-key or RISEVPN_RELEASE_PUBLIC_KEY" >&2
  exit 1
}
minisign -Vm "$WORK/checksums.txt" -x "$WORK/checksums.txt.minisig" -P "$RELEASE_PUBLIC_KEY"
for asset in "$AGENT" "$HYSTERIA" "$XRAY" "$PACKAGE" "$INSTALLER"; do
  expected=$(awk -v file="$asset" '$2 == file || $2 == "*" file {print $1}' "$WORK/checksums.txt")
  [ -n "$expected" ] || { echo "missing checksum for $asset" >&2; exit 1; }
  actual=$(sha256sum "$WORK/$asset" | awk '{print $1}')
  [ "$actual" = "$expected" ] || { echo "checksum mismatch for $asset" >&2; exit 1; }
done

mkdir "$WORK/packaging"
tar -xzf "$WORK/$PACKAGE" -C "$WORK/packaging"
for required in risevpn-node.service risevpn-hysteria.service risevpn-xray.service hysteria-server.yaml.in xray-server.json.in risevpn-node-admin risevpn-cert-deploy risevpn-cert-pre risevpn-cert-post; do
  [ -f "$WORK/packaging/$required" ] || { echo "packaging archive is missing $required" >&2; exit 1; }
done

getent group risevpn >/dev/null || groupadd --system risevpn
id risevpn-agent >/dev/null 2>&1 || useradd --system --gid risevpn --home-dir /var/lib/risevpn --shell /usr/sbin/nologin risevpn-agent
id risevpn-hysteria >/dev/null 2>&1 || useradd --system --gid risevpn --home-dir /nonexistent --shell /usr/sbin/nologin risevpn-hysteria
id risevpn-xray >/dev/null 2>&1 || useradd --system --gid risevpn --home-dir /nonexistent --shell /usr/sbin/nologin risevpn-xray
install -d -m 0755 -o root -g root /usr/local/lib/risevpn
install -d -m 0750 -o root -g risevpn /etc/risevpn /etc/risevpn/tls
install -d -m 0700 -o risevpn-agent -g risevpn /var/lib/risevpn

if [ ! -d "/etc/letsencrypt/live/$DOMAIN" ]; then
  certbot certonly --non-interactive --agree-tos --standalone --preferred-challenges http \
    --email "$ACME_EMAIL" --domain "$DOMAIN"
fi

printf '%s\n' "$DOMAIN" > /etc/risevpn/domain
chmod 0640 /etc/risevpn/domain
chown root:risevpn /etc/risevpn/domain
install -m 0755 "$WORK/packaging/risevpn-cert-deploy" /etc/letsencrypt/renewal-hooks/deploy/risevpn-node
install -m 0755 "$WORK/packaging/risevpn-cert-pre" /etc/letsencrypt/renewal-hooks/pre/risevpn-node
install -m 0755 "$WORK/packaging/risevpn-cert-post" /etc/letsencrypt/renewal-hooks/post/risevpn-node
/etc/letsencrypt/renewal-hooks/deploy/risevpn-node

TRAFFIC_SECRET=$(openssl rand -hex 32)
OBFS_PASSWORD=${RISEVPN_OBFS_PASSWORD:-}
REALITY_PRIVATE_KEY=
REALITY_PUBLIC_KEY=
REALITY_SHORT_ID=
if [ -r /etc/risevpn/node.conf ]; then
  old_secret=$(sed -n 's/^traffic_stats_secret=//p' /etc/risevpn/node.conf)
  [ -z "$old_secret" ] || TRAFFIC_SECRET=$old_secret
  old_obfs=$(sed -n 's/^obfs_password=//p' /etc/risevpn/node.conf)
  [ -z "$old_obfs" ] || OBFS_PASSWORD=$old_obfs
  REALITY_PRIVATE_KEY=$(sed -n 's/^reality_private_key=//p' /etc/risevpn/node.conf)
  REALITY_PUBLIC_KEY=$(sed -n 's/^reality_public_key=//p' /etc/risevpn/node.conf)
  REALITY_SHORT_ID=$(sed -n 's/^reality_short_id=//p' /etc/risevpn/node.conf)
fi
case "$OBFS_PASSWORD" in *[!A-Za-z0-9._~-]*) echo "RISEVPN_OBFS_PASSWORD contains unsafe characters" >&2; exit 1 ;; esac
if [ -n "$OBFS_PASSWORD" ] && [ "${#OBFS_PASSWORD}" -lt 4 ]; then
  echo "RISEVPN_OBFS_PASSWORD must contain at least 4 characters" >&2
  exit 1
fi
if [ -z "$REALITY_PRIVATE_KEY" ] || [ -z "$REALITY_PUBLIC_KEY" ] || [ -z "$REALITY_SHORT_ID" ]; then
  chmod 0755 "$WORK/$AGENT"
  "$WORK/$AGENT" reality-keypair --private-file "$WORK/reality-private" --public-file "$WORK/reality-public"
  REALITY_PRIVATE_KEY=$(sed -n '1p' "$WORK/reality-private")
  REALITY_PUBLIC_KEY=$(sed -n '1p' "$WORK/reality-public")
  REALITY_SHORT_ID=$(openssl rand -hex 8)
fi
case "$REALITY_PRIVATE_KEY$REALITY_PUBLIC_KEY" in *[!A-Za-z0-9_-]*) echo "invalid Reality key" >&2; exit 1 ;; esac
case "$REALITY_SHORT_ID" in *[!A-Fa-f0-9]*) echo "invalid Reality short ID" >&2; exit 1 ;; esac
[ "${#REALITY_SHORT_ID}" -eq 16 ] || { echo "Reality short ID must contain 16 hexadecimal characters" >&2; exit 1; }

cat > "$WORK/node.conf" <<EOF
domain=$DOMAIN
acme_email=$ACME_EMAIL
masquerade_url=$MASQUERADE_URL
database_path=/var/lib/risevpn/node.db
internal_listen=127.0.0.1:9080
enrollment_listen=:8443
tls_cert_file=/etc/risevpn/tls/fullchain.pem
tls_key_file=/etc/risevpn/tls/privkey.pem
traffic_stats_url=http://127.0.0.1:9999
traffic_stats_secret=$TRAFFIC_SECRET
xray_api_address=127.0.0.1:10085
reality_private_key=$REALITY_PRIVATE_KEY
reality_public_key=$REALITY_PUBLIC_KEY
reality_short_id=$REALITY_SHORT_ID
release_public_key=$RELEASE_PUBLIC_KEY
agent_version=$RELEASE_VERSION
EOF
[ -z "$OBFS_PASSWORD" ] || printf 'obfs_password=%s\n' "$OBFS_PASSWORD" >> "$WORK/node.conf"

escaped_url=$(printf '%s' "$MASQUERADE_URL" | sed 's/[&|]/\\&/g')
sed -e "s|@TRAFFIC_SECRET@|$TRAFFIC_SECRET|g" -e "s|@MASQUERADE_URL@|$escaped_url|g" \
  "$WORK/packaging/hysteria-server.yaml.in" > "$WORK/hysteria.yaml"
if [ -n "$OBFS_PASSWORD" ]; then
  sed -i "/^auth:/i\\
obfs:\\
  type: salamander\\
  salamander:\\
    password: \"$OBFS_PASSWORD\"\\
" "$WORK/hysteria.yaml"
fi

sed -e "s|@DOMAIN@|$DOMAIN|g" \
  -e "s|@REALITY_PRIVATE_KEY@|$REALITY_PRIVATE_KEY|g" \
  -e "s|@REALITY_SHORT_ID@|$REALITY_SHORT_ID|g" \
  "$WORK/packaging/xray-server.json.in" > "$WORK/xray.json"

rollback_config=false
rollback_xray_config=false
if [ -f /etc/risevpn/node.conf ]; then
  cp -p /etc/risevpn/node.conf "$WORK/node.conf.previous"
  rollback_config=true
fi
if [ -f /etc/risevpn/hysteria.yaml ]; then
  cp -p /etc/risevpn/hysteria.yaml "$WORK/hysteria.yaml.previous"
fi
if [ -f /etc/risevpn/xray.json ]; then
  cp -p /etc/risevpn/xray.json "$WORK/xray.json.previous"
  rollback_xray_config=true
fi
install -m 0640 -o root -g risevpn "$WORK/node.conf" /etc/risevpn/node.conf
install -m 0640 -o root -g risevpn "$WORK/hysteria.yaml" /etc/risevpn/hysteria.yaml
install -m 0640 -o root -g risevpn "$WORK/xray.json" /etc/risevpn/xray.json
install -m 0644 "$WORK/packaging/risevpn-node.service" /etc/systemd/system/risevpn-node.service
install -m 0644 "$WORK/packaging/risevpn-hysteria.service" /etc/systemd/system/risevpn-hysteria.service
install -m 0644 "$WORK/packaging/risevpn-xray.service" /etc/systemd/system/risevpn-xray.service
install -m 0755 "$WORK/packaging/risevpn-node-admin" /usr/local/bin/risevpn-node
install -m 0755 "$WORK/$INSTALLER" /usr/local/lib/risevpn/install.sh

rollback=false
rollback_xray=false
if [ -f /usr/local/lib/risevpn/risevpn-node-bin ]; then
  cp -p /usr/local/lib/risevpn/risevpn-node-bin /usr/local/lib/risevpn/risevpn-node-bin.previous
  rollback=true
fi
if [ -f /usr/local/lib/risevpn/hysteria ]; then
  cp -p /usr/local/lib/risevpn/hysteria /usr/local/lib/risevpn/hysteria.previous
fi
if [ -f /usr/local/lib/risevpn/xray ]; then
  cp -p /usr/local/lib/risevpn/xray /usr/local/lib/risevpn/xray.previous
  rollback_xray=true
fi
install -m 0755 "$WORK/$AGENT" /usr/local/lib/risevpn/risevpn-node-bin
install -m 0755 "$WORK/$HYSTERIA" /usr/local/lib/risevpn/hysteria
install -m 0755 "$WORK/$XRAY" /usr/local/lib/risevpn/xray

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow 443/udp
  ufw allow 8443/tcp
else
  nft list table inet risevpn >/dev/null 2>&1 || nft add table inet risevpn
  nft list chain inet risevpn input >/dev/null 2>&1 || nft 'add chain inet risevpn input { type filter hook input priority -5; policy accept; }'
  nft list chain inet risevpn input | grep -q 'risevpn-web' || nft 'add rule inet risevpn input tcp dport { 80, 443, 8443 } accept comment "risevpn-web"'
  nft list chain inet risevpn input | grep -q 'risevpn-quic' || nft 'add rule inet risevpn input udp dport 443 accept comment "risevpn-quic"'
fi

systemctl daemon-reload
systemctl enable risevpn-node.service risevpn-hysteria.service risevpn-xray.service
if [ "$UPGRADE" = true ]; then
  systemctl restart risevpn-node.service risevpn-hysteria.service risevpn-xray.service
else
  systemctl start risevpn-node.service risevpn-hysteria.service risevpn-xray.service
fi

healthy=false
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if curl --fail --silent http://127.0.0.1:9080/healthz >/dev/null && systemctl is-active --quiet risevpn-hysteria.service && systemctl is-active --quiet risevpn-xray.service; then healthy=true; break; fi
  echo "waiting for services ($attempt/10)" >&2
  sleep 1
done
if [ "$healthy" != true ]; then
  journalctl -u risevpn-node.service -n 30 --no-pager >&2 || true
  if [ "$rollback_config" = true ]; then
    install -m 0640 -o root -g risevpn "$WORK/node.conf.previous" /etc/risevpn/node.conf
    [ ! -f "$WORK/hysteria.yaml.previous" ] || install -m 0640 -o root -g risevpn "$WORK/hysteria.yaml.previous" /etc/risevpn/hysteria.yaml
    if [ "$rollback_xray_config" = true ]; then
      install -m 0640 -o root -g risevpn "$WORK/xray.json.previous" /etc/risevpn/xray.json
    else
      rm -f /etc/risevpn/xray.json
    fi
  fi
  if [ "$rollback" = true ]; then
    install -m 0755 /usr/local/lib/risevpn/risevpn-node-bin.previous /usr/local/lib/risevpn/risevpn-node-bin
    [ ! -f /usr/local/lib/risevpn/hysteria.previous ] || install -m 0755 /usr/local/lib/risevpn/hysteria.previous /usr/local/lib/risevpn/hysteria
    if [ "$rollback_xray" = true ]; then
      install -m 0755 /usr/local/lib/risevpn/xray.previous /usr/local/lib/risevpn/xray
      systemctl restart risevpn-node.service risevpn-hysteria.service risevpn-xray.service || true
    else
      systemctl disable --now risevpn-xray.service || true
      rm -f /usr/local/lib/risevpn/xray
      systemctl restart risevpn-node.service risevpn-hysteria.service || true
    fi
  else
    systemctl disable --now risevpn-node.service risevpn-hysteria.service risevpn-xray.service || true
  fi
  echo "health check failed; previous binaries were restored when available" >&2
  exit 1
fi

echo
if [ "$UPGRADE" = true ]; then
  echo "RiseVPN Node $RELEASE_VERSION is healthy. Existing enrollment remains active."
else
  echo "RiseVPN Node $RELEASE_VERSION is healthy. Enrollment key (valid for 24 hours):"
  /usr/local/lib/risevpn/risevpn-node-bin enrollment show --config /etc/risevpn/node.conf
fi
