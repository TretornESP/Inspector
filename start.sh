#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Container entrypoint
#  1. Installs the custom CA into mitmproxy's expected location
#  2. Starts nginx in the background
#  3. Starts mitmproxy with the Traffic Inspector addon (foreground)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

BOLD="\033[1m"
CYAN="\033[0;36m"
GREEN="\033[0;32m"
RESET="\033[0m"

echo -e "${BOLD}${CYAN}"
echo "  ┌────────────────────────────────────────────────┐"
echo "  │       Traffic Inspector  — Starting up         │"
echo "  └────────────────────────────────────────────────┘"
echo -e "${RESET}"

# ── Validate mounted certs ─────────────────────────────────────────────────────
if [[ ! -f /certs/ca.key ]] || [[ ! -f /certs/ca.crt ]]; then
  echo "  [✗] /certs/ca.key or /certs/ca.crt not found."
  echo "      Run setup.sh first, then start with: docker compose up"
  exit 1
fi

# ── Install CA into mitmproxy format ──────────────────────────────────────────
echo -e "  ${GREEN}[1/3]${RESET} Installing custom CA..."
mkdir -p /root/.mitmproxy
# mitmproxy-ca.pem must contain both the private key and the cert, PEM-concatenated
cat /certs/ca.key /certs/ca.crt > /root/.mitmproxy/mitmproxy-ca.pem
cp /certs/ca.crt /root/.mitmproxy/mitmproxy-ca-cert.pem
# Also copy our pre-built combined file if it exists
[[ -f /certs/mitmproxy-ca.pem ]] && cp /certs/mitmproxy-ca.pem /root/.mitmproxy/mitmproxy-ca.pem

# ── Start nginx ────────────────────────────────────────────────────────────────
echo -e "  ${GREEN}[2/3]${RESET} Starting nginx  (port 80 → dashboard)..."
nginx -t 2>&1
nginx
echo "         nginx started."

# ── Start mitmproxy ────────────────────────────────────────────────────────────
echo -e "  ${GREEN}[3/3]${RESET} Starting mitmproxy  (port 8080)..."
echo ""
echo "  ┌────────────────────────────────────────────────┐"
echo "  │  Proxy endpoint  :  0.0.0.0:8080               │"
echo "  │  Dashboard       :  http://localhost            │"
echo "  └────────────────────────────────────────────────┘"
echo ""

exec mitmdump \
  --listen-host 0.0.0.0 \
  --listen-port 8080 \
  --scripts /app/addon.py \
  --set block_global=false \
  --set ssl_insecure=true \
  --set connection_strategy=lazy \
  --quiet
