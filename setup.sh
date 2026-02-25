#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Traffic Inspector — Setup Script
#  Generates a root CA, signs it with your chosen details, builds the Docker
#  image, and prints step-by-step instructions for every OS.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
RESET="\033[0m"

banner() {
  echo -e "${CYAN}"
  echo "  ████████╗██████╗  █████╗ ███████╗███████╗██╗ ██████╗"
  echo "     ██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██║██╔════╝"
  echo "     ██║   ██████╔╝███████║█████╗  █████╗  ██║██║     "
  echo "     ██║   ██╔══██╗██╔══██║██╔══╝  ██╔══╝  ██║██║     "
  echo "     ██║   ██║  ██║██║  ██║██║     ██║     ██║╚██████╗"
  echo "     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝ ╚═════╝"
  echo ""
  echo "  ██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗ ██████╗ ██████╗"
  echo "  ██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗"
  echo "  ██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║   ██║   ██║██████╔╝"
  echo "  ██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗"
  echo "  ██║██║ ╚████║███████║██║     ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║"
  echo "  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝"
  echo -e "${RESET}"
}

step() { echo -e "${BOLD}${GREEN}[*]${RESET} $*"; }
info() { echo -e "    ${CYAN}→${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[✗]${RESET} $*"; exit 1; }

# ─── Pre-flight checks ────────────────────────────────────────────────────────
banner

command -v openssl >/dev/null 2>&1 || err "openssl is required. Install it first."
command -v docker  >/dev/null 2>&1 || err "docker is required. Install it first."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p certs

# ─── CA Generation ────────────────────────────────────────────────────────────
step "Generating Root Certificate Authority (4096-bit RSA, 10-year validity)..."

CA_SUBJECT="/C=US/ST=CyberSec/L=Lab/O=Traffic Inspector/OU=Security Research/CN=Traffic Inspector Root CA"

openssl genrsa -out certs/ca.key 4096 2>/dev/null
openssl req -new -x509 \
  -days 3650 \
  -key  certs/ca.key \
  -out  certs/ca.crt \
  -subj "$CA_SUBJECT" 2>/dev/null

# mitmproxy CA format: concatenated key + cert in one PEM file
cat certs/ca.key certs/ca.crt > certs/mitmproxy-ca.pem

# Fingerprint for verification
FINGERPRINT=$(openssl x509 -noout -fingerprint -sha256 -in certs/ca.crt | cut -d= -f2)

info "CA key:         certs/ca.key"
info "CA certificate: certs/ca.crt  (install this on your host)"
info "SHA-256:        ${FINGERPRINT}"

# ─── Docker build ─────────────────────────────────────────────────────────────
step "Building Docker image  (traffic-inspector:latest)..."
docker build -t traffic-inspector:latest . 2>&1 | \
  grep -E "^(Step|Successfully|ERROR|error)" || true
docker image inspect traffic-inspector:latest >/dev/null 2>&1 \
  || err "Docker build failed. Run:  docker build -t traffic-inspector ."

info "Image built successfully."

# ─── Instructions ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  STEP 1 — Install the CA certificate on your machine${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "  ${YELLOW}Linux (Debian/Ubuntu):${RESET}"
echo "    sudo cp certs/ca.crt /usr/local/share/ca-certificates/traffic-inspector.crt"
echo "    sudo update-ca-certificates"
echo ""
echo -e "  ${YELLOW}Linux (RHEL/CentOS/Fedora):${RESET}"
echo "    sudo cp certs/ca.crt /etc/pki/ca-trust/source/anchors/traffic-inspector.crt"
echo "    sudo update-ca-trust extract"
echo ""
echo -e "  ${YELLOW}macOS:${RESET}"
echo "    sudo security add-trusted-cert -d -r trustRoot \\"
echo "      -k /Library/Keychains/System.keychain certs/ca.crt"
echo ""
echo -e "  ${YELLOW}Windows (PowerShell as Admin):${RESET}"
echo '    certutil -addstore -f "ROOT" certs\ca.crt'
echo ""
echo -e "  ${YELLOW}Firefox (any OS — manual):${RESET}"
echo "    Settings → Privacy & Security → Certificates → View Certificates"
echo "    → Authorities → Import → select certs/ca.crt → Trust for websites"
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  STEP 2 — Start the inspector${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo "    docker compose up"
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  STEP 3 — Configure browser/system proxy${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo "    HTTP Proxy:   127.0.0.1   port 8080"
echo "    HTTPS Proxy:  127.0.0.1   port 8080"
echo "    No-proxy:     localhost, 127.0.0.1"
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  STEP 4 — Open the dashboard${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo "    http://localhost"
echo ""
echo -e "  ${CYAN}Certificate fingerprint (SHA-256):${RESET}"
echo "    ${FINGERPRINT}"
echo ""
