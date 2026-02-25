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

# ─── Detect host IP ───────────────────────────────────────────────────────────
step "Detecting host IP addresses..."

# LAN IP — works on Linux; fallback for macOS
LAN_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}' \
      || ipconfig getifaddr en0 2>/dev/null \
      || hostname -I 2>/dev/null | awk '{print $1}' \
      || echo "")

# Public IP (5-second timeout, non-fatal)
PUBLIC_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "")

info "LAN IP    : ${LAN_IP:-not detected}"
info "Public IP : ${PUBLIC_IP:-not detected}"

echo ""
if [[ -n "$PUBLIC_IP" && "$PUBLIC_IP" != "$LAN_IP" ]]; then
  echo -e "  Use which IP in client deployment scripts?"
  echo -e "    ${CYAN}1)${RESET} LAN      ${LAN_IP}    (same network / home lab)"
  echo -e "    ${CYAN}2)${RESET} Public   ${PUBLIC_IP}  (remote clients over internet)"
  echo -e "    ${CYAN}3)${RESET} Custom   (enter manually)"
  echo ""
  read -rp "  Choice [1]: " ip_choice
  case "${ip_choice:-1}" in
    2) PROXY_IP="$PUBLIC_IP" ;;
    3) read -rp "  Enter IP: " PROXY_IP ;;
    *) PROXY_IP="$LAN_IP"   ;;
  esac
else
  PROXY_IP="${LAN_IP}"
fi

[[ -z "$PROXY_IP" ]] && { read -rp "  Could not detect IP. Enter manually: " PROXY_IP; }
PROXY_PORT=8080
info "Client scripts will point to: ${PROXY_IP}:${PROXY_PORT}"

# ─── Generate deploy scripts ──────────────────────────────────────────────────
step "Generating client deployment scripts  (deploy/)..."

mkdir -p deploy

# Single-line base64 (no line breaks) — works with OpenSSL & LibreSSL
CERT_B64=$(openssl enc -base64 -A -in certs/ca.crt)

# ── Windows PowerShell ────────────────────────────────────────────────────────
cat > deploy/install-windows.ps1 << EOF
# ─────────────────────────────────────────────────────────────────────────────
#  Traffic Inspector — Windows Client Setup
#  Installs the root CA into the system trust store and sets the system proxy.
#
#  Run as Administrator:
#    PowerShell -ExecutionPolicy Bypass -File install-windows.ps1
#
#  Optional override:
#    PowerShell -ExecutionPolicy Bypass -File install-windows.ps1 -ProxyHost 10.0.0.5
# ─────────────────────────────────────────────────────────────────────────────
param(
    [string]\$ProxyHost = "${PROXY_IP}",
    [int]   \$ProxyPort = ${PROXY_PORT}
)

\$CertB64     = "${CERT_B64}"
\$Fingerprint = "${FINGERPRINT}"

Write-Host ""
Write-Host "  Traffic Inspector" -ForegroundColor Cyan -NoNewline
Write-Host "  — Windows Client Setup"
Write-Host "  ─────────────────────────────────────────────────────────────"
Write-Host ""

# ── 1. Install certificate ────────────────────────────────────────────────────
Write-Host "[1/2] Installing root CA certificate..." -ForegroundColor Green
\$certBytes = [System.Convert]::FromBase64String(\$CertB64)
\$certPath  = Join-Path \$env:TEMP "ti-ca-\$(Get-Random).crt"
[IO.File]::WriteAllBytes(\$certPath, \$certBytes)

\$store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
    "Root", "LocalMachine")
\$store.Open("ReadWrite")
\$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(\$certPath)
\$store.Add(\$cert)
\$store.Close()
Remove-Item \$certPath -Force
Write-Host "      Added to LocalMachine\\Root" -ForegroundColor DarkGray
Write-Host "      SHA-256: \$Fingerprint" -ForegroundColor DarkGray

# ── 2. Set system proxy ───────────────────────────────────────────────────────
Write-Host "[2/2] Configuring system proxy (\${ProxyHost}:\${ProxyPort})..." -ForegroundColor Green
\$reg = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
Set-ItemProperty -Path \$reg -Name ProxyEnable  -Value 1
Set-ItemProperty -Path \$reg -Name ProxyServer   -Value "\${ProxyHost}:\${ProxyPort}"
Set-ItemProperty -Path \$reg -Name ProxyOverride -Value "localhost;127.0.0.1;<local>"

# Notify WinINet immediately (no reboot required)
\$sig = @'
[DllImport("wininet.dll")]
public static extern bool InternetSetOption(IntPtr h, int opt, IntPtr buf, int len);
'@
\$wi = Add-Type -MemberDefinition \$sig -Name WinInet -Namespace TI -PassThru
\$wi::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
\$wi::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
Write-Host "      WinINet notified — no reboot required." -ForegroundColor DarkGray

Write-Host ""
Write-Host "  ✔  Done!" -ForegroundColor Green
Write-Host "     Proxy     : \${ProxyHost}:\${ProxyPort}" -ForegroundColor Cyan
Write-Host "     Dashboard : http://\${ProxyHost}" -ForegroundColor Cyan
Write-Host ""
Write-Host "  To revert:" -ForegroundColor DarkGray
Write-Host "    Set-ItemProperty '\$reg' -Name ProxyEnable -Value 0" -ForegroundColor DarkGray
Write-Host "    (and remove the cert from certmgr.msc → Trusted Root CAs)" -ForegroundColor DarkGray
Write-Host ""
EOF

# ── macOS ─────────────────────────────────────────────────────────────────────
cat > deploy/install-macos.sh << EOF
#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Traffic Inspector — macOS Client Setup
#  Installs the root CA into the System keychain and configures all active
#  network services to use the inspector as an HTTP/HTTPS proxy.
#
#  Usage: bash install-macos.sh [proxy-host] [proxy-port]
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

PROXY_HOST="\${1:-${PROXY_IP}}"
PROXY_PORT="\${2:-${PROXY_PORT}}"
CERT_B64="${CERT_B64}"
FINGERPRINT="${FINGERPRINT}"

BOLD="\033[1m" GREEN="\033[0;32m" CYAN="\033[0;36m" YELLOW="\033[1;33m"
GRAY="\033[2m"  RESET="\033[0m"

echo -e "\n  \${CYAN}Traffic Inspector\${RESET} — macOS Client Setup"
echo    "  ─────────────────────────────────────────────────────"
echo ""

# ── 1. Install certificate ────────────────────────────────────────────────────
echo -e "\${GREEN}[1/2]\${RESET} Installing root CA certificate..."
TMPFILE=\$(mktemp /tmp/ti-ca-XXXX.crt)
# macOS base64 uses -D, GNU uses -d; try both
echo "\$CERT_B64" | base64 -D > "\$TMPFILE" 2>/dev/null \
  || echo "\$CERT_B64" | base64 -d > "\$TMPFILE"

sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain "\$TMPFILE"
rm -f "\$TMPFILE"
echo -e "      \${GRAY}Added to System keychain.\${RESET}"
echo -e "      \${GRAY}SHA-256: \$FINGERPRINT\${RESET}"

# ── 2. Configure proxy on all active network services ─────────────────────────
echo -e "\${GREEN}[2/2]\${RESET} Configuring system proxy (\${PROXY_HOST}:\${PROXY_PORT})..."

while IFS= read -r svc; do
  [[ -z "\$svc" ]] && continue
  networksetup -setwebproxy            "\$svc" "\$PROXY_HOST" "\$PROXY_PORT" 2>/dev/null && \\
  networksetup -setsecurewebproxy      "\$svc" "\$PROXY_HOST" "\$PROXY_PORT" 2>/dev/null && \\
  networksetup -setwebproxystate       "\$svc" on 2>/dev/null && \\
  networksetup -setsecurewebproxystate "\$svc" on 2>/dev/null && \\
  networksetup -setproxybypassdomains  "\$svc" localhost 127.0.0.1 2>/dev/null && \\
  echo -e "      \${GRAY}Applied to: \$svc\${RESET}" || true
done < <(networksetup -listnetworkserviceorder \
         | awk -F'[()]' '/^\([0-9]/ {print \$3}')

echo ""
echo -e "  \${GREEN}✔  Done!\${RESET}"
echo -e "     Proxy     : \${CYAN}\${PROXY_HOST}:\${PROXY_PORT}\${RESET}"
echo -e "     Dashboard : \${CYAN}http://\${PROXY_HOST}\${RESET}"
echo ""
echo -e "  \${GRAY}To revert:\${RESET}"
echo -e "  \${GRAY}  networksetup -setwebproxystate      'Wi-Fi' off\${RESET}"
echo -e "  \${GRAY}  networksetup -setsecurewebproxystate 'Wi-Fi' off\${RESET}"
echo -e "  \${GRAY}  (and remove the cert via Keychain Access → System → Certificates)\${RESET}"
echo ""
EOF

# ── Linux ─────────────────────────────────────────────────────────────────────
cat > deploy/install-linux.sh << EOF
#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Traffic Inspector — Linux Client Setup
#  Installs the root CA into the system trust store and configures the proxy
#  for GNOME, KDE Plasma, and the shell environment (~/.profile).
#
#  Usage: bash install-linux.sh [proxy-host] [proxy-port]
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

PROXY_HOST="\${1:-${PROXY_IP}}"
PROXY_PORT="\${2:-${PROXY_PORT}}"
CERT_B64="${CERT_B64}"
FINGERPRINT="${FINGERPRINT}"

GREEN="\033[0;32m" CYAN="\033[0;36m" YELLOW="\033[1;33m"
GRAY="\033[2m"      RESET="\033[0m"

echo -e "\n  \${CYAN}Traffic Inspector\${RESET} — Linux Client Setup"
echo    "  ─────────────────────────────────────────────────────"
echo ""

# ── 1. Install certificate ────────────────────────────────────────────────────
echo -e "\${GREEN}[1/2]\${RESET} Installing root CA certificate..."
TMPFILE=\$(mktemp /tmp/ti-ca-XXXX.crt)
echo "\$CERT_B64" | base64 -d > "\$TMPFILE"

if command -v update-ca-certificates >/dev/null 2>&1; then
  sudo cp "\$TMPFILE" /usr/local/share/ca-certificates/traffic-inspector.crt
  sudo update-ca-certificates --fresh 2>&1 | grep -E "(added|error)" || true
  echo -e "      \${GRAY}Installed — Debian/Ubuntu path.\${RESET}"
elif command -v update-ca-trust >/dev/null 2>&1; then
  sudo cp "\$TMPFILE" /etc/pki/ca-trust/source/anchors/traffic-inspector.crt
  sudo update-ca-trust extract
  echo -e "      \${GRAY}Installed — RHEL/Fedora path.\${RESET}"
else
  sudo mkdir -p /usr/local/share/ca-certificates
  sudo cp "\$TMPFILE" /usr/local/share/ca-certificates/traffic-inspector.crt
  echo -e "      \${YELLOW}Unknown distro — copied to /usr/local/share/ca-certificates/.\${RESET}"
  echo -e "      \${YELLOW}You may need to run your distro's trust-update command manually.\${RESET}"
fi
rm -f "\$TMPFILE"
echo -e "      \${GRAY}SHA-256: \$FINGERPRINT\${RESET}"

# ── 2. Configure proxy ────────────────────────────────────────────────────────
echo -e "\${GREEN}[2/2]\${RESET} Configuring system proxy (\${PROXY_HOST}:\${PROXY_PORT})..."

PROXY_URL="http://\${PROXY_HOST}:\${PROXY_PORT}"
NO_PROXY="localhost,127.0.0.1,::1"

# GNOME
if command -v gsettings >/dev/null 2>&1 && gsettings list-schemas 2>/dev/null | grep -q "org.gnome.system.proxy"; then
  gsettings set org.gnome.system.proxy        mode         'manual'
  gsettings set org.gnome.system.proxy.http   host         "\$PROXY_HOST"
  gsettings set org.gnome.system.proxy.http   port          \$PROXY_PORT
  gsettings set org.gnome.system.proxy.https  host         "\$PROXY_HOST"
  gsettings set org.gnome.system.proxy.https  port          \$PROXY_PORT
  gsettings set org.gnome.system.proxy        ignore-hosts "['localhost','127.0.0.1','::1']"
  echo -e "      \${GRAY}GNOME proxy configured.\${RESET}"
fi

# KDE Plasma
if command -v kwriteconfig5 >/dev/null 2>&1; then
  kwriteconfig5 --file kioslaverc --group "Proxy Settings" --key ProxyType  1
  kwriteconfig5 --file kioslaverc --group "Proxy Settings" --key httpProxy  "\$PROXY_URL"
  kwriteconfig5 --file kioslaverc --group "Proxy Settings" --key httpsProxy "\$PROXY_URL"
  kwriteconfig5 --file kioslaverc --group "Proxy Settings" --key NoProxyFor "\$NO_PROXY"
  echo -e "      \${GRAY}KDE proxy configured.\${RESET}"
fi

# Shell environment — remove old block, append fresh one
PROFILE="\$HOME/.profile"
touch "\$PROFILE"
# Strip previous Traffic Inspector proxy block if present
grep -v "# ti-proxy" "\$PROFILE" > /tmp/ti_profile_tmp && mv /tmp/ti_profile_tmp "\$PROFILE" || true
printf '%s\n' \\
  "# ti-proxy — Traffic Inspector (remove this block to disable)" \\
  "export http_proxy=\"\$PROXY_URL\" HTTP_PROXY=\"\$PROXY_URL\"\\" \\
  "       https_proxy=\"\$PROXY_URL\" HTTPS_PROXY=\"\$PROXY_URL\"\\" \\
  "       no_proxy=\"\$NO_PROXY\"    NO_PROXY=\"\$NO_PROXY\" # ti-proxy" \\
  >> "\$PROFILE"
echo -e "      \${GRAY}Shell env vars written to \$PROFILE.\${RESET}"

echo ""
echo -e "  \${GREEN}✔  Done!\${RESET}"
echo -e "     Proxy     : \${CYAN}\${PROXY_HOST}:\${PROXY_PORT}\${RESET}"
echo -e "     Dashboard : \${CYAN}http://\${PROXY_HOST}\${RESET}"
echo ""
echo -e "  \${GRAY}Note: Log out/in (or source ~/.profile) for shell env vars to apply.\${RESET}"
echo -e "  \${GRAY}To revert: remove the # ti-proxy block from ~/.profile and run:\${RESET}"
echo -e "  \${GRAY}  gsettings set org.gnome.system.proxy mode 'none'\${RESET}"
echo ""
EOF

chmod +x deploy/install-macos.sh deploy/install-linux.sh

info "Windows  →  deploy/install-windows.ps1"
info "macOS    →  deploy/install-macos.sh"
info "Linux    →  deploy/install-linux.sh"

# ─── Instructions ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  STEP 1 — Distribute & run the client script for your OS${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "  Scripts are in ${CYAN}deploy/${RESET}  — copy the right one to the target machine:"
echo ""
echo -e "  ${YELLOW}Windows${RESET}  (run PowerShell as Administrator)"
echo "    PowerShell -ExecutionPolicy Bypass -File install-windows.ps1"
echo ""
echo -e "  ${YELLOW}macOS${RESET}"
echo "    bash install-macos.sh"
echo ""
echo -e "  ${YELLOW}Linux${RESET}"
echo "    bash install-linux.sh"
echo ""
echo -e "  Each script embeds the CA certificate and proxy address — no extra"
echo -e "  files needed on the target machine."
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  STEP 2 — Start the inspector${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo "    docker compose up"
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  STEP 3 — Open the dashboard${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "    http://${PROXY_IP}"
echo ""
echo -e "  ${CYAN}Certificate fingerprint (SHA-256):${RESET}"
echo "    ${FINGERPRINT}"
echo ""
