FROM python:3.11-slim

# ── System packages ────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ────────────────────────────────────────────────────────
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Application files ──────────────────────────────────────────────────────────
COPY addon.py      ./addon.py
COPY static/       ./static/
COPY nginx.conf    /etc/nginx/nginx.conf
COPY start.sh      /start.sh
RUN chmod +x /start.sh

# ── Runtime directories ────────────────────────────────────────────────────────
RUN mkdir -p /root/.mitmproxy /certs

# ── Ports ──────────────────────────────────────────────────────────────────────
# 8080 → mitmproxy HTTPS interception proxy
# 80   → nginx → dashboard (aiohttp on 5000)
EXPOSE 8080 80

ENTRYPOINT ["/start.sh"]
