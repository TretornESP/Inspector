"""
Traffic Inspector — mitmproxy addon
────────────────────────────────────
Embeds an aiohttp web server (port 5000) inside mitmproxy's event loop.
Every HTTP/HTTPS transaction is:
  • stored in an in-memory ring-buffer (summary + full detail)
  • broadcast in real-time to all connected WebSocket clients
"""

from __future__ import annotations

import asyncio
import gzip
import json
import time
import uuid
import zlib
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aiohttp import web
from mitmproxy import ctx, http

# ── Constants ─────────────────────────────────────────────────────────────────
MAX_ENTRIES   = 2_000        # ring-buffer size
MAX_BODY_SIZE = 128 * 1024   # 128 KB max body stored per side
STATIC_DIR    = Path("/app/static")

# ── Helpers ───────────────────────────────────────────────────────────────────

def _decode_body(content: bytes | None, headers: dict[str, str]) -> str:
    """Return a human-readable representation of a response/request body."""
    if not content:
        return ""

    # mitmproxy usually decompresses automatically; handle residuals just in case
    enc = headers.get("content-encoding", "").lower()
    if enc:
        try:
            if "gzip" in enc:
                content = gzip.decompress(content)
            elif "deflate" in enc:
                content = zlib.decompress(content)
        except Exception:
            pass

    if len(content) > MAX_BODY_SIZE:
        return f"[Truncated — {len(content):,} bytes total; showing first {MAX_BODY_SIZE // 1024} KB]\n" + \
               content[:MAX_BODY_SIZE].decode("utf-8", errors="replace")

    ct = headers.get("content-type", "").lower()
    is_text = any(t in ct for t in (
        "text/", "json", "xml", "javascript", "x-www-form-urlencoded",
        "graphql", "csv", "plain",
    ))
    if is_text:
        return content.decode("utf-8", errors="replace")

    return f"[Binary — {len(content):,} bytes]"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Main addon class ───────────────────────────────────────────────────────────

class TrafficInspector:
    """mitmproxy addon + embedded aiohttp dashboard server."""

    def __init__(self) -> None:
        self._entries: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._details: dict[str, dict[str, Any]]        = {}
        self._websockets: set[web.WebSocketResponse]    = set()
        self._runner: web.AppRunner | None              = None
        self._inject_enabled: bool = False
        self._inject_script:  str  = ""
        self._app = self._build_app()

    # ── aiohttp app ───────────────────────────────────────────────────────────

    def _build_app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/",                    self._handle_index)
        app.router.add_get("/ws",                  self._handle_ws)
        app.router.add_get("/api/entries",         self._handle_entries)
        app.router.add_get("/api/entry/{eid}",     self._handle_entry)
        app.router.add_get("/api/stats",           self._handle_stats)
        app.router.add_delete("/api/entries",      self._handle_clear)
        app.router.add_get("/api/inject",          self._handle_inject_get)
        app.router.add_post("/api/inject",         self._handle_inject_post)
        return app

    # ── HTTP route handlers ───────────────────────────────────────────────────

    async def _handle_index(self, _req: web.Request) -> web.Response:
        return web.Response(
            body=(STATIC_DIR / "index.html").read_bytes(),
            content_type="text/html",
        )

    async def _handle_entries(self, _req: web.Request) -> web.Response:
        return web.json_response(list(self._entries.values()))

    async def _handle_entry(self, req: web.Request) -> web.Response:
        eid    = req.match_info["eid"]
        detail = self._details.get(eid)
        if detail is None:
            raise web.HTTPNotFound(reason="Entry not found")
        return web.json_response(detail)

    async def _handle_stats(self, _req: web.Request) -> web.Response:
        total   = len(self._entries)
        errors  = sum(1 for e in self._entries.values() if e["status"] >= 400)
        data_rx = sum(e["size"] for e in self._entries.values())
        return web.json_response({
            "total": total, "errors": errors, "data_bytes": data_rx,
        })

    async def _handle_clear(self, _req: web.Request) -> web.Response:
        self._entries.clear()
        self._details.clear()
        await self._broadcast({"type": "clear"})
        return web.json_response({"ok": True})

    async def _handle_inject_get(self, _req: web.Request) -> web.Response:
        return web.json_response({
            "enabled": self._inject_enabled,
            "script":  self._inject_script,
        })

    async def _handle_inject_post(self, req: web.Request) -> web.Response:
        data = await req.json()
        if "enabled" in data:
            self._inject_enabled = bool(data["enabled"])
        if "script" in data:
            self._inject_script = str(data["script"])
        await self._broadcast({
            "type":    "inject_state",
            "enabled": self._inject_enabled,
            "script":  self._inject_script,
        })
        ctx.log.info(
            f"JS injection {'enabled' if self._inject_enabled else 'disabled'} "
            f"({len(self._inject_script)} chars)"
        )
        return web.json_response({"ok": True, "enabled": self._inject_enabled})

    # ── WebSocket handler ─────────────────────────────────────────────────────

    async def _handle_ws(self, req: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=25, max_msg_size=0)
        await ws.prepare(req)
        self._websockets.add(ws)

        # Replay existing entries for freshly connected clients
        backlog = json.dumps({
            "type": "backlog",
            "data": list(self._entries.values()),
        })
        try:
            await ws.send_str(backlog)
        except Exception:
            self._websockets.discard(ws)
            return ws

        try:
            async for _msg in ws:
                pass          # client sends nothing; loop keeps socket alive
        finally:
            self._websockets.discard(ws)

        return ws

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _broadcast(self, msg: dict[str, Any]) -> None:
        if not self._websockets:
            return
        text = json.dumps(msg)
        dead: set[web.WebSocketResponse] = set()
        for ws in list(self._websockets):
            try:
                await ws.send_str(text)
            except Exception:
                dead.add(ws)
        self._websockets -= dead

    def _evict_oldest(self) -> None:
        """Remove the oldest entry if the ring buffer is full."""
        if len(self._entries) >= MAX_ENTRIES:
            oldest_id = next(iter(self._entries))
            del self._entries[oldest_id]
            self._details.pop(oldest_id, None)

    # ── mitmproxy lifecycle hooks ─────────────────────────────────────────────

    async def running(self) -> None:
        """Called once mitmproxy is fully started — launch the dashboard."""
        self._runner = web.AppRunner(self._app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", 5000)
        await site.start()
        ctx.log.info("Traffic Inspector dashboard ready → http://localhost")

    async def done(self) -> None:
        """Graceful shutdown."""
        if self._runner:
            await self._runner.cleanup()

    # ── mitmproxy flow hooks ──────────────────────────────────────────────────

    def request(self, flow: http.HTTPFlow) -> None:
        """Tag each flow with a unique ID and start timestamp."""
        flow.metadata["_id"] = str(uuid.uuid4())
        flow.metadata["_t0"] = time.perf_counter()

    async def response(self, flow: http.HTTPFlow) -> None:
        """Called when a complete response has been received."""
        eid      = flow.metadata.get("_id", str(uuid.uuid4()))
        t0       = flow.metadata.get("_t0", time.perf_counter())
        duration = round((time.perf_counter() - t0) * 1000, 1)

        req  = flow.request
        resp = flow.response

        req_headers  = dict(req.headers)
        resp_headers = dict(resp.headers)

        # ── JS injection ──────────────────────────────────────────────────────
        injected = False
        if self._inject_enabled and self._inject_script:
            ct = resp.headers.get("content-type", "").lower()
            if "text/html" in ct:
                # Strip headers that would block inline scripts
                for h in ("content-security-policy",
                          "content-security-policy-report-only",
                          "x-xss-protection"):
                    resp.headers.pop(h, None)

                tag = (
                    f'\n<script data-ti="injected">\n'
                    f'{self._inject_script}\n'
                    f'</script>\n'
                ).encode("utf-8")

                body  = resp.content
                lower = body.lower()
                # Prefer injecting just before </body>, then </html>, then append
                for marker in (b"</body>", b"</html>"):
                    idx = lower.rfind(marker)
                    if idx != -1:
                        resp.content = body[:idx] + tag + body[idx:]
                        injected = True
                        break
                if not injected:
                    resp.content = body + tag
                    injected = True

                resp_headers = dict(resp.headers)   # refresh after modifications

        # ── Summary (shown in the traffic table) ─────────────────────────────
        entry: dict[str, Any] = {
            "id":           eid,
            "timestamp":    _now_iso(),
            "method":       req.method,
            "scheme":       req.scheme,
            "host":         req.pretty_host,
            "path":         req.path,
            "url":          req.pretty_url,
            "status":       resp.status_code,
            "status_text":  resp.reason or "",
            "content_type": resp.headers.get("content-type", ""),
            "size":         len(resp.content) if resp.content else 0,
            "duration":     duration,
            "injected":     injected,
        }

        # ── Full detail (shown in the detail panel) ───────────────────────────
        detail: dict[str, Any] = {
            **entry,
            "request": {
                "method":       req.method,
                "url":          req.pretty_url,
                "http_version": req.http_version,
                "headers":      req_headers,
                "body":         _decode_body(req.content, req_headers),
            },
            "response": {
                "status_code":  resp.status_code,
                "reason":       resp.reason or "",
                "http_version": resp.http_version,
                "headers":      resp_headers,
                "body":         _decode_body(resp.content, resp_headers),
            },
        }

        self._evict_oldest()
        self._entries[eid] = entry
        self._details[eid] = detail

        await self._broadcast({"type": "entry", "data": entry})

    async def error(self, flow: http.HTTPFlow) -> None:
        """Log connection/TLS errors as synthetic entries."""
        if not flow.error:
            return
        eid = flow.metadata.get("_id", str(uuid.uuid4()))
        req = flow.request

        entry: dict[str, Any] = {
            "id":           eid,
            "timestamp":    _now_iso(),
            "method":       req.method if req else "CONNECT",
            "scheme":       req.scheme  if req else "https",
            "host":         req.pretty_host if req else "?",
            "path":         req.path        if req else "/",
            "url":          req.pretty_url  if req else "?",
            "status":       0,
            "status_text":  "Connection Error",
            "content_type": "",
            "size":         0,
            "duration":     0,
            "error":        str(flow.error),
        }

        self._evict_oldest()
        self._entries[eid] = entry
        self._details[eid] = {**entry, "request": {}, "response": {}}

        await self._broadcast({"type": "entry", "data": entry})


# ── Register with mitmproxy ───────────────────────────────────────────────────
addons = [TrafficInspector()]
