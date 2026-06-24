"""
x64dbg MCP Server - Exposes x64dbg debugger functionality via MCP protocol.
All addresses use HEX STRINGS to avoid JSON integer precision loss.
"""
import asyncio
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import time
from typing import Any
import urllib.error
import urllib.request

BROKER_HOST = "127.0.0.1"
BROKER_PORT = 21463
BROKER_STATE_LOCK = threading.Lock()
BROKER_PLUGINS: dict[str, dict[str, Any]] = {}
BROKER_SESSIONS: dict[str, dict[str, Any]] = {}
BROKER_WEB_ROOT: Path | None = None
BROKER_STALE_AFTER_SECONDS = 30


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seen_timestamp(value: Any) -> float:
    if not isinstance(value, str) or not value:
        return 0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0


def _prune_stale_locked() -> None:
    cutoff = datetime.now(timezone.utc).timestamp() - BROKER_STALE_AFTER_SECONDS
    stale_sessions = [
        plugin_id for plugin_id, session in BROKER_SESSIONS.items()
        if _seen_timestamp(session.get("last_seen")) < cutoff
    ]
    for plugin_id in stale_sessions:
        BROKER_SESSIONS.pop(plugin_id, None)

    stale_plugins = [
        plugin_id for plugin_id, plugin in BROKER_PLUGINS.items()
        if _seen_timestamp(plugin.get("last_seen")) < cutoff
    ]
    for plugin_id in stale_plugins:
        BROKER_PLUGINS.pop(plugin_id, None)


def _allocate_alias(preferred: str | None = None) -> str:
    used = {session.get("alias") for session in BROKER_SESSIONS.values()}
    if preferred and preferred not in used:
        return preferred
    for code in range(ord("A"), ord("Z") + 1):
        alias = chr(code)
        if alias not in used:
            return alias
    return f"S{len(used) + 1}"


def _broker_snapshot() -> dict[str, Any]:
    with BROKER_STATE_LOCK:
        _prune_stale_locked()
        plugins = list(BROKER_PLUGINS.values())
        sessions = list(BROKER_SESSIONS.values())
    return {
        "ok": True,
        "broker": "running",
        "version": "0.1.0",
        "plugins": len(plugins),
        "sessions": len(sessions),
        "plugin_list": plugins,
        "session_list": sessions,
        "time": _utc_now(),
    }


def _session_error(alias: str, sessions: list[dict[str, Any]]) -> str:
    if alias:
        return f"session alias not found: {alias}"
    if not sessions:
        return "no active debug session"
    aliases = ", ".join(str(item.get("alias") or "?") for item in sessions)
    return f"multiple active debug sessions ({aliases}); route through /<alias>/rpc"


def _select_session(alias: str = "") -> tuple[dict[str, Any] | None, str | None]:
    with BROKER_STATE_LOCK:
        _prune_stale_locked()
        sessions = list(BROKER_SESSIONS.values())
        if alias:
            session = next((item for item in sessions if item.get("alias") == alias), None)
        else:
            session = sessions[0] if len(sessions) == 1 else None
    if session:
        return session, None
    return None, _session_error(alias, sessions)


def _forward_rpc_bytes(alias: str, body: bytes) -> bytes:
    session, error = _select_session(alias)
    if not session:
        return json.dumps({"ok": False, "error": error}, ensure_ascii=False).encode("utf-8")

    control_url = str(session.get("control_url", "")).rstrip("/")
    request = urllib.request.Request(
        f"{control_url}/rpc",
        data=body or b"{}",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.read(256 * 1024)


def _call_bridge_tool(command: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    from bridge_client import _convert_addrs, _error_response, _normalize_response

    request = {
        "id": str(int(time.time() * 1000000)),
        "method": command,
        "params": _convert_addrs(params or {}),
    }
    try:
        raw = _forward_rpc_bytes("", json.dumps(request).encode("utf-8"))
        response = json.loads(raw.decode("utf-8")) if raw else {}
        return _normalize_response(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        return _error_response("TRANSPORT_ERROR", str(exc))


def _default_health_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>x64dbg MCP Health</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #202124; }
    h1 { font-size: 22px; margin: 0 0 16px; }
    table { border-collapse: collapse; width: 100%; margin-top: 12px; }
    th, td { border-bottom: 1px solid #ddd; padding: 8px; text-align: left; font-size: 13px; }
    th { background: #f4f6f8; }
    .ok { color: #137333; font-weight: 600; }
    .muted { color: #5f6368; }
    code { background: #f1f3f4; padding: 1px 4px; border-radius: 3px; }
  </style>
</head>
<body>
  <h1>x64dbg MCP Broker</h1>
  <div id="status" class="muted">Loading...</div>
  <h2>Sessions</h2>
  <table id="sessions"></table>
  <h2>Plugins</h2>
  <table id="plugins"></table>
  <script>
    function row(values) { return "<tr>" + values.map(v => "<td>" + (v ?? "") + "</td>").join("") + "</tr>"; }
    function table(id, headers, rows) {
      document.getElementById(id).innerHTML = "<tr>" + headers.map(h => "<th>" + h + "</th>").join("") + "</tr>" + rows.join("");
    }
    async function refresh() {
      const res = await fetch("/api/health");
      const data = await res.json();
      document.getElementById("status").innerHTML = '<span class="ok">running</span> ' +
        data.sessions + " sessions, " + data.plugins + " plugins, " + data.time;
      table("sessions", ["Alias", "Target", "State", "Plugin", "URL"], data.session_list.map(s =>
        row([s.alias, s.target_hint || s.target_name, s.state, s.plugin_id, "<code>" + s.control_url + "</code>"])));
      table("plugins", ["Plugin", "PID", "State", "Port", "Target"], data.plugin_list.map(p =>
        row([p.plugin_id, p.pid, p.state, p.control_port, p.target_hint])));
    }
    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>"""


class BrokerHandler(BaseHTTPRequestHandler):
    server_version = "x64dbg-mcp-broker/0.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, status: int, data: Any) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, status: int, html_text: str) -> None:
        raw = html_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b"{}"
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("expected JSON object")
        return data

    def do_GET(self) -> None:
        if self.path == "/health":
            health_file = BROKER_WEB_ROOT / "health.html" if BROKER_WEB_ROOT else None
            if health_file and health_file.exists():
                try:
                    self._send_html(200, health_file.read_text(encoding="utf-8"))
                    return
                except OSError:
                    pass
            self._send_html(200, _default_health_html())
            return
        if self.path == "/api/health":
            self._send_json(200, _broker_snapshot())
            return
        if self.path == "/api/instances":
            self._send_json(200, {"ok": True, "instances": _broker_snapshot()["plugin_list"]})
            return
        if self.path == "/api/sessions":
            self._send_json(200, {"ok": True, "sessions": _broker_snapshot()["session_list"]})
            return
        self._send_json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        if self.path == "/api/register_session":
            self._handle_register_session()
            return
        if self.path == "/api/unregister_session":
            self._handle_unregister_session()
            return
        if self.path.endswith("/rpc"):
            self._handle_rpc_proxy()
            return
        self._send_json(404, {"ok": False, "error": "not found"})

    def _handle_register_session(self) -> None:
        try:
            payload = self._read_json()
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})
            return

        plugin_id = str(payload.get("plugin_id") or payload.get("pid") or payload.get("control_url") or "")
        control_url = str(payload.get("control_url") or "")
        if not plugin_id or not control_url:
            self._send_json(400, {"ok": False, "error": "plugin_id and control_url are required"})
            return

        now = _utc_now()
        with BROKER_STATE_LOCK:
            _prune_stale_locked()
            plugin = dict(payload)
            plugin["plugin_id"] = plugin_id
            plugin["last_seen"] = now
            BROKER_PLUGINS[plugin_id] = plugin

            alias = BROKER_SESSIONS.get(plugin_id, {}).get("alias") or _allocate_alias(payload.get("preferred_alias"))
            session = dict(payload)
            session["plugin_id"] = plugin_id
            session["alias"] = alias
            session["registered_at"] = BROKER_SESSIONS.get(plugin_id, {}).get("registered_at", now)
            session["last_seen"] = now
            BROKER_SESSIONS[plugin_id] = session

        self._send_json(200, {"ok": True, "alias": alias, "plugin_id": plugin_id})

    def _handle_unregister_session(self) -> None:
        try:
            payload = self._read_json()
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})
            return
        plugin_id = str(payload.get("plugin_id") or payload.get("pid") or payload.get("control_url") or "")
        with BROKER_STATE_LOCK:
            if plugin_id:
                BROKER_SESSIONS.pop(plugin_id, None)
                if plugin_id in BROKER_PLUGINS:
                    BROKER_PLUGINS[plugin_id]["state"] = "idle"
                    BROKER_PLUGINS[plugin_id]["last_seen"] = _utc_now()
        self._send_json(200, {"ok": True})

    def _handle_rpc_proxy(self) -> None:
        alias = self.path.strip("/").split("/", 1)[0] if self.path != "/rpc" else ""
        with BROKER_STATE_LOCK:
            _prune_stale_locked()
            sessions = list(BROKER_SESSIONS.values())
            if alias:
                session = next((item for item in sessions if item.get("alias") == alias), None)
            else:
                session = sessions[0] if len(sessions) == 1 else None
        if not session:
            if alias:
                message = f"session alias not found: {alias}"
            elif not sessions:
                message = "no active debug session"
            else:
                aliases = ", ".join(str(item.get("alias") or "?") for item in sessions)
                message = f"multiple active debug sessions ({aliases}); route through /<alias>/rpc"
            self._send_json(404, {"ok": False, "error": message})
            return

        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length > 0 else b"{}"
        control_url = str(session.get("control_url", "")).rstrip("/")
        request = urllib.request.Request(
            f"{control_url}/rpc",
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                raw = response.read(256 * 1024)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self._send_json(502, {"ok": False, "error": str(exc)})
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def _json_response(data: Any, status_code: int = 200):
    from starlette.responses import JSONResponse

    return JSONResponse(
        data,
        status_code=status_code,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "no-store",
        },
    )


def _html_response(text: str, status_code: int = 200):
    from starlette.responses import HTMLResponse

    return HTMLResponse(
        text,
        status_code=status_code,
        headers={"Cache-Control": "no-store"},
    )


async def _health_route(request):
    health_file = BROKER_WEB_ROOT / "health.html" if BROKER_WEB_ROOT else None
    if health_file and health_file.exists():
        try:
            return _html_response(health_file.read_text(encoding="utf-8"))
        except OSError:
            pass
    return _html_response(_default_health_html())


async def _api_health_route(request):
    return _json_response(_broker_snapshot())


async def _api_instances_route(request):
    return _json_response({"ok": True, "instances": _broker_snapshot()["plugin_list"]})


async def _api_sessions_route(request):
    return _json_response({"ok": True, "sessions": _broker_snapshot()["session_list"]})


async def _register_session_route(request):
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise ValueError("expected JSON object")
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        return _json_response({"ok": False, "error": str(exc)}, 400)

    plugin_id = str(payload.get("plugin_id") or payload.get("pid") or payload.get("control_url") or "")
    control_url = str(payload.get("control_url") or "")
    if not plugin_id or not control_url:
        return _json_response({"ok": False, "error": "plugin_id and control_url are required"}, 400)

    now = _utc_now()
    with BROKER_STATE_LOCK:
        _prune_stale_locked()
        plugin = dict(payload)
        plugin["plugin_id"] = plugin_id
        plugin["last_seen"] = now
        BROKER_PLUGINS[plugin_id] = plugin

        alias = BROKER_SESSIONS.get(plugin_id, {}).get("alias") or _allocate_alias(payload.get("preferred_alias"))
        session = dict(payload)
        session["plugin_id"] = plugin_id
        session["alias"] = alias
        session["registered_at"] = BROKER_SESSIONS.get(plugin_id, {}).get("registered_at", now)
        session["last_seen"] = now
        BROKER_SESSIONS[plugin_id] = session

    return _json_response({"ok": True, "alias": alias, "plugin_id": plugin_id})


async def _unregister_session_route(request):
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise ValueError("expected JSON object")
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        return _json_response({"ok": False, "error": str(exc)}, 400)

    plugin_id = str(payload.get("plugin_id") or payload.get("pid") or payload.get("control_url") or "")
    with BROKER_STATE_LOCK:
        if plugin_id:
            BROKER_SESSIONS.pop(plugin_id, None)
            if plugin_id in BROKER_PLUGINS:
                BROKER_PLUGINS[plugin_id]["state"] = "idle"
                BROKER_PLUGINS[plugin_id]["last_seen"] = _utc_now()
    return _json_response({"ok": True})


async def _rpc_proxy_route(request):
    alias = request.path_params.get("alias", "")
    body = await request.body()
    try:
        raw = _forward_rpc_bytes(alias, body)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return _json_response({"ok": False, "error": str(exc)}, 502)

    from starlette.responses import Response

    return Response(raw, media_type="application/json")


def _create_broker_mcp_server():
    from mcp.server import Server
    from mcp.types import TextContent, Tool

    from tool_registry import get_tools, mcp_to_bridge_command

    server = Server("x64dbg-mcp")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return get_tools()

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        cmd = mcp_to_bridge_command(name)
        result = _call_bridge_tool(cmd, arguments)

        if name == "string_read":
            _decode_string_read(result)

        return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]

    return server


class _StreamableHTTPASGIApp:
    def __init__(self, session_manager):
        self.session_manager = session_manager

    async def __call__(self, scope, receive, send):
        await self.session_manager.handle_request(scope, receive, send)


def run_broker(argv: list[str]) -> None:
    global BROKER_WEB_ROOT
    host = BROKER_HOST
    port = BROKER_PORT
    web_root: Path | None = None
    if "--host" in argv:
        host = argv[argv.index("--host") + 1]
    if "--port" in argv:
        port = int(argv[argv.index("--port") + 1])
    if "--web-root" in argv:
        web_root = Path(argv[argv.index("--web-root") + 1])
    BROKER_WEB_ROOT = web_root

    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from starlette.applications import Starlette
    from starlette.routing import Route
    import uvicorn

    mcp_server = _create_broker_mcp_server()
    session_manager = StreamableHTTPSessionManager(
        app=mcp_server,
        json_response=False,
        stateless=False,
    )
    mcp_app = _StreamableHTTPASGIApp(session_manager)

    app = Starlette(
        routes=[
            Route("/", endpoint=mcp_app, methods=["GET", "POST", "DELETE"]),
            Route("/health", endpoint=_health_route, methods=["GET"]),
            Route("/api/health", endpoint=_api_health_route, methods=["GET"]),
            Route("/api/instances", endpoint=_api_instances_route, methods=["GET"]),
            Route("/api/sessions", endpoint=_api_sessions_route, methods=["GET"]),
            Route("/api/register_session", endpoint=_register_session_route, methods=["POST"]),
            Route("/api/unregister_session", endpoint=_unregister_session_route, methods=["POST"]),
            Route("/rpc", endpoint=_rpc_proxy_route, methods=["POST"]),
            Route("/{alias:str}/rpc", endpoint=_rpc_proxy_route, methods=["POST"]),
        ],
        lifespan=lambda app: session_manager.run(),
    )

    print(f"x64dbg MCP broker listening on http://{host}:{port}", flush=True)
    print(f"x64dbg MCP health page: http://{host}:{port}/health", flush=True)
    uvicorn.run(app, host=host, port=port, log_level="warning")


def _looks_utf16le(raw: bytes) -> bool:
    sample = raw[:128]
    pairs = [(sample[i], sample[i + 1]) for i in range(0, len(sample) - 1, 2)]
    if not pairs:
        return False
    return sum(1 for _, high in pairs if high == 0) / len(pairs) >= 0.6


def _decode_string_read(result: dict[str, Any]) -> None:
    data = result.get("data")
    if not isinstance(data, dict) or "hex" not in data:
        return

    hex_data = data["hex"]
    if not isinstance(hex_data, str):
        return

    try:
        raw = bytes.fromhex(hex_data[2:] if hex_data.startswith("0x") else hex_data)
    except ValueError:
        return

    # Truncate at first double null on even boundary (UTF-16LE alignment).
    dnull = -1
    for i in range(0, len(raw) - 1, 2):
        if raw[i] == 0 and raw[i + 1] == 0:
            dnull = i
            break
    if dnull >= 0:
        raw = raw[:dnull]

    if _looks_utf16le(raw):
        try:
            decoded = raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
            if decoded:
                data["string"] = decoded
                data["encoding"] = "utf-16-le"
        except UnicodeError:
            pass

    if "string" not in data or len(data["string"]) < 2:
        try:
            decoded = raw.decode("ascii").rstrip("\x00")
            data["string"] = decoded
            data["encoding"] = "ascii"
        except UnicodeError:
            pass

    if "string" not in data:
        try:
            data["string"] = raw.decode("utf-8").rstrip("\x00")
            data["encoding"] = "utf-8"
        except UnicodeError:
            data["string"] = hex_data


async def run_mcp() -> None:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool

    from bridge_client import BridgeClient
    from tool_registry import get_tools, mcp_to_bridge_command

    bridge = BridgeClient()
    server = Server("x64dbg-mcp")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return get_tools()

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        if not bridge.is_connected():
            if not bridge.connect():
                message = bridge.last_error or "Cannot connect to x64dbg HTTP bridge."
                return [TextContent(type="text",
                    text=json.dumps({
                        "ok": False,
                        "data": None,
                        "error": {
                            "code": "BRIDGE_UNAVAILABLE",
                            "message": message,
                        },
                    }, indent=2))]

        cmd = mcp_to_bridge_command(name)
        result = bridge.call(cmd, arguments)

        if name == "string_read":
            _decode_string_read(result)

        return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    if "--broker" in sys.argv:
        run_broker(sys.argv[1:])
    else:
        asyncio.run(run_mcp())
