"""
x64dbg MCP Bridge Client - HTTP communication with the bridge plugin.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

HTTP_HOST = "127.0.0.1"
HTTP_PORT_START = 21464
HTTP_PORT_END = 21564
BROKER_URL = "http://127.0.0.1:21463"
HTTP_TIMEOUT_MS = 5000
DEFAULT_BUFFER_SIZE = 256 * 1024
INSTANCE_DIR = Path(tempfile.gettempdir()) / "x64dbg-mcp" / "instances"

ADDR_KEYS = {"addr", "address", "module_base", "base", "start", "end", "from", "to"}


def _error_response(code: str, message: str, bridge_id: Any = None) -> dict:
    response = {
        "ok": False,
        "data": None,
        "error": {"code": code, "message": message},
    }
    if bridge_id is not None:
        response["bridge_id"] = bridge_id
    return response


def _convert_addrs(params: dict) -> dict:
    """Convert integer address params to hex strings (safety net for JSON precision)."""
    if not params:
        return params
    result = {}
    for k, v in params.items():
        if k in ADDR_KEYS and isinstance(v, int):
            result[k] = f"0x{v:X}"
        else:
            result[k] = v
    return result


def _normalize_response(response: Any) -> dict:
    """Convert bridge JSON-RPC-ish responses into a stable MCP payload shape."""
    if not isinstance(response, dict):
        return _error_response("INVALID_RESPONSE", f"Expected object, got {type(response).__name__}")

    bridge_id = response.get("id")
    if "error" in response:
        error = response["error"]
        if isinstance(error, dict):
            code = str(error.get("code", "BRIDGE_ERROR"))
            message = str(error.get("message", error))
        else:
            code = "BRIDGE_ERROR"
            message = str(error)
        return _error_response(code, message, bridge_id)

    data = response.get("result", response.get("data", response))
    ok = True
    error = None
    if isinstance(data, dict) and data.get("ok") is False:
        ok = False
        error = {
            "code": "COMMAND_FAILED",
            "message": str(data.get("error", "Bridge command failed")),
        }

    normalized = {
        "ok": ok,
        "data": data,
        "error": error,
    }
    if bridge_id is not None:
        normalized["bridge_id"] = bridge_id
    return normalized


def _normalize_base_url(value: str) -> str:
    value = value.strip().rstrip("/")
    if value.startswith("http://") or value.startswith("https://"):
        return value
    if value.isdigit():
        return f"http://{HTTP_HOST}:{value}"
    return f"http://{value}"


def discover_instances(instance_dir: Path = INSTANCE_DIR) -> list[dict]:
    """Read x64dbg HTTP bridge instance files from the temp directory."""
    instances: list[dict] = []
    if not instance_dir.exists():
        return instances

    for path in instance_dir.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        url = data.get("url")
        port = data.get("port")
        if not isinstance(url, str) and isinstance(port, int):
            url = f"http://{HTTP_HOST}:{port}"
        if not isinstance(url, str):
            continue
        data = dict(data)
        data["url"] = _normalize_base_url(url)
        data["instance_file"] = str(path)
        try:
            data["mtime"] = path.stat().st_mtime
        except OSError:
            data["mtime"] = 0
        instances.append(data)

    instances.sort(key=lambda item: item.get("mtime", 0), reverse=True)

    deduped: dict[str, dict] = {}
    for instance in instances:
        deduped.setdefault(instance["url"], instance)
    return list(deduped.values())


class BridgeClient:
    """HTTP client for communicating with the x64dbg MCP bridge plugin."""

    def __init__(self, base_url: Optional[str] = None):
        self._configured_url = _normalize_base_url(base_url) if base_url else None
        self._base_url: Optional[str] = None
        self.last_error: Optional[str] = None

    def _http_json(self, method: str, path: str, payload: Optional[dict] = None,
                   timeout_ms: int = HTTP_TIMEOUT_MS) -> Any:
        if not self._base_url:
            raise RuntimeError("HTTP bridge URL is not selected")

        url = f"{self._base_url}{path}"
        data = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout_ms / 1000) as response:
                raw = response.read(DEFAULT_BUFFER_SIZE).decode("utf-8").strip()
        except urllib.error.HTTPError as exc:
            raw = exc.read(DEFAULT_BUFFER_SIZE).decode("utf-8").strip()
        return json.loads(raw) if raw else {}

    def _probe_url(self, url: str) -> bool:
        original_url = self._base_url
        self._base_url = url
        try:
            health = self._http_json("GET", "/api/health")
            if isinstance(health, dict) and health.get("broker") == "running":
                return True
        except Exception:
            pass
        try:
            health = self._http_json("GET", "/health")
            return isinstance(health, dict) and health.get("ok") is True
        except Exception:
            return False
        finally:
            self._base_url = original_url

    def _candidate_urls(self) -> tuple[list[str], bool]:
        env_url = os.environ.get("X64DBG_MCP_URL")
        if env_url:
            return [_normalize_base_url(env_url)], False

        env_port = os.environ.get("X64DBG_MCP_PORT")
        if env_port:
            return [_normalize_base_url(env_port)], False

        instances = discover_instances()
        if instances:
            return [BROKER_URL] + [item["url"] for item in instances], True

        return [BROKER_URL] + [f"http://{HTTP_HOST}:{port}" for port in range(HTTP_PORT_START, HTTP_PORT_END + 1)], False

    def connect(self) -> bool:
        self.last_error = None
        require_single = False
        if self._configured_url:
            candidates = [self._configured_url]
        else:
            candidates, require_single = self._candidate_urls()
        if not candidates:
            if not self.last_error:
                self.last_error = "No x64dbg HTTP bridge instances found"
            return False

        errors = []
        live_urls = []
        original_url = self._base_url
        for url in candidates:
            if not url:
                continue
            try:
                if not self._probe_url(url):
                    raise RuntimeError("health check failed")
                live_urls.append(url)
            except Exception as exc:  # noqa: BLE001 - stored for user-facing diagnostics
                errors.append(f"{url}: {exc}")
        self._base_url = original_url

        if live_urls:
            if BROKER_URL in live_urls:
                self._base_url = BROKER_URL
                return True
            if require_single and len(live_urls) > 1:
                ports = ", ".join(url.rsplit(":", 1)[-1] for url in live_urls)
                self.last_error = f"Multiple x64dbg HTTP instances found ({ports}); set X64DBG_MCP_PORT or X64DBG_MCP_URL"
                return False
            self._base_url = live_urls[0]
            return True

        self.last_error = "; ".join(errors) if errors else "No x64dbg HTTP bridge instances found"
        return False

    def disconnect(self):
        self._base_url = None

    def is_connected(self) -> bool:
        return self._base_url is not None

    def call(self, method: str, params: Optional[dict] = None,
             timeout_ms: int = HTTP_TIMEOUT_MS) -> dict:
        if self._base_url is None and not self.connect():
            return _error_response("BRIDGE_UNAVAILABLE", self.last_error or "Cannot connect to x64dbg HTTP bridge")

        request = {
            "id": str(int(time.time() * 1000000)),
            "method": method,
            "params": _convert_addrs(params or {}),
        }

        try:
            response = self._http_json("POST", "/rpc", request, timeout_ms=timeout_ms)
            return _normalize_response(response)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError, RuntimeError) as exc:
            self.disconnect()
            return _error_response("TRANSPORT_ERROR", str(exc))

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()
