"""
x64dbg MCP Bridge Client - Named pipe communication with the bridge plugin.
"""
import json
import time
from typing import Optional, Any

import win32file
import win32pipe
import pywintypes

PIPE_NAME = r"\\.\pipe\x64dbg_mcp_bridge"
PIPE_TIMEOUT_MS = 5000
DEFAULT_BUFFER_SIZE = 256 * 1024

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


class BridgeClient:
    """Client for communicating with the x64dbg MCP bridge plugin."""

    def __init__(self, pipe_name: str = PIPE_NAME):
        self._pipe_name = pipe_name
        self._handle: Any = None

    def connect(self) -> bool:
        try:
            self._handle = win32file.CreateFile(
                self._pipe_name,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING, 0, None,
            )
            win32pipe.SetNamedPipeHandleState(
                self._handle, win32pipe.PIPE_READMODE_MESSAGE, None, None,
            )
            return True
        except pywintypes.error:
            return False

    def disconnect(self):
        if self._handle is not None:
            try:
                win32file.CloseHandle(self._handle)
            except pywintypes.error:
                pass
            self._handle = None

    def is_connected(self) -> bool:
        return self._handle is not None

    def _send(self, data: str) -> None:
        win32file.WriteFile(self._handle, data.encode("utf-8"))

    def _recv(self) -> str:
        err_code, raw = win32file.ReadFile(self._handle, DEFAULT_BUFFER_SIZE)
        if isinstance(raw, bytes):
            return raw.decode("utf-8").strip()
        return raw.strip()

    def call(self, method: str, params: Optional[dict] = None,
             timeout_ms: int = PIPE_TIMEOUT_MS) -> dict:
        if self._handle is None:
            return _error_response("NOT_CONNECTED", "Not connected to bridge")

        request = json.dumps({
            "id": str(int(time.time() * 1000000)),
            "method": method,
            "params": _convert_addrs(params or {}),
        })

        try:
            self._send(request)
            response_str = self._recv()
            return _normalize_response(json.loads(response_str))
        except (pywintypes.error, json.JSONDecodeError) as e:
            self.disconnect()
            if self.connect():
                try:
                    self._send(request)
                    response_str = self._recv()
                    return _normalize_response(json.loads(response_str))
                except Exception:
                    pass
            return _error_response("TRANSPORT_ERROR", str(e))

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()
