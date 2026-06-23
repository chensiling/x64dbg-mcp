"""
x64dbg MCP Server - Exposes x64dbg debugger functionality via MCP protocol.
All addresses use HEX STRINGS to avoid JSON integer precision loss.
"""
import asyncio
import json
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from bridge_client import BridgeClient
from tool_registry import get_tools, mcp_to_bridge_command

bridge = BridgeClient()
server = Server("x64dbg-mcp")


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


@server.list_tools()
async def list_tools() -> list[Tool]:
    return get_tools()


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if not bridge.is_connected():
        if not bridge.connect():
            return [TextContent(type="text",
                text=json.dumps({
                    "ok": False,
                    "data": None,
                    "error": {
                        "code": "BRIDGE_UNAVAILABLE",
                        "message": "Cannot connect to x64dbg bridge.",
                    },
                }, indent=2))]

    cmd = mcp_to_bridge_command(name)
    result = bridge.call(cmd, arguments)

    if name == "string_read":
        _decode_string_read(result)

    return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
