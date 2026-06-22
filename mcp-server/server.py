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

bridge = BridgeClient()
server = Server("x64dbg-mcp")

def _hexify(obj):
    """Convert all integers to hex strings to avoid JSON precision loss."""
    if isinstance(obj, dict):
        return {k: _hexify(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_hexify(v) for v in obj]
    if isinstance(obj, int) and not isinstance(obj, bool):
        return f"0x{obj:X}"
    return obj

TOOL_TO_CMD = {
    "memory_read":       "read_memory",
    "memory_write":      "write_memory",
    "disassemble":       "disassemble",
    "registers_get":     "get_registers",
    "register_set":      "set_register",
    "breakpoints_list":  "get_breakpoints",
    "breakpoint_set":    "set_breakpoint",
    "breakpoint_delete": "delete_breakpoint",
    "breakpoint_toggle": "toggle_breakpoint",
    "debug_run":         "run",
    "debug_pause":       "pause",
    "debug_stop":        "stop",
    "debug_step_in":     "step_in",
    "debug_step_over":   "step_over",
    "debug_step_out":    "step_out",
    "debug_get_state":   "get_debug_state",
    "run_to":            "run_to",
    "set_eip":           "set_eip",
    "threads_get":       "get_threads",
    "find_bytes":        "find_bytes",
    "get_function_info": "get_function_info",
    "get_xrefs":         "get_xrefs",
    "set_bp_filter":     "set_bp_filter",
    "modules_get":       "get_modules",
    "module_info":       "get_module_info",
    "symbols_get":       "get_symbols",
    "evaluate":          "evaluate",
    "memory_map":        "get_memory_map",
    "call_stack":        "get_call_stack",
    "label_get":         "get_label",
    "label_set":         "set_label",
    "comment_get":       "get_comment",
    "comment_set":       "set_comment",
    "assemble":          "assemble",
    "string_read":       "get_string",
    "find_string":       "find_string",
    "cmd_exec":          "cmd_exec",
}

A = {"type": "string", "description": "Hex address string (e.g. '0x7FF642030338')."}
A0 = {"type": "string", "description": "Hex address string (e.g. '0x7FF642030338'). Required."}


def get_tools():
    return [
        Tool(name="memory_read", description="Read memory from the debugged process.",
             inputSchema={"type": "object", "properties": {
                 "addr": A0, "size": {"type": "string", "default": "256", "description": "Bytes to read (max 16MB)."}}, "required": ["addr"]}),
        Tool(name="memory_write", description="Write data to debugged process memory.",
             inputSchema={"type": "object", "properties": {
                 "addr": A0, "data": {"type": "string", "description": "Hex-encoded data ('90 90' or '9090')."}}, "required": ["addr", "data"]}),
        Tool(name="disassemble", description="Disassemble instructions. Use count or end address.",
             inputSchema={"type": "object", "properties": {
                 "addr": A0, "count": {"type": "string", "default": "10", "description": "Number of instructions (alternative to end)."},
                 "end": {"type": "string", "description": "End address (alternative to count)."}}, "required": ["addr"]}),
        Tool(name="registers_get", description="Get CPU registers. Pass name (e.g. 'rax') for single register, omit for all.",
             inputSchema={"type": "object", "properties": {
                 "name": {"type": "string", "description": "Optional: single register name (rax, rcx, rip, etc.)."}}}),
        Tool(name="register_set", description="Set a register value.",
             inputSchema={"type": "object", "properties": {
                 "name": {"type": "string", "description": "Register name (eip, rax, rcx...)."},
                 "value": {"type": "string", "description": "Value to set (hex string e.g. '0x1000' or decimal)."}}, "required": ["name", "value"]}),
        Tool(name="breakpoints_list", description="List all breakpoints.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="breakpoint_set", description="Set a breakpoint.",
             inputSchema={"type": "object", "properties": {
                 "addr": A0, "type": {"type": "string", "enum": ["normal", "hardware", "memory"], "default": "normal"},
         "hw_type": {"type": "string", "enum": ["access", "write", "execute"], "default": "execute", "description": "For hardware BP: access type."},
         "hw_size": {"type": "string", "enum": ["byte", "word", "dword", "qword"], "default": "dword", "description": "For hardware BP: size."},
         "condition": {"type": "string", "description": "Optional break condition expression."}}, "required": ["addr"]}),
        Tool(name="breakpoint_delete", description="Delete a breakpoint.",
             inputSchema={"type": "object", "properties": {"addr": A0}, "required": ["addr"]}),
        Tool(name="breakpoint_toggle", description="Toggle a breakpoint on/off.",
             inputSchema={"type": "object", "properties": {"addr": A0}, "required": ["addr"]}),
        Tool(name="debug_run", description="Run (continue) the debugged process.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="debug_pause", description="Pause the debugged process.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="debug_stop", description="Stop debugging.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="debug_step_in", description="Step into the next instruction.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="debug_step_over", description="Step over the next instruction.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="debug_step_out", description="Step out of the current function.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="debug_get_state", description="Get debugger state: running/paused/stopped.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="modules_get", description="List loaded modules in the debugged process.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="module_info", description="Get module information.",
             inputSchema={"type": "object", "properties": {
                 "addr": A, "name": {"type": "string", "description": "Module name (e.g. 'kernel32.dll')."}}}),
        Tool(name="symbols_get", description="Get symbols for a module.",
             inputSchema={"type": "object", "properties": {
                 "module_base": A0}, "required": ["module_base"]}),
        Tool(name="evaluate", description="Evaluate an x64dbg expression.",
             inputSchema={"type": "object", "properties": {
                 "expression": {"type": "string", "description": "Expression ('eip+0x10', '[eax]', 'kernel32.GetProcAddress')."}}, "required": ["expression"]}),
        Tool(name="memory_map", description="Get virtual memory map of the debugged process.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="call_stack", description="Get the call stack.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="label_get", description="Get a label at an address.",
             inputSchema={"type": "object", "properties": {"addr": A0}, "required": ["addr"]}),
        Tool(name="label_set", description="Set a label at an address.",
             inputSchema={"type": "object", "properties": {
                 "addr": A0, "label": {"type": "string", "description": "Label text."}}, "required": ["addr", "label"]}),
        Tool(name="comment_get", description="Get a comment at an address.",
             inputSchema={"type": "object", "properties": {"addr": A0}, "required": ["addr"]}),
        Tool(name="comment_set", description="Set a comment at an address.",
             inputSchema={"type": "object", "properties": {
                 "addr": A0, "comment": {"type": "string", "description": "Comment text."}}, "required": ["addr", "comment"]}),
        Tool(name="assemble", description="Assemble and write an instruction to an address.",
             inputSchema={"type": "object", "properties": {
                 "addr": A0, "instruction": {"type": "string", "description": "Assembly ('mov eax, 0x1234')."}}, "required": ["addr", "instruction"]}),
        Tool(name="string_read", description="Read a string at an address from the debugged process.",
             inputSchema={"type": "object", "properties": {"addr": A0}, "required": ["addr"]}),
        Tool(name="find_string", description="Fuzzy search for a string pattern in process memory.",
             inputSchema={"type": "object", "properties": {
                 "pattern": {"type": "string", "description": "String pattern to search for."}}, "required": ["pattern"]}),
        Tool(name="find_bytes", description="Search for a hex byte pattern in process memory.",
             inputSchema={"type": "object", "properties": {
                 "pattern": {"type": "string", "description": "Hex byte pattern ('48 8D 15' or '488D15')."}}, "required": ["pattern"]}),
        Tool(name="run_to", description="Set a temporary one-shot breakpoint and run to an address.",
             inputSchema={"type": "object", "properties": {"addr": A0}, "required": ["addr"]}),
        Tool(name="set_eip", description="Set the instruction pointer (EIP/RIP) to an address.",
             inputSchema={"type": "object", "properties": {"addr": A0}, "required": ["addr"]}),
        Tool(name="threads_get", description="Get the list of threads in the debugged process with details.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="get_function_info", description="Get function boundaries (start/end) for an address.",
             inputSchema={"type": "object", "properties": {"addr": A0}, "required": ["addr"]}),
        Tool(name="get_xrefs", description="Get cross-references (who references this address).",
             inputSchema={"type": "object", "properties": {"addr": A0}, "required": ["addr"]}),
        Tool(name="set_bp_filter", description="Set a filename filter on a breakpoint. When the BP hits, auto-continue unless filename matches.",
             inputSchema={"type": "object", "properties": {
                 "addr": A0, "filename": {"type": "string", "description": "Filename pattern to match (case-insensitive substring)."}}, "required": ["addr", "filename"]}),
        Tool(name="cmd_exec", description="Execute an x64dbg console command directly.",
             inputSchema={"type": "object", "properties": {
                 "command": {"type": "string", "description": "x64dbg command ('alloc 0x1000', 'msg Hello')."}}, "required": ["command"]}),
    ]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return get_tools()


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if not bridge.is_connected():
        if not bridge.connect():
            return [TextContent(type="text",
                text="Error: Cannot connect to x64dbg bridge.")]

    cmd = TOOL_TO_CMD.get(name, name)
    result = bridge.call(cmd, arguments)

    # Auto-decode string_read hex results
    if name == "string_read" and "hex" in result:
        hex_data = result["hex"]
        try:
            raw = bytes.fromhex(hex_data[2:] if hex_data.startswith("0x") else hex_data)
            # Truncate at first double null on even boundary (UTF-16LE alignment)
            dnull = -1
            for i in range(0, len(raw) - 1, 2):
                if raw[i] == 0 and raw[i+1] == 0:
                    dnull = i
                    break
            if dnull >= 0:
                raw = raw[:dnull]
            # Try UTF-16LE
            try:
                decoded = raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
                if decoded:
                    result["string"] = decoded
                    result["encoding"] = "utf-16-le"
            except:
                pass
            # Try ASCII if UTF-16LE produced too short or failed
            if "string" not in result or len(result["string"]) < 2:
                try:
                    decoded = raw.decode("ascii").rstrip("\x00")
                    result["string"] = decoded
                    result["encoding"] = "ascii"
                except:
                    pass
            # Try UTF-8
            if "string" not in result:
                try:
                    decoded = raw.decode("utf-8").rstrip("\x00")
                    result["string"] = decoded
                    result["encoding"] = "utf-8"
                except:
                    result["string"] = hex_data
        except:
            pass

    return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
