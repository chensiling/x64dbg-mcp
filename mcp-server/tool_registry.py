"""Tool metadata and command mapping for the x64dbg MCP server."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from mcp.types import Tool

ADDRESS = {"type": "string", "description": "Hex address string (e.g. '0x7FF642030338')."}
REQUIRED_ADDRESS = {
    "type": "string",
    "description": "Hex address string (e.g. '0x7FF642030338'). Required.",
}

TOOL_TO_CMD: dict[str, str] = {
    "memory_read": "read_memory",
    "memory_write": "write_memory",
    "disassemble": "disassemble",
    "registers_get": "get_registers",
    "register_set": "set_register",
    "breakpoints_list": "get_breakpoints",
    "breakpoint_set": "set_breakpoint",
    "breakpoint_delete": "delete_breakpoint",
    "breakpoint_toggle": "toggle_breakpoint",
    "breakpoint_condition_get": "get_breakpoint_condition",
    "breakpoint_condition_set": "set_breakpoint_condition",
    "breakpoint_condition_append": "append_breakpoint_condition",
    "breakpoint_condition_clear": "clear_breakpoint_condition",
    "debug_run": "run",
    "debug_pause": "pause",
    "debug_stop": "stop",
    "debug_step_in": "step_in",
    "debug_step_over": "step_over",
    "debug_step_out": "step_out",
    "debug_get_state": "get_debug_state",
    "run_to": "run_to",
    "set_eip": "set_eip",
    "threads_get": "get_threads",
    "find_bytes": "find_bytes",
    "get_function_info": "get_function_info",
    "get_xrefs": "get_xrefs",
    "set_bp_filter": "set_breakpoint_condition",
    "modules_get": "get_modules",
    "module_info": "get_module_info",
    "symbols_get": "get_symbols",
    "evaluate": "evaluate",
    "memory_map": "get_memory_map",
    "call_stack": "get_call_stack",
    "label_get": "get_label",
    "label_set": "set_label",
    "comment_get": "get_comment",
    "comment_set": "set_comment",
    "assemble": "assemble",
    "string_read": "get_string",
    "find_string": "find_string",
    "cmd_exec": "cmd_exec",
}

TOOL_DEFINITIONS: tuple[dict[str, Any], ...] = (
    {
        "name": "memory_read",
        "description": "Read memory from the debugged process.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "addr": REQUIRED_ADDRESS,
                "size": {"type": "string", "default": "256", "description": "Bytes to read (max 16MB)."},
            },
            "required": ["addr"],
        },
    },
    {
        "name": "memory_write",
        "description": "Write data to debugged process memory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "addr": REQUIRED_ADDRESS,
                "data": {"type": "string", "description": "Hex-encoded data ('90 90' or '9090')."},
            },
            "required": ["addr", "data"],
        },
    },
    {
        "name": "disassemble",
        "description": "Disassemble instructions with machine-code bytes, symbolized labels, and a human-readable text block. Use count or end address.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "addr": REQUIRED_ADDRESS,
                "count": {"type": "string", "default": "10", "description": "Number of instructions (alternative to end)."},
                "end": {"type": "string", "description": "End address (alternative to count)."},
            },
            "required": ["addr"],
        },
    },
    {
        "name": "registers_get",
        "description": "Get CPU registers. Pass name (e.g. 'rax') for single register, omit for all.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string", "description": "Optional: single register name (rax, rcx, rip, etc.)."}},
        },
    },
    {
        "name": "register_set",
        "description": "Set a register value.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Register name (eip, rax, rcx...)."},
                "value": {"type": "string", "description": "Value to set (hex string e.g. '0x1000' or decimal)."},
            },
            "required": ["name", "value"],
        },
    },
    {"name": "breakpoints_list", "description": "List all breakpoints.", "inputSchema": {"type": "object", "properties": {}}},
    {
        "name": "breakpoint_set",
        "description": "Set a breakpoint.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "addr": REQUIRED_ADDRESS,
                "type": {"type": "string", "enum": ["normal", "hardware", "memory"], "default": "normal"},
                "hw_type": {"type": "string", "enum": ["access", "write", "execute"], "default": "execute", "description": "For hardware BP: access type."},
                "hw_size": {"type": "string", "enum": ["byte", "word", "dword", "qword"], "default": "dword", "description": "For hardware BP: size."},
            },
            "required": ["addr"],
        },
    },
    {"name": "breakpoint_delete", "description": "Delete a breakpoint.", "inputSchema": {"type": "object", "properties": {"addr": REQUIRED_ADDRESS}, "required": ["addr"]}},
    {"name": "breakpoint_toggle", "description": "Toggle a breakpoint on/off.", "inputSchema": {"type": "object", "properties": {"addr": REQUIRED_ADDRESS}, "required": ["addr"]}},
    {
        "name": "breakpoint_condition_get",
        "description": "Read the native x64dbg break condition for a breakpoint.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "addr": REQUIRED_ADDRESS,
                "type": {"type": "string", "enum": ["auto", "normal", "hardware", "memory", "dll", "exception"], "default": "auto", "description": "Breakpoint type. auto searches common types at the address."},
            },
            "required": ["addr"],
        },
    },
    {
        "name": "breakpoint_condition_set",
        "description": "Set the native x64dbg break condition for an existing breakpoint.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "addr": REQUIRED_ADDRESS,
                "type": {"type": "string", "enum": ["auto", "normal", "hardware", "memory", "dll", "exception"], "default": "auto", "description": "Breakpoint type. auto searches common types at the address."},
                "condition": {"type": "string", "description": "x64dbg expression. Non-zero = break. Supports registers, memory, arithmetic, and x64dbg expression functions."},
                "conditions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple x64dbg expressions to combine into one break condition.",
                },
                "op": {"type": "string", "enum": ["and", "or"], "default": "and", "description": "How to combine conditions when conditions is provided."},
            },
            "required": ["addr"],
        },
    },
    {
        "name": "breakpoint_condition_append",
        "description": "Append one or more expressions to an existing x64dbg break condition.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "addr": REQUIRED_ADDRESS,
                "type": {"type": "string", "enum": ["auto", "normal", "hardware", "memory", "dll", "exception"], "default": "auto", "description": "Breakpoint type. auto searches common types at the address."},
                "condition": {"type": "string", "description": "x64dbg expression to append."},
                "conditions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple x64dbg expressions to append.",
                },
                "op": {"type": "string", "enum": ["and", "or"], "default": "and", "description": "How to combine existing and new conditions."},
            },
            "required": ["addr"],
        },
    },
    {
        "name": "breakpoint_condition_clear",
        "description": "Clear the native x64dbg break condition from a breakpoint.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "addr": REQUIRED_ADDRESS,
                "type": {"type": "string", "enum": ["auto", "normal", "hardware", "memory", "dll", "exception"], "default": "auto", "description": "Breakpoint type. auto searches common types at the address."},
            },
            "required": ["addr"],
        },
    },
    {"name": "debug_run", "description": "Run (continue) the debugged process.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "debug_pause", "description": "Pause the debugged process.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "debug_stop", "description": "Stop debugging.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "debug_step_in", "description": "Step into the next instruction.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "debug_step_over", "description": "Step over the next instruction.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "debug_step_out", "description": "Step out of the current function.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "debug_get_state", "description": "Get debugger state: running/paused/stopped.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "modules_get", "description": "List loaded modules in the debugged process.", "inputSchema": {"type": "object", "properties": {}}},
    {
        "name": "module_info",
        "description": "Get module information.",
        "inputSchema": {"type": "object", "properties": {"addr": ADDRESS, "name": {"type": "string", "description": "Module name (e.g. 'kernel32.dll')."}}},
    },
    {"name": "symbols_get", "description": "Get symbols for a module.", "inputSchema": {"type": "object", "properties": {"module_base": REQUIRED_ADDRESS}, "required": ["module_base"]}},
    {
        "name": "evaluate",
        "description": "Evaluate an x64dbg expression.",
        "inputSchema": {"type": "object", "properties": {"expression": {"type": "string", "description": "Expression ('eip+0x10', '[eax]', 'kernel32.GetProcAddress')."}}, "required": ["expression"]},
    },
    {"name": "memory_map", "description": "Get virtual memory map of the debugged process.", "inputSchema": {"type": "object", "properties": {}}},
    {
        "name": "call_stack",
        "description": "Get the call stack with module/symbol details and optional stack words.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "stack_words": {
                    "type": "string",
                    "default": "4",
                    "description": "Number of pointer-sized stack values to include for each frame (0-16).",
                },
            },
        },
    },
    {"name": "label_get", "description": "Get a label at an address.", "inputSchema": {"type": "object", "properties": {"addr": REQUIRED_ADDRESS}, "required": ["addr"]}},
    {"name": "label_set", "description": "Set a label at an address.", "inputSchema": {"type": "object", "properties": {"addr": REQUIRED_ADDRESS, "label": {"type": "string", "description": "Label text."}}, "required": ["addr", "label"]}},
    {"name": "comment_get", "description": "Get a comment at an address.", "inputSchema": {"type": "object", "properties": {"addr": REQUIRED_ADDRESS}, "required": ["addr"]}},
    {"name": "comment_set", "description": "Set a comment at an address.", "inputSchema": {"type": "object", "properties": {"addr": REQUIRED_ADDRESS, "comment": {"type": "string", "description": "Comment text."}}, "required": ["addr", "comment"]}},
    {"name": "assemble", "description": "Assemble and write an instruction to an address.", "inputSchema": {"type": "object", "properties": {"addr": REQUIRED_ADDRESS, "instruction": {"type": "string", "description": "Assembly ('mov eax, 0x1234')."}}, "required": ["addr", "instruction"]}},
    {"name": "string_read", "description": "Read a string at an address from the debugged process.", "inputSchema": {"type": "object", "properties": {"addr": REQUIRED_ADDRESS}, "required": ["addr"]}},
    {"name": "find_string", "description": "Fuzzy search for a string pattern in process memory.", "inputSchema": {"type": "object", "properties": {"pattern": {"type": "string", "description": "String pattern to search for."}}, "required": ["pattern"]}},
    {"name": "find_bytes", "description": "Search for a hex byte pattern in process memory.", "inputSchema": {"type": "object", "properties": {"pattern": {"type": "string", "description": "Hex byte pattern ('48 8D 15' or '488D15')."}}, "required": ["pattern"]}},
    {"name": "run_to", "description": "Set a temporary one-shot breakpoint and run to an address.", "inputSchema": {"type": "object", "properties": {"addr": REQUIRED_ADDRESS}, "required": ["addr"]}},
    {"name": "set_eip", "description": "Set the instruction pointer (EIP/RIP) to an address.", "inputSchema": {"type": "object", "properties": {"addr": REQUIRED_ADDRESS}, "required": ["addr"]}},
    {"name": "threads_get", "description": "Get the list of threads in the debugged process with details.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "get_function_info", "description": "Get function boundaries (start/end) for an address.", "inputSchema": {"type": "object", "properties": {"addr": REQUIRED_ADDRESS}, "required": ["addr"]}},
    {"name": "get_xrefs", "description": "Get cross-references (who references this address).", "inputSchema": {"type": "object", "properties": {"addr": REQUIRED_ADDRESS}, "required": ["addr"]}},
    {
        "name": "set_bp_filter",
        "description": "Set a native x64dbg condition on a breakpoint. Pass condition or conditions+op. The breakpoint stops only when the final expression evaluates non-zero.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "addr": REQUIRED_ADDRESS,
                "condition": {"type": "string", "description": "x64dbg expression. Non-zero = break. Supports registers, memory, arithmetic, and x64dbg expression functions."},
                "conditions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple x64dbg expressions to combine into one break condition.",
                },
                "op": {"type": "string", "enum": ["and", "or"], "default": "and", "description": "How to combine conditions when conditions is provided."},
            },
            "required": ["addr"],
        },
    },
    {"name": "cmd_exec", "description": "Execute an x64dbg console command directly.", "inputSchema": {"type": "object", "properties": {"command": {"type": "string", "description": "x64dbg command ('alloc 0x1000', 'msg Hello')."}}, "required": ["command"]}},
)


def get_tools() -> list[Tool]:
    """Build MCP Tool objects from static metadata."""
    return [
        Tool(
            name=spec["name"],
            description=spec["description"],
            inputSchema=deepcopy(spec["inputSchema"]),
        )
        for spec in TOOL_DEFINITIONS
    ]


def mcp_to_bridge_command(name: str) -> str:
    """Map public MCP tool names to bridge plugin command names."""
    return TOOL_TO_CMD.get(name, name)
