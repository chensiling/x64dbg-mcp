#ifndef MCP_PROTOCOL_H
#define MCP_PROTOCOL_H

#include <stdint.h>

#define HTTP_HOST "127.0.0.1"
#define HTTP_PORT_START 21464
#define HTTP_PORT_END 21564
#define HTTP_BUFFER_SIZE (256 * 1024)
#define HTTP_INSTANCE_ROOT "x64dbg-mcp"
#define HTTP_INSTANCE_DIR "instances"
#define MAX_COMMAND_SIZE (64 * 1024)

#define CMD_READ_MEMORY       "read_memory"
#define CMD_WRITE_MEMORY      "write_memory"
#define CMD_DISASSEMBLE       "disassemble"
#define CMD_GET_REGISTERS     "get_registers"
#define CMD_SET_REGISTER      "set_register"
#define CMD_GET_BREAKPOINTS   "get_breakpoints"
#define CMD_SET_BREAKPOINT    "set_breakpoint"
#define CMD_DELETE_BREAKPOINT "delete_breakpoint"
#define CMD_TOGGLE_BREAKPOINT "toggle_breakpoint"
#define CMD_GET_BREAKPOINT_CONDITION    "get_breakpoint_condition"
#define CMD_SET_BREAKPOINT_CONDITION    "set_breakpoint_condition"
#define CMD_APPEND_BREAKPOINT_CONDITION "append_breakpoint_condition"
#define CMD_CLEAR_BREAKPOINT_CONDITION  "clear_breakpoint_condition"
#define CMD_GET_DEBUG_STATE   "get_debug_state"
#define CMD_RUN               "run"
#define CMD_PAUSE             "pause"
#define CMD_STOP              "stop"
#define CMD_STEP_IN           "step_in"
#define CMD_STEP_OVER          "step_over"
#define CMD_STEP_OUT           "step_out"
#define CMD_GET_MODULES       "get_modules"
#define CMD_GET_MODULE_INFO   "get_module_info"
#define CMD_GET_SYMBOLS       "get_symbols"
#define CMD_EVALUATE          "evaluate"
#define CMD_GET_MEMORY_MAP    "get_memory_map"
#define CMD_GET_CALL_STACK    "get_call_stack"
#define CMD_GET_LABEL         "get_label"
#define CMD_SET_LABEL         "set_label"
#define CMD_GET_COMMENT       "get_comment"
#define CMD_SET_COMMENT       "set_comment"
#define CMD_ASSEMBLE          "assemble"
#define CMD_GET_STRING        "get_string"
#define CMD_FIND_STRING       "find_string"
#define CMD_RUN_TO             "run_to"
#define CMD_SET_EIP             "set_eip"
#define CMD_GET_THREADS         "get_threads"
#define CMD_FIND_BYTES          "find_bytes"
#define CMD_GET_FUNCTION_INFO   "get_function_info"
#define CMD_GET_XREFS           "get_xrefs"
#define CMD_SET_BP_FILTER       "set_bp_filter"
#define CMD_CMD_EXEC          "cmd_exec"
#define CMD_ENUM_LABELS        "enum_labels"
#define CMD_ENUM_COMMENTS      "enum_comments"
#define CMD_ENUM_IMPORTS       "enum_imports"
#define CMD_ENUM_EXPORTS       "enum_exports"

#endif // MCP_PROTOCOL_H
