#ifndef MCP_BRIDGE_PLUGIN_H
#define MCP_BRIDGE_PLUGIN_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>

#include "../pluginsdk/bridgemain.h"
#include "../pluginsdk/_plugins.h"
#include "../pluginsdk/_dbgfunctions.h"
#include "../pluginsdk/_scriptapi_label.h"
#include "../pluginsdk/_scriptapi_comment.h"
#include "../pluginsdk/_scriptapi_module.h"
#include "../pluginsdk/_scriptapi_symbol.h"
#include "../pluginsdk/jansson/jansson.h"
#include "protocol.h"

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------
extern HANDLE g_hHttpThread;
extern HANDLE g_hWatchdogThread;
extern HANDLE g_hBrokerProcess;
extern SOCKET g_listenSocket;
extern volatile LONG g_running;
extern int g_pluginHandle;
extern HMODULE g_hModule;
extern bool g_consoleAllocated;
extern unsigned short g_httpPort;
extern char g_instanceFile[MAX_PATH];
extern volatile LONG g_sessionRegistered;

struct broker_config
{
    char brokerUrl[256];
    char pythonPath[MAX_PATH];
    char serverScript[MAX_PATH];
    char webRoot[MAX_PATH];
    DWORD watchdogIntervalMs;
    int failuresBeforeNotify;
    bool autoRestartBroker;
};

extern broker_config g_brokerConfig;

// ---------------------------------------------------------------------------
// Command handler type and dispatch
// ---------------------------------------------------------------------------
typedef void (*cmd_handler)(json_t* req, json_t* params, json_t** out_resp);

struct handler_entry
{
    const char* method;
    cmd_handler handler;
};

cmd_handler get_handler(const char* method);
void process_request(json_t* req, char* out_buf, size_t out_buf_size);

// ---------------------------------------------------------------------------
// Utility functions (util.cpp)
// ---------------------------------------------------------------------------
void hex_encode(const unsigned char* data, size_t len, char* out);
size_t hex_decode(const char* hex, unsigned char* out);
void init_console();
void log_msg(const char* format, ...);
bool get_addr_param(json_t* params, const char* key, duint* out);
bool get_int_param(json_t* params, const char* key, duint defaultVal, duint* out);
json_t* addr_json(duint value);
json_t* json_string_safe(const char* value);
char* json_escape(const char* src);
json_t* build_value_response(const char* id, json_t* data);
json_t* build_error_response(const char* id, const char* msg);

// ---------------------------------------------------------------------------
// Debug state helpers (commands.cpp)
// ---------------------------------------------------------------------------
const char* get_debug_state_string();
bool wait_for_debug_state(const char* expected, DWORD timeoutMs);

// ---------------------------------------------------------------------------
// Breakpoint helpers (commands.cpp)
// ---------------------------------------------------------------------------
bool append_condition_expr(char* out, size_t outSize, const char* text, char* err, size_t errSize);
bool get_condition_joiner(json_t* params, const char** outJoiner, const char** outOp, char* err, size_t errSize);
bool build_break_condition(json_t* params, char* out, size_t outSize, char* err, size_t errSize);
const char* bp_type_to_string(BPXTYPE type);
bool get_bp_type_param(json_t* params, BPXTYPE* out, char* err, size_t errSize);
bool resolve_bp_ref(duint addr, BPXTYPE requestedType, BP_REF* ref, BPXTYPE* actualType);

struct text_capture
{
    char* value;
    size_t valueSize;
};

void capture_text_callback(const char* text, void* userdata);
bool read_break_condition(duint addr, BPXTYPE requestedType, char* out, size_t outSize, BPXTYPE* actualType);
bool write_break_condition(duint addr, BPXTYPE requestedType, const char* condition, BPXTYPE* actualType, char* err, size_t errSize);
bool combine_break_conditions(const char* left, const char* right, json_t* params, char* out, size_t outSize, const char** outOp, char* err, size_t errSize);

// ---------------------------------------------------------------------------
// Command handlers (commands.cpp)
// ---------------------------------------------------------------------------
void handle_read_memory(json_t* req, json_t* params, json_t** out_resp);
void handle_write_memory(json_t* req, json_t* params, json_t** out_resp);
json_t* describe_disasm_address(duint addr, char* outDisplay, size_t displaySize, char* outSymbol, size_t symbolSize);
void handle_disassemble(json_t* req, json_t* params, json_t** out_resp);
void handle_get_registers(json_t* req, json_t* params, json_t** out_resp);
void handle_set_register(json_t* req, json_t* params, json_t** out_resp);
void handle_get_breakpoints(json_t* req, json_t* params, json_t** out_resp);
void handle_set_breakpoint(json_t* req, json_t* params, json_t** out_resp);
void handle_delete_breakpoint(json_t* req, json_t* params, json_t** out_resp);
void handle_toggle_breakpoint(json_t* req, json_t* params, json_t** out_resp);
void handle_get_debug_state(json_t* req, json_t* params, json_t** out_resp);
void handle_run(json_t* req, json_t* params, json_t** out_resp);
void handle_pause(json_t* req, json_t* params, json_t** out_resp);
void handle_stop(json_t* req, json_t* params, json_t** out_resp);
void handle_step_in(json_t* req, json_t* params, json_t** out_resp);
void handle_step_over(json_t* req, json_t* params, json_t** out_resp);
void handle_step_out(json_t* req, json_t* params, json_t** out_resp);
void handle_get_modules(json_t* req, json_t* params, json_t** out_resp);
void handle_get_module_info(json_t* req, json_t* params, json_t** out_resp);
void handle_get_symbols(json_t* req, json_t* params, json_t** out_resp);
void handle_evaluate(json_t* req, json_t* params, json_t** out_resp);
void handle_get_memory_map(json_t* req, json_t* params, json_t** out_resp);
json_t* describe_stack_address(duint addr);
void handle_get_call_stack(json_t* req, json_t* params, json_t** out_resp);
void handle_get_label(json_t* req, json_t* params, json_t** out_resp);
void handle_set_label(json_t* req, json_t* params, json_t** out_resp);
void handle_get_comment(json_t* req, json_t* params, json_t** out_resp);
void handle_set_comment(json_t* req, json_t* params, json_t** out_resp);
void handle_assemble(json_t* req, json_t* params, json_t** out_resp);
void handle_run_to(json_t* req, json_t* params, json_t** out_resp);
void handle_set_eip(json_t* req, json_t* params, json_t** out_resp);
void handle_get_threads(json_t* req, json_t* params, json_t** out_resp);
void handle_get_breakpoint_condition(json_t* req, json_t* params, json_t** out_resp);
void handle_set_breakpoint_condition(json_t* req, json_t* params, json_t** out_resp);
void handle_append_breakpoint_condition(json_t* req, json_t* params, json_t** out_resp);
void handle_clear_breakpoint_condition(json_t* req, json_t* params, json_t** out_resp);
void handle_set_bp_filter(json_t* req, json_t* params, json_t** out_resp);
void handle_find_bytes(json_t* req, json_t* params, json_t** out_resp);
void handle_get_function_info(json_t* req, json_t* params, json_t** out_resp);
void handle_get_xrefs(json_t* req, json_t* params, json_t** out_resp);
void handle_get_string(json_t* req, json_t* params, json_t** out_resp);
char* normalize_string(const char* s);
void handle_find_string(json_t* req, json_t* params, json_t** out_resp);
void handle_enum_labels(json_t* req, json_t* params, json_t** out_resp);
void handle_enum_comments(json_t* req, json_t* params, json_t** out_resp);
void handle_enum_imports(json_t* req, json_t* params, json_t** out_resp);
void handle_enum_exports(json_t* req, json_t* params, json_t** out_resp);
void handle_cmd_exec(json_t* req, json_t* params, json_t** out_resp);

// ---------------------------------------------------------------------------
// HTTP server (http_server.cpp)
// ---------------------------------------------------------------------------
bool send_all(SOCKET sock, const char* data, int len);
void send_http_response(SOCKET client, int status, const char* reason, const char* contentType, const char* body);
int get_http_content_length(const char* headers);
void send_instance_info(SOCKET client);
void handle_http_client(SOCKET client);
DWORD WINAPI http_client_thread(LPVOID param);
bool bind_http_socket(SOCKET listenSocket, unsigned short* outPort);
DWORD WINAPI http_thread(LPVOID param);

// ---------------------------------------------------------------------------
// Broker management (broker.cpp)
// ---------------------------------------------------------------------------
void get_target_hint(char* out, size_t outSize);
bool get_plugin_config_dir(char* out, size_t outSize);
bool is_absolute_path(const char* path);
void resolve_relative_path(const char* baseDir, char* path, size_t pathSize);
void load_broker_config();
bool parse_http_url(const char* url, char* host, size_t hostSize, unsigned short* port, char* path, size_t pathSize);
bool broker_request(const char* method, const char* pathSuffix, const char* body, char* response, size_t responseSize);
bool broker_health_ok();
bool start_broker_process();
void notify_broker_down_once();
void register_or_unregister_session();
DWORD WINAPI watchdog_thread(LPVOID param);

// ---------------------------------------------------------------------------
// Instance file management (instance_file.cpp)
// ---------------------------------------------------------------------------
json_t* build_instance_info_json();
void delete_instance_file();
bool write_instance_file();

#endif // MCP_BRIDGE_PLUGIN_H
