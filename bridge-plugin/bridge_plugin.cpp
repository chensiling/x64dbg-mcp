#include "bridge_plugin.h"

// ---------------------------------------------------------------------------
// Global state definitions
// ---------------------------------------------------------------------------
HANDLE g_hHttpThread = NULL;
HANDLE g_hWatchdogThread = NULL;
HANDLE g_hBrokerProcess = NULL;
SOCKET g_listenSocket = INVALID_SOCKET;
volatile LONG g_running = 0;
int g_pluginHandle = 0;
HMODULE g_hModule = NULL;
bool g_consoleAllocated = false;
unsigned short g_httpPort = 0;
char g_instanceFile[MAX_PATH] = {0};
volatile LONG g_sessionRegistered = 0;

broker_config g_brokerConfig = {
    "http://127.0.0.1:21463",
    "python",
    "",
    "",
    3000,
    3,
    true,
};

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

static const handler_entry HANDLERS[] = {
    { CMD_READ_MEMORY,       handle_read_memory },
    { CMD_WRITE_MEMORY,      handle_write_memory },
    { CMD_DISASSEMBLE,       handle_disassemble },
    { CMD_GET_REGISTERS,     handle_get_registers },
    { CMD_SET_REGISTER,      handle_set_register },
    { CMD_GET_BREAKPOINTS,   handle_get_breakpoints },
    { CMD_SET_BREAKPOINT,    handle_set_breakpoint },
    { CMD_DELETE_BREAKPOINT, handle_delete_breakpoint },
    { CMD_TOGGLE_BREAKPOINT, handle_toggle_breakpoint },
    { CMD_GET_BREAKPOINT_CONDITION,    handle_get_breakpoint_condition },
    { CMD_SET_BREAKPOINT_CONDITION,    handle_set_breakpoint_condition },
    { CMD_APPEND_BREAKPOINT_CONDITION, handle_append_breakpoint_condition },
    { CMD_CLEAR_BREAKPOINT_CONDITION,  handle_clear_breakpoint_condition },
    { CMD_GET_DEBUG_STATE,   handle_get_debug_state },
    { CMD_RUN,               handle_run },
    { CMD_PAUSE,             handle_pause },
    { CMD_STOP,              handle_stop },
    { CMD_STEP_IN,           handle_step_in },
    { CMD_STEP_OVER,         handle_step_over },
    { CMD_STEP_OUT,          handle_step_out },
    { CMD_GET_MODULES,       handle_get_modules },
    { CMD_GET_MODULE_INFO,   handle_get_module_info },
    { CMD_GET_SYMBOLS,       handle_get_symbols },
    { CMD_EVALUATE,          handle_evaluate },
    { CMD_GET_MEMORY_MAP,    handle_get_memory_map },
    { CMD_GET_CALL_STACK,    handle_get_call_stack },
    { CMD_GET_LABEL,         handle_get_label },
    { CMD_SET_LABEL,         handle_set_label },
    { CMD_GET_COMMENT,       handle_get_comment },
    { CMD_SET_COMMENT,       handle_set_comment },
    { CMD_ASSEMBLE,          handle_assemble },
    { CMD_GET_STRING,        handle_get_string },
    { CMD_FIND_STRING,       handle_find_string },
    { CMD_RUN_TO,            handle_run_to },
    { CMD_SET_EIP,           handle_set_eip },
    { CMD_GET_THREADS,       handle_get_threads },
    { CMD_FIND_BYTES,        handle_find_bytes },
    { CMD_GET_FUNCTION_INFO, handle_get_function_info },
    { CMD_GET_XREFS,         handle_get_xrefs },
    { CMD_SET_BP_FILTER,     handle_set_bp_filter },
    { CMD_CMD_EXEC,          handle_cmd_exec },
    { CMD_ENUM_LABELS,       handle_enum_labels },
    { CMD_ENUM_COMMENTS,     handle_enum_comments },
    { CMD_ENUM_IMPORTS,      handle_enum_imports },
    { CMD_ENUM_EXPORTS,      handle_enum_exports },
};

cmd_handler get_handler(const char* method)
{
    if(!method)
        return NULL;

    for(size_t i = 0; i < sizeof(HANDLERS) / sizeof(HANDLERS[0]); i++)
    {
        if(strcmp(method, HANDLERS[i].method) == 0)
            return HANDLERS[i].handler;
    }
    return NULL;
}

void process_request(json_t* req, char* out_buf, size_t out_buf_size)
{
    const char* method = json_string_value(json_object_get(req, "method"));
    json_t* params = json_object_get(req, "params");
    const char* id = json_string_value(json_object_get(req, "id"));

    json_t* resp = NULL;
    json_t* emptyParams = NULL;
    if(!params)
    {
        emptyParams = json_object();
        params = emptyParams;
    }

    cmd_handler handler = get_handler(method);
    if(handler)
    {
        handler(req, params, &resp);
    }
    else if(!method)
    {
        resp = build_error_response(id, "missing method");
    }
    else
    {
        resp = json_object();
        json_object_set_new(resp, "id", json_string_safe(id));
        json_object_set_new(resp, "error", json_string("unknown method"));
    }

    if(resp)
    {
        char* json_str = json_dumps(resp, JSON_COMPACT);
        if(json_str)
        {
            size_t len = strlen(json_str);
            if(len < out_buf_size - 2)
            {
                memcpy(out_buf, json_str, len);
                out_buf[len] = '\n';
                out_buf[len + 1] = '\0';
            }
            else
            {
                out_buf[0] = '\0';
            }
            free(json_str);
        }
        json_decref(resp);
    }

    if(emptyParams)
        json_decref(emptyParams);
}

// ---------------------------------------------------------------------------
// Plugin lifecycle (x64dbg entry points)
// ---------------------------------------------------------------------------

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->sdkVersion = PLUG_SDKVERSION;
    initStruct->pluginVersion = 1;
    strncpy(initStruct->pluginName, "MCP Bridge Plugin", 256);
    g_pluginHandle = initStruct->pluginHandle;
    return true;
}

extern "C" __declspec(dllexport) bool plugstop()
{
    InterlockedExchange(&g_running, 0);
    if(g_listenSocket != INVALID_SOCKET)
    {
        shutdown(g_listenSocket, SD_BOTH);
        closesocket(g_listenSocket);
        g_listenSocket = INVALID_SOCKET;
    }
    if(g_hHttpThread)
    {
        WaitForSingleObject(g_hHttpThread, 3000);
        CloseHandle(g_hHttpThread);
        g_hHttpThread = NULL;
    }
    if(g_hWatchdogThread)
    {
        WaitForSingleObject(g_hWatchdogThread, 3000);
        CloseHandle(g_hWatchdogThread);
        g_hWatchdogThread = NULL;
    }
    if(g_hBrokerProcess)
    {
        CloseHandle(g_hBrokerProcess);
        g_hBrokerProcess = NULL;
    }
    delete_instance_file();
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    (void)setupStruct;
    init_console();
    load_broker_config();
    InterlockedExchange(&g_running, 1);
    g_hHttpThread = CreateThread(NULL, 0, http_thread, NULL, 0, NULL);
    g_hWatchdogThread = CreateThread(NULL, 0, watchdog_thread, NULL, 0, NULL);
    log_msg("[MCP Bridge] Plugin loaded successfully");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)lpReserved;
    if(ul_reason_for_call == DLL_PROCESS_ATTACH)
        g_hModule = hModule;
    if(ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        InterlockedExchange(&g_running, 0);
        delete_instance_file();
    }
    return TRUE;
}
