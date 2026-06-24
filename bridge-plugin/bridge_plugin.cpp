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
#include "../pluginsdk/jansson/jansson.h"
#include "protocol.h"

static HANDLE g_hHttpThread = NULL;
static HANDLE g_hWatchdogThread = NULL;
static HANDLE g_hBrokerProcess = NULL;
static SOCKET g_listenSocket = INVALID_SOCKET;
static volatile LONG g_running = 0;
static int g_pluginHandle = 0;
static HMODULE g_hModule = NULL;
static bool g_consoleAllocated = false;
static unsigned short g_httpPort = 0;
static char g_instanceFile[MAX_PATH] = {0};
static volatile LONG g_sessionRegistered = 0;

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

static broker_config g_brokerConfig = {
    "http://127.0.0.1:21463",
    "python",
    "",
    "",
    3000,
    3,
    true,
};

static bool send_all(SOCKET sock, const char* data, int len);

static void hex_encode(const unsigned char* data, size_t len, char* out)
{
    for(size_t i = 0; i < len; i++)
        sprintf(out + i * 2, "%02X", data[i]);
    out[len * 2] = '\0';
}

static size_t hex_decode(const char* hex, unsigned char* out)
{
    size_t len = 0;
    for(const char* p = hex; *p; p++)
    {
        if(*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            continue;
        unsigned int byte;
        if(sscanf(p, "%2x", &byte) == 1)
        {
            out[len++] = (unsigned char)byte;
            p++;
        }
        else break;
    }
    return len;
}

static void init_console()
{
    if(AllocConsole())
    {
        g_consoleAllocated = true;
        FILE* dummy;
        freopen_s(&dummy, "CONOUT$", "w", stdout);
        freopen_s(&dummy, "CONOUT$", "w", stderr);
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTitleW(L"x64dbg MCP Bridge");
        printf("========================================\n");
        printf("  x64dbg MCP Bridge Plugin Console\n");
        printf("  HTTP: pending\n");
        printf("========================================\n\n");
    }
}

static void log_msg(const char* format, ...)
{
    char buf[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    if(g_consoleAllocated)
        printf("%s\n", buf);
    _plugin_logputs(buf);
}

static bool get_addr_param(json_t* params, const char* key, duint* out)
{
    json_t* val = json_object_get(params, key);
    if(!val) return false;
    if(json_is_string(val))
    {
        *out = DbgValFromString(json_string_value(val));
        return true;
    }
    if(json_is_integer(val))
    {
        char hexBuf[32];
        snprintf(hexBuf, sizeof(hexBuf), "0x%llX", (unsigned long long)json_integer_value(val));
        *out = DbgValFromString(hexBuf);
        return true;
    }
    return false;
}

static bool get_int_param(json_t* params, const char* key, duint defaultVal, duint* out)
{
    json_t* val = json_object_get(params, key);
    if(!val)
    {
        *out = defaultVal;
        return true;
    }
    if(json_is_string(val))
    {
        *out = (duint)strtoull(json_string_value(val), NULL, 10);
        return true;
    }
    if(json_is_integer(val))
    {
        *out = (duint)json_integer_value(val);
        return true;
    }
    return false;
}

static json_t* addr_json(duint value)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)value);
    return json_string(buf);
}

static json_t* json_string_safe(const char* value)
{
    return json_string(value ? value : "");
}

static char* json_escape(const char* src)
{
    json_t* j = json_string(src);
    const char* raw = json_string_value(j);
    size_t len = strlen(raw);
    char* escaped = (char*)BridgeAlloc(len + 1);
    memcpy(escaped, raw, len + 1);
    json_decref(j);
    return escaped;
}

static json_t* build_value_response(const char* id, json_t* data)
{
    json_t* resp = json_object();
    json_object_set_new(resp, "id", json_string_safe(id));
    if(data)
        json_object_set_new(resp, "result", data);
    else
        json_object_set_new(resp, "error", json_string("no data"));
    return resp;
}

static json_t* build_error_response(const char* id, const char* msg)
{
    json_t* resp = json_object();
    json_object_set_new(resp, "id", json_string_safe(id));
    json_object_set_new(resp, "error", json_string_safe(msg));
    return resp;
}

static const char* get_debug_state_string()
{
    if(!DbgIsDebugging())
        return "stopped";
    return DbgIsRunning() ? "running" : "paused";
}

static bool wait_for_debug_state(const char* expected, DWORD timeoutMs)
{
    DWORD start = GetTickCount();
    do
    {
        if(strcmp(get_debug_state_string(), expected) == 0)
            return true;
        Sleep(25);
    } while(GetTickCount() - start < timeoutMs);

    return strcmp(get_debug_state_string(), expected) == 0;
}

static bool append_condition_expr(char* out, size_t outSize, const char* text, char* err, size_t errSize)
{
    size_t used = strlen(out);
    int written = snprintf(out + used, outSize - used, "%s", text);
    if(written < 0 || (size_t)written >= outSize - used)
    {
        snprintf(err, errSize, "combined condition is too long");
        return false;
    }
    return true;
}

static bool get_condition_joiner(json_t* params, const char** outJoiner, const char** outOp, char* err, size_t errSize)
{
    json_t* opValue = json_object_get(params, "op");
    const char* op = NULL;
    if(opValue)
    {
        if(!json_is_string(opValue))
        {
            snprintf(err, errSize, "op must be 'and' or 'or'");
            return false;
        }
        op = json_string_value(opValue);
    }
    if(!op || !op[0])
        op = "and";

    if(_stricmp(op, "and") == 0)
    {
        *outJoiner = "&&";
        *outOp = "and";
        return true;
    }
    if(_stricmp(op, "or") == 0)
    {
        *outJoiner = "||";
        *outOp = "or";
        return true;
    }

    snprintf(err, errSize, "op must be 'and' or 'or'");
    return false;
}

static bool build_break_condition(json_t* params, char* out, size_t outSize, char* err, size_t errSize)
{
    out[0] = '\0';
    json_t* conditionValue = json_object_get(params, "condition");
    json_t* conditionsValue = json_object_get(params, "conditions");

    if(conditionValue)
    {
        if(!json_is_string(conditionValue) || !json_string_value(conditionValue)[0])
        {
            snprintf(err, errSize, "condition must be a non-empty string");
            return false;
        }
        return append_condition_expr(out, outSize, json_string_value(conditionValue), err, errSize);
    }

    if(!conditionsValue)
    {
        snprintf(err, errSize, "condition or conditions is required");
        return false;
    }
    if(!json_is_array(conditionsValue) || json_array_size(conditionsValue) == 0)
    {
        snprintf(err, errSize, "conditions must be a non-empty string array");
        return false;
    }

    const char* joiner = NULL;
    const char* normalizedOp = NULL;
    if(!get_condition_joiner(params, &joiner, &normalizedOp, err, errSize))
        return false;

    size_t count = json_array_size(conditionsValue);
    for(size_t i = 0; i < count; i++)
    {
        json_t* item = json_array_get(conditionsValue, i);
        if(!json_is_string(item) || !json_string_value(item)[0])
        {
            snprintf(err, errSize, "conditions must contain only non-empty strings");
            return false;
        }

        if(i > 0 && !append_condition_expr(out, outSize, joiner, err, errSize))
            return false;
        if(!append_condition_expr(out, outSize, "(", err, errSize))
            return false;
        if(!append_condition_expr(out, outSize, json_string_value(item), err, errSize))
            return false;
        if(!append_condition_expr(out, outSize, ")", err, errSize))
            return false;
    }
    return true;
}

static const char* bp_type_to_string(BPXTYPE type)
{
    switch(type)
    {
    case bp_normal: return "normal";
    case bp_hardware: return "hardware";
    case bp_memory: return "memory";
    case bp_dll: return "dll";
    case bp_exception: return "exception";
    default: return "unknown";
    }
}

static bool get_bp_type_param(json_t* params, BPXTYPE* out, char* err, size_t errSize)
{
    json_t* typeValue = json_object_get(params, "type");
    if(!typeValue)
    {
        *out = bp_none;
        return true;
    }
    if(!json_is_string(typeValue))
    {
        snprintf(err, errSize, "type must be auto, normal, hardware, memory, dll, or exception");
        return false;
    }

    const char* type = json_string_value(typeValue);
    if(!type || !type[0] || _stricmp(type, "auto") == 0)
        *out = bp_none;
    else if(_stricmp(type, "normal") == 0)
        *out = bp_normal;
    else if(_stricmp(type, "hardware") == 0)
        *out = bp_hardware;
    else if(_stricmp(type, "memory") == 0)
        *out = bp_memory;
    else if(_stricmp(type, "dll") == 0)
        *out = bp_dll;
    else if(_stricmp(type, "exception") == 0)
        *out = bp_exception;
    else
    {
        snprintf(err, errSize, "type must be auto, normal, hardware, memory, dll, or exception");
        return false;
    }
    return true;
}

static bool resolve_bp_ref(duint addr, BPXTYPE requestedType, BP_REF* ref, BPXTYPE* actualType)
{
    const DBGFUNCTIONS* funcs = DbgFunctions();
    if(!funcs || !funcs->BpRefVa)
        return false;

    if(requestedType != bp_none)
    {
        memset(ref, 0, sizeof(*ref));
        if(funcs->BpRefVa(ref, requestedType, addr))
        {
            if(actualType)
                *actualType = requestedType;
            return true;
        }
        return false;
    }

    static const BPXTYPE preferredTypes[] = {
        bp_normal, bp_hardware, bp_memory, bp_dll, bp_exception
    };
    for(size_t i = 0; i < sizeof(preferredTypes) / sizeof(preferredTypes[0]); i++)
    {
        memset(ref, 0, sizeof(*ref));
        if(funcs->BpRefVa(ref, preferredTypes[i], addr))
        {
            if(actualType)
                *actualType = preferredTypes[i];
            return true;
        }
    }
    return false;
}

struct text_capture
{
    char* value;
    size_t valueSize;
};

static void capture_text_callback(const char* text, void* userdata)
{
    text_capture* capture = (text_capture*)userdata;
    if(!capture || !capture->value || capture->valueSize == 0)
        return;
    snprintf(capture->value, capture->valueSize, "%s", text ? text : "");
}

static bool read_break_condition(duint addr, BPXTYPE requestedType, char* out, size_t outSize, BPXTYPE* actualType)
{
    const DBGFUNCTIONS* funcs = DbgFunctions();
    if(!funcs || !funcs->BpGetFieldText)
        return false;

    BP_REF ref = {0};
    BPXTYPE foundType = bp_none;
    if(!resolve_bp_ref(addr, requestedType, &ref, &foundType))
        return false;

    out[0] = '\0';
    text_capture capture = { out, outSize };
    if(!funcs->BpGetFieldText(&ref, bpf_breakcondition, capture_text_callback, &capture))
        return false;

    if(actualType)
        *actualType = foundType;
    return true;
}

static bool write_break_condition(duint addr, BPXTYPE requestedType, const char* condition, BPXTYPE* actualType, char* err, size_t errSize)
{
    const DBGFUNCTIONS* funcs = DbgFunctions();
    if(!funcs || !funcs->BpSetFieldText)
    {
        snprintf(err, errSize, "breakpoint field API is unavailable");
        return false;
    }

    BP_REF ref = {0};
    BPXTYPE foundType = bp_none;
    if(!resolve_bp_ref(addr, requestedType, &ref, &foundType))
    {
        snprintf(err, errSize, "breakpoint not found at address");
        return false;
    }

    if(!funcs->BpSetFieldText(&ref, bpf_breakcondition, condition ? condition : ""))
    {
        snprintf(err, errSize, "failed to set breakpoint condition");
        return false;
    }

    GuiUpdateBreakpointsView();
    if(actualType)
        *actualType = foundType;
    return true;
}

static bool combine_break_conditions(const char* left, const char* right, json_t* params, char* out, size_t outSize, const char** outOp, char* err, size_t errSize)
{
    out[0] = '\0';
    const char* l = left ? left : "";
    const char* r = right ? right : "";
    if(!l[0])
        return append_condition_expr(out, outSize, r, err, errSize);
    if(!r[0])
        return append_condition_expr(out, outSize, l, err, errSize);

    const char* joiner = NULL;
    const char* normalizedOp = NULL;
    if(!get_condition_joiner(params, &joiner, &normalizedOp, err, errSize))
        return false;
    if(outOp)
        *outOp = normalizedOp;

    return append_condition_expr(out, outSize, "(", err, errSize) &&
        append_condition_expr(out, outSize, l, err, errSize) &&
        append_condition_expr(out, outSize, ")", err, errSize) &&
        append_condition_expr(out, outSize, joiner, err, errSize) &&
        append_condition_expr(out, outSize, "(", err, errSize) &&
        append_condition_expr(out, outSize, r, err, errSize) &&
        append_condition_expr(out, outSize, ")", err, errSize);
}

static void handle_read_memory(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    duint size = 256;
    if(!get_addr_param(params, "addr", &addr))
    {
        *out_resp = build_error_response(id, "read_memory requires addr (hex string or int)");
        return;
    }
    get_int_param(params, "size", 256, &size);
    unsigned char* buf = (unsigned char*)BridgeAlloc(size);
    if(!buf || !DbgMemRead(addr, buf, size))
    {
        if(buf) BridgeFree(buf);
        *out_resp = build_error_response(id, "Failed to read memory");
        return;
    }

    char* hex = (char*)BridgeAlloc(size * 2 + 1);
    hex_encode(buf, size, hex);
    BridgeFree(buf);

    json_t* data = json_object();
    json_object_set_new(data, "data", json_string(hex));
    json_object_set_new(data, "addr", addr_json(addr));
    json_object_set_new(data, "size", addr_json(size));
    *out_resp = build_value_response(id, data);
    BridgeFree(hex);
}

static void handle_write_memory(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr) || !json_is_string(json_object_get(params, "data")))
    {
        *out_resp = build_error_response(id, "write_memory requires addr (hex string) and data (hex string)");
        return;
    }
    const char* hex = json_string_value(json_object_get(params, "data"));
    size_t hexLen = strlen(hex);

    unsigned char* buf = (unsigned char*)BridgeAlloc(hexLen / 2 + 1);
    size_t decodedLen = hex_decode(hex, buf);
    bool ok = DbgMemWrite(addr, buf, (duint)decodedLen);
    BridgeFree(buf);

    json_t* data = json_object();
    json_object_set_new(data, "written", addr_json(ok ? decodedLen : 0));
    *out_resp = build_value_response(id, data);
}

static json_t* describe_disasm_address(duint addr, char* outDisplay, size_t displaySize, char* outSymbol, size_t symbolSize)
{
    char addressText[32] = {0};
    snprintf(addressText, sizeof(addressText), "%016llX", (unsigned long long)addr);
    if(outDisplay && displaySize)
        snprintf(outDisplay, displaySize, "%s", addressText);
    if(outSymbol && symbolSize)
        outSymbol[0] = '\0';

    json_t* details = json_object();
    json_object_set_new(details, "address", addr_json(addr));
    json_object_set_new(details, "address_text", json_string(addressText));

    const DBGFUNCTIONS* funcs = DbgFunctions();
    duint base = funcs && funcs->ModBaseFromAddr ? funcs->ModBaseFromAddr(addr) : 0;
    char module[MAX_MODULE_SIZE] = {0};
    if(base && funcs && funcs->ModNameFromAddr)
    {
        funcs->ModNameFromAddr(addr, module, false);
        json_object_set_new(details, "module", json_string(module));
        json_object_set_new(details, "module_base", addr_json(base));
        json_object_set_new(details, "rva", addr_json(addr - base));
    }

    bool hasSymbol = false;
    char qualified[512] = {0};
    SYMBOLINFO sym = {0};
    if(DbgGetSymbolInfoAt(addr, &sym))
    {
        const char* name = sym.undecoratedSymbol && sym.undecoratedSymbol[0] ? sym.undecoratedSymbol : sym.decoratedSymbol;
        if(name && name[0])
        {
            hasSymbol = true;
            duint displacement = addr >= sym.addr ? addr - sym.addr : 0;
            if(module[0])
                snprintf(qualified, sizeof(qualified), "%s.%s", module, name);
            else
                snprintf(qualified, sizeof(qualified), "%s", name);
            if(displacement)
                snprintf(qualified + strlen(qualified), sizeof(qualified) - strlen(qualified), "+0x%llX", (unsigned long long)displacement);

            json_object_set_new(details, "symbol", json_string(qualified));
            json_object_set_new(details, "symbol_name", json_string(name));
            json_object_set_new(details, "symbol_addr", addr_json(sym.addr));
            json_object_set_new(details, "symbol_displacement", addr_json(displacement));
            json_object_set_new(details, "symbol_ordinal", json_integer(sym.ordinal));
            if(sym.decoratedSymbol && sym.decoratedSymbol[0])
                json_object_set_new(details, "decorated", json_string(sym.decoratedSymbol));
            if(sym.undecoratedSymbol && sym.undecoratedSymbol[0])
                json_object_set_new(details, "undecorated", json_string(sym.undecoratedSymbol));
        }
        if(sym.freeDecorated && sym.decoratedSymbol)
            BridgeFree(sym.decoratedSymbol);
        if(sym.freeUndecorated && sym.undecoratedSymbol)
            BridgeFree(sym.undecoratedSymbol);
    }

    char label[MAX_LABEL_SIZE] = {0};
    if(!hasSymbol && DbgGetLabelAt(addr, SEG_DEFAULT, label) && label[0])
    {
        if(module[0])
            snprintf(qualified, sizeof(qualified), "%s.%s", module, label);
        else
            snprintf(qualified, sizeof(qualified), "%s", label);
        json_object_set_new(details, "symbol", json_string(qualified));
        json_object_set_new(details, "label", json_string(label));
        hasSymbol = true;
    }

    char comment[MAX_COMMENT_SIZE] = {0};
    if(DbgGetCommentAt(addr, comment) && comment[0])
        json_object_set_new(details, "comment", json_string(comment));

    char display[640] = {0};
    if(hasSymbol && qualified[0])
    {
        snprintf(display, sizeof(display), "%s <%s>", addressText, qualified);
        if(outSymbol && symbolSize)
            snprintf(outSymbol, symbolSize, "%s", qualified);
    }
    else if(module[0] && base)
    {
        snprintf(qualified, sizeof(qualified), "%s+0x%llX", module, (unsigned long long)(addr - base));
        snprintf(display, sizeof(display), "%s <%s>", addressText, qualified);
    }
    else
    {
        snprintf(display, sizeof(display), "%s", addressText);
    }
    json_object_set_new(details, "display", json_string(display));
    if(outDisplay && displaySize)
        snprintf(outDisplay, displaySize, "%s", display);

    return details;
}

static void handle_disassemble(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr))
    {
        *out_resp = build_error_response(id, "disassemble requires addr (hex string)");
        return;
    }
    duint count = 1;
    duint endAddr = 0;
    get_int_param(params, "count", 1, &count);
    if(json_is_string(json_object_get(params, "end")))
    {
        duint e = 0;
        if(get_addr_param(params, "end", &e) && e > addr)
            endAddr = e;
    }
    if(count < 1) count = 1;
    if(count > 256) count = 256;

    json_t* instructions = json_array();
    char* text = (char*)BridgeAlloc(HTTP_BUFFER_SIZE);
    size_t textLen = 0;
    if(text)
    {
        textLen += snprintf(text + textLen, HTTP_BUFFER_SIZE - textLen,
            "%-56s  %-30s  %s\n",
            "Address / Symbol",
            "Bytes",
            "Instruction");
        textLen += snprintf(text + textLen, HTTP_BUFFER_SIZE - textLen,
            "%-56s  %-30s  %s\n",
            "--------------------------------------------------------",
            "------------------------------",
            "----------------");
    }
    duint cur = addr;
    int i = 0;
    while(i < (int)count && (!endAddr || cur < endAddr))
    {
        BASIC_INSTRUCTION_INFO basicinfo = {0};
        DbgDisasmFastAt(cur, &basicinfo);

        DISASM_INSTR instr = {0};
        DbgDisasmAt(cur, &instr);

        json_t* entry = json_object();
        char display[640] = {0};
        char symbol[512] = {0};
        char addressText[32] = {0};
        snprintf(addressText, sizeof(addressText), "%016llX", (unsigned long long)cur);
        json_t* symbolDetails = describe_disasm_address(cur, display, sizeof(display), symbol, sizeof(symbol));
        json_object_set_new(entry, "address", addr_json(cur));
        json_object_set_new(entry, "address_text", json_string(addressText));
        json_object_set_new(entry, "display", json_string(display[0] ? display : ""));
        if(symbol[0])
            json_object_set_new(entry, "symbol", json_string(symbol));
        json_object_set_new(entry, "symbol_details", symbolDetails);
        json_object_set_new(entry, "instruction", json_string(instr.instruction));
        json_object_set_new(entry, "size", addr_json(basicinfo.size));
        char bytesText[96] = {0};
        if(basicinfo.size > 0 && basicinfo.size <= 32)
        {
            unsigned char bytes[32] = {0};
            bool bytesOk = DbgMemRead(cur, bytes, basicinfo.size);
            json_object_set_new(entry, "bytes_ok", json_boolean(bytesOk));
            if(bytesOk)
            {
                char hex[65] = {0};
                char spaced[96] = {0};
                hex_encode(bytes, basicinfo.size, hex);
                for(int j = 0; j < basicinfo.size; j++)
                {
                    char* out = spaced + j * 3;
                    if(j + 1 < basicinfo.size)
                        snprintf(out, 4, "%02X ", bytes[j]);
                    else
                        snprintf(out, 3, "%02X", bytes[j]);
                }
                json_object_set_new(entry, "bytes", json_string(hex));
                json_object_set_new(entry, "bytes_text", json_string(spaced));
                snprintf(bytesText, sizeof(bytesText), "%s", spaced);
            }
        }
        if(basicinfo.branch)
        {
            json_object_set_new(entry, "branch", json_true());
            json_object_set_new(entry, "branch_dest", addr_json(basicinfo.addr));
        }

        char line[1024] = {0};
        snprintf(line, sizeof(line), "%-56s  %-30s  %s",
            display[0] ? display : addressText,
            bytesText,
            instr.instruction);
        json_object_set_new(entry, "line", json_string(line));
        if(text && textLen < HTTP_BUFFER_SIZE - 2)
        {
            int written = snprintf(text + textLen, HTTP_BUFFER_SIZE - textLen, "%s\n", line);
            if(written > 0)
                textLen += (size_t)written < HTTP_BUFFER_SIZE - textLen ? (size_t)written : HTTP_BUFFER_SIZE - textLen - 1;
        }
        json_array_append_new(instructions, entry);

        i++;
        if(basicinfo.size <= 0)
            break;
        cur += basicinfo.size;
    }

    json_t* data = json_object();
    json_object_set_new(data, "address", addr_json(addr));
    json_object_set_new(data, "count", addr_json(count));
    if(text)
    {
        json_object_set_new(data, "text", json_string(text));
        BridgeFree(text);
    }
    json_object_set_new(data, "instructions", instructions);
    *out_resp = build_value_response(id, data);
}

static void handle_get_registers(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    const char* filterName = json_string_value(json_object_get(params, "name"));

    REGDUMP_AVX512 regdump = {0};
    if(!DbgGetRegDumpEx(&regdump, sizeof(REGDUMP_AVX512)))
    {
        *out_resp = build_error_response(id, "Failed to get register dump");
        return;
    }

    REGISTERCONTEXT_AVX512* ctx = &regdump.regcontext;

    // If filtering by name, use DbgEval for maximum accuracy (avoids thread context issues)
    if(filterName)
    {
        duint val = DbgValFromString(filterName);
        json_t* data = json_object();
        json_object_set_new(data, "name", json_string(filterName));
        json_object_set_new(data, "value", addr_json(val));
        json_object_set_new(data, "ok", json_true());
        *out_resp = build_value_response(id, data);
        return;
    }

    json_t* regs = json_object();
#ifdef _WIN64
    json_object_set_new(regs, "rax", addr_json(ctx->cax));
    json_object_set_new(regs, "rbx", addr_json(ctx->cbx));
    json_object_set_new(regs, "rcx", addr_json(ctx->ccx));
    json_object_set_new(regs, "rdx", addr_json(ctx->cdx));
    json_object_set_new(regs, "rsp", addr_json(ctx->csp));
    json_object_set_new(regs, "rbp", addr_json(ctx->cbp));
    json_object_set_new(regs, "rsi", addr_json(ctx->csi));
    json_object_set_new(regs, "rdi", addr_json(ctx->cdi));
    json_object_set_new(regs, "r8",  addr_json(ctx->r8));
    json_object_set_new(regs, "r9",  addr_json(ctx->r9));
    json_object_set_new(regs, "r10", addr_json(ctx->r10));
    json_object_set_new(regs, "r11", addr_json(ctx->r11));
    json_object_set_new(regs, "r12", addr_json(ctx->r12));
    json_object_set_new(regs, "r13", addr_json(ctx->r13));
    json_object_set_new(regs, "r14", addr_json(ctx->r14));
    json_object_set_new(regs, "r15", addr_json(ctx->r15));
    json_object_set_new(regs, "rip", addr_json(ctx->cip));
#else
    json_object_set_new(regs, "eax", addr_json(ctx->cax));
    json_object_set_new(regs, "ebx", addr_json(ctx->cbx));
    json_object_set_new(regs, "ecx", addr_json(ctx->ccx));
    json_object_set_new(regs, "edx", addr_json(ctx->cdx));
    json_object_set_new(regs, "esp", addr_json(ctx->csp));
    json_object_set_new(regs, "ebp", addr_json(ctx->cbp));
    json_object_set_new(regs, "esi", addr_json(ctx->csi));
    json_object_set_new(regs, "edi", addr_json(ctx->cdi));
    json_object_set_new(regs, "eip", addr_json(ctx->cip));
#endif
    json_object_set_new(regs, "eflags", addr_json(ctx->eflags));

    // Segment registers
    json_t* segs = json_object();
    json_object_set_new(segs, "cs", addr_json(ctx->cs));
    json_object_set_new(segs, "ds", addr_json(ctx->ds));
    json_object_set_new(segs, "es", addr_json(ctx->es));
    json_object_set_new(segs, "fs", addr_json(ctx->fs));
    json_object_set_new(segs, "gs", addr_json(ctx->gs));
    json_object_set_new(segs, "ss", addr_json(ctx->ss));
    json_object_set_new(regs, "segments", segs);

    // Debug registers
    json_t* drs = json_object();
    json_object_set_new(drs, "dr0", addr_json(ctx->dr0));
    json_object_set_new(drs, "dr1", addr_json(ctx->dr1));
    json_object_set_new(drs, "dr2", addr_json(ctx->dr2));
    json_object_set_new(drs, "dr3", addr_json(ctx->dr3));
    json_object_set_new(drs, "dr6", addr_json(ctx->dr6));
    json_object_set_new(drs, "dr7", addr_json(ctx->dr7));
    json_object_set_new(regs, "debug_regs", drs);

    // MXCSR
    json_object_set_new(regs, "mxcsr", addr_json(ctx->MxCsr));

    // XMM registers (full 128-bit)
#ifdef _WIN64
    json_t* xmm = json_object();
    for(int i = 0; i < 16; i++)
    {
        char name[8];
        char buf[64];
        snprintf(name, sizeof(name), "xmm%d", i);
        snprintf(buf, sizeof(buf), "0x%016llX%016llX",
            ctx->ZmmRegisters[i].Low.Low.High,
            ctx->ZmmRegisters[i].Low.Low.Low);
        json_object_set_new(xmm, name, json_string(buf));
    }
    json_object_set_new(regs, "xmm", xmm);
#endif

    // EFLAGS flags
    unsigned long long efl = ctx->eflags;
    json_t* flags = json_object();
    json_object_set_new(flags, "cf", json_boolean((efl & 1) != 0));
    json_object_set_new(flags, "pf", json_boolean((efl & 4) != 0));
    json_object_set_new(flags, "af", json_boolean((efl & 16) != 0));
    json_object_set_new(flags, "zf", json_boolean((efl & 64) != 0));
    json_object_set_new(flags, "sf", json_boolean((efl & 128) != 0));
    json_object_set_new(flags, "tf", json_boolean((efl & 256) != 0));
    json_object_set_new(flags, "if_", json_boolean((efl & 512) != 0));
    json_object_set_new(flags, "df", json_boolean((efl & 1024) != 0));
    json_object_set_new(flags, "of", json_boolean((efl & 2048) != 0));
    json_object_set_new(regs, "flags", flags);

    *out_resp = build_value_response(id, regs);
}

static void handle_set_register(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    if(!json_is_string(json_object_get(params, "name")) ||
       !json_is_string(json_object_get(params, "value")))
    {
        *out_resp = build_error_response(id, "set_register requires name (string) and value (string)");
        return;
    }
    const char* name = json_string_value(json_object_get(params, "name"));
    duint value = DbgValFromString(json_string_value(json_object_get(params, "value")));

    char expr[256];
    snprintf(expr, sizeof(expr), "%s=%llX", name, (unsigned long long)value);
    bool ok = DbgCmdExecDirect(expr);

    json_t* data = json_object();
    json_object_set_new(data, "ok", json_boolean(ok));
    *out_resp = build_value_response(id, data);
}

static void handle_get_breakpoints(json_t* req, json_t* params, json_t** out_resp)
{
    (void)params;
    const char* id = json_string_value(json_object_get(req, "id"));

    json_t* bps = json_array();

    BPMAP bpMap = {0};
    int count = DbgGetBpList(bp_none, &bpMap);
    if(count > 0 && bpMap.bp)
    {
        for(int i = 0; i < count; i++)
        {
            json_t* bp = json_object();
            json_object_set_new(bp, "address", addr_json(bpMap.bp[i].addr));
            json_object_set_new(bp, "enabled", json_boolean(bpMap.bp[i].enabled));
            json_object_set_new(bp, "active", json_boolean(bpMap.bp[i].active));
            json_object_set_new(bp, "singleshoot", json_boolean(bpMap.bp[i].singleshoot));
            json_object_set_new(bp, "name", json_string(bpMap.bp[i].name));
            json_object_set_new(bp, "module", json_string(bpMap.bp[i].mod));
            json_object_set_new(bp, "slot", addr_json(bpMap.bp[i].slot));
            json_object_set_new(bp, "type_ex", addr_json(bpMap.bp[i].typeEx));
            json_object_set_new(bp, "hw_size", addr_json(bpMap.bp[i].hwSize));
            json_object_set_new(bp, "hit_count", addr_json(bpMap.bp[i].hitCount));
            json_object_set_new(bp, "fast_resume", json_boolean(bpMap.bp[i].fastResume));
            json_object_set_new(bp, "silent", json_boolean(bpMap.bp[i].silent));
            json_object_set_new(bp, "break_condition", json_string(bpMap.bp[i].breakCondition));
            json_object_set_new(bp, "log_text", json_string(bpMap.bp[i].logText));
            json_object_set_new(bp, "log_condition", json_string(bpMap.bp[i].logCondition));
            json_object_set_new(bp, "command_text", json_string(bpMap.bp[i].commandText));
            json_object_set_new(bp, "command_condition", json_string(bpMap.bp[i].commandCondition));

            const char* type_str = "unknown";
            switch(bpMap.bp[i].type)
            {
            case bp_normal:    type_str = "normal"; break;
            case bp_hardware:  type_str = "hardware"; break;
            case bp_memory:    type_str = "memory"; break;
            case bp_dll:       type_str = "dll"; break;
            case bp_exception: type_str = "exception"; break;
            }
            json_object_set_new(bp, "type", json_string(type_str));
            json_array_append_new(bps, bp);
        }
        BridgeFree(bpMap.bp);
    }

    *out_resp = build_value_response(id, bps);
}

static void handle_set_breakpoint(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr))
    {
        *out_resp = build_error_response(id, "set_breakpoint requires addr (hex string)");
        return;
    }
    const char* type_str = json_string_value(json_object_get(params, "type"));
    if(!type_str) type_str = "normal";

    bool ok = false;
    if(strcmp(type_str, "hardware") == 0)
    {
        const char* hwType = json_string_value(json_object_get(params, "hw_type"));
        const char* hwSize = json_string_value(json_object_get(params, "hw_size"));
        if(!hwType) hwType = "execute";
        if(!hwSize) hwSize = "dword";

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "bphws %llX, %s, %s",
            (unsigned long long)addr, hwType, hwSize);
        ok = DbgCmdExecDirect(cmd);
    }
    else if(strcmp(type_str, "memory") == 0)
    {
        ok = DbgCmdExecDirect("SetMemoryBreakpoint");
    }
    else
    {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "bp %llX", (unsigned long long)addr);
        ok = DbgCmdExecDirect(cmd);
    }

    json_t* data = json_object();
    json_object_set_new(data, "ok", json_boolean(ok));
    *out_resp = build_value_response(id, data);
}

static void handle_delete_breakpoint(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr))
    {
        *out_resp = build_error_response(id, "delete_breakpoint requires addr (hex string)");
        return;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "bc %llX", (unsigned long long)addr);
    bool ok = DbgCmdExecDirect(cmd);

    json_t* data = json_object();
    json_object_set_new(data, "ok", json_boolean(ok));
    *out_resp = build_value_response(id, data);
}

static void handle_toggle_breakpoint(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr))
    {
        *out_resp = build_error_response(id, "toggle_breakpoint requires addr (hex string)");
        return;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "bptoggle %llX", (unsigned long long)addr);
    bool ok = DbgCmdExecDirect(cmd);

    json_t* data = json_object();
    json_object_set_new(data, "ok", json_boolean(ok));
    *out_resp = build_value_response(id, data);
}

static void handle_get_debug_state(json_t* req, json_t* params, json_t** out_resp)
{
    (void)params;
    const char* id = json_string_value(json_object_get(req, "id"));

    json_t* data = json_object();
    json_object_set_new(data, "state", json_string(get_debug_state_string()));
    *out_resp = build_value_response(id, data);
}

static void handle_run(json_t* req, json_t* params, json_t** out_resp)
{
    (void)params;
    const char* id = json_string_value(json_object_get(req, "id"));
    DbgCmdExecDirect("run");
    json_t* data = json_object();
    json_object_set_new(data, "ok", json_true());
    *out_resp = build_value_response(id, data);
}

static void handle_pause(json_t* req, json_t* params, json_t** out_resp)
{
    (void)params;
    const char* id = json_string_value(json_object_get(req, "id"));

    json_t* data = json_object();
    const char* before = get_debug_state_string();

    if(strcmp(before, "stopped") == 0)
    {
        json_object_set_new(data, "ok", json_false());
        json_object_set_new(data, "requested", json_false());
        json_object_set_new(data, "state", json_string(before));
        json_object_set_new(data, "error", json_string("Debugger is not active"));
        *out_resp = build_value_response(id, data);
        return;
    }

    if(strcmp(before, "paused") == 0)
    {
        json_object_set_new(data, "ok", json_true());
        json_object_set_new(data, "requested", json_false());
        json_object_set_new(data, "state", json_string(before));
        *out_resp = build_value_response(id, data);
        return;
    }

    bool commandOk = DbgCmdExec("pause");
    bool paused = wait_for_debug_state("paused", 3000);
    const char* after = get_debug_state_string();

    json_object_set_new(data, "ok", json_boolean(paused));
    json_object_set_new(data, "requested", json_boolean(commandOk));
    json_object_set_new(data, "state", json_string(after));
    if(!paused)
        json_object_set_new(data, "error", json_string(commandOk ? "Timed out waiting for pause" : "Pause command failed"));
    *out_resp = build_value_response(id, data);
}

static void handle_stop(json_t* req, json_t* params, json_t** out_resp)
{
    (void)params;
    const char* id = json_string_value(json_object_get(req, "id"));
    DbgCmdExecDirect("StopDebug");
    json_t* data = json_object();
    json_object_set_new(data, "ok", json_true());
    *out_resp = build_value_response(id, data);
}

static void handle_step_in(json_t* req, json_t* params, json_t** out_resp)
{
    (void)params;
    const char* id = json_string_value(json_object_get(req, "id"));
    DbgCmdExecDirect("StepInto");
    json_t* data = json_object();
    json_object_set_new(data, "ok", json_true());
    *out_resp = build_value_response(id, data);
}

static void handle_step_over(json_t* req, json_t* params, json_t** out_resp)
{
    (void)params;
    const char* id = json_string_value(json_object_get(req, "id"));
    DbgCmdExecDirect("StepOver");
    json_t* data = json_object();
    json_object_set_new(data, "ok", json_true());
    *out_resp = build_value_response(id, data);
}

static void handle_step_out(json_t* req, json_t* params, json_t** out_resp)
{
    (void)params;
    const char* id = json_string_value(json_object_get(req, "id"));
    DbgCmdExecDirect("StepOut");
    json_t* data = json_object();
    json_object_set_new(data, "ok", json_true());
    *out_resp = build_value_response(id, data);
}

static void handle_get_modules(json_t* req, json_t* params, json_t** out_resp)
{
    (void)params;
    const char* id = json_string_value(json_object_get(req, "id"));

    json_t* mods = json_array();
    MEMMAP mm = {0};

    if(DbgMemMap(&mm))
    {
        duint lastBase = 0;
        for(int i = 0; i < mm.count; i++)
        {
            duint allocBase = (duint)mm.page[i].mbi.AllocationBase;
            if(mm.page[i].mbi.Type == MEM_IMAGE && allocBase != lastBase)
            {
                lastBase = allocBase;
                char modName[MAX_MODULE_SIZE] = {0};
                DbgFunctions()->ModNameFromAddr(allocBase, modName, true);

                json_t* mod = json_object();
                json_object_set_new(mod, "base", addr_json(allocBase));
                json_object_set_new(mod, "size", addr_json((duint)mm.page[i].mbi.RegionSize));
                json_object_set_new(mod, "name", json_string(modName));
                json_array_append_new(mods, mod);
            }
        }
        BridgeFree(mm.page);
    }

    json_t* data = json_object();
    json_object_set_new(data, "modules", mods);
    *out_resp = build_value_response(id, data);
}

static void handle_get_module_info(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    const char* modname = NULL;

    if(json_is_string(json_object_get(params, "addr")))
        get_addr_param(params, "addr", &addr);
    else if(json_is_string(json_object_get(params, "name")))
        modname = json_string_value(json_object_get(params, "name"));
    else
    {
        *out_resp = build_error_response(id, "get_module_info requires addr (hex string) or name (string)");
        return;
    }

    json_t* data = json_object();
    duint base = modname ? DbgModBaseFromName(modname) : addr;
    if(base)
    {
        char name[MAX_MODULE_SIZE] = {0};
        char path[MAX_PATH] = {0};
        DbgFunctions()->ModNameFromAddr(base, name, true);
        DbgFunctions()->ModPathFromAddr(base, path, MAX_PATH);
        json_object_set_new(data, "base", addr_json(base));
        json_object_set_new(data, "name", json_string(name));
        json_object_set_new(data, "path", json_string(path));

        duint size = DbgFunctions()->ModSizeFromAddr(base);
        json_object_set_new(data, "size", addr_json(size));
    }

    *out_resp = build_value_response(id, data);
}

static void handle_get_symbols(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint base = 0;
    if(!get_addr_param(params, "module_base", &base))
    {
        *out_resp = build_error_response(id, "get_symbols requires module_base (hex string)");
        return;
    }

    struct symbol_context
    {
        json_t* symbols;
    } ctx = { json_array() };

    DbgSymbolEnum(base, [](const SYMBOLPTR* sym, void* user) -> bool {
        struct symbol_context* c = (struct symbol_context*)user;
        SYMBOLINFO info = {0};
        DbgGetSymbolInfo(sym, &info);

        json_t* s = json_object();
        json_object_set_new(s, "address", addr_json(info.addr));
        if(info.decoratedSymbol)
            json_object_set_new(s, "decorated", json_string(info.decoratedSymbol));
        if(info.undecoratedSymbol)
            json_object_set_new(s, "undecorated", json_string(info.undecoratedSymbol));

        const char* symtype = "symbol";
        switch(info.type)
        {
        case sym_import: symtype = "import"; break;
        case sym_export: symtype = "export"; break;
        case sym_symbol: symtype = "symbol"; break;
        }
        json_object_set_new(s, "type", json_string(symtype));

        if(info.freeDecorated) BridgeFree(info.decoratedSymbol);
        if(info.freeUndecorated) BridgeFree(info.undecoratedSymbol);

        json_array_append_new(c->symbols, s);
        return true;
    }, &ctx);

    json_t* data = json_object();
    json_object_set_new(data, "module_base", addr_json(base));
    json_object_set_new(data, "symbols", ctx.symbols);
    *out_resp = build_value_response(id, data);
}

static void handle_evaluate(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    if(!json_is_string(json_object_get(params, "expression")))
    {
        *out_resp = build_error_response(id, "evaluate requires expression (string)");
        return;
    }
    const char* expr = json_string_value(json_object_get(params, "expression"));

    bool success = false;
    duint value = DbgEval(expr, &success);

    json_t* data = json_object();
    json_object_set_new(data, "value", addr_json(value));
    json_object_set_new(data, "success", json_boolean(success));
    *out_resp = build_value_response(id, data);
}

static void handle_get_memory_map(json_t* req, json_t* params, json_t** out_resp)
{
    (void)params;
    const char* id = json_string_value(json_object_get(req, "id"));

    MEMMAP mm = {0};
    if(!DbgMemMap(&mm))
    {
        *out_resp = build_error_response(id, "Failed to get memory map");
        return;
    }

    json_t* pages = json_array();
    for(int i = 0; i < mm.count; i++)
    {
        json_t* page = json_object();
        json_object_set_new(page, "base", addr_json((duint)mm.page[i].mbi.BaseAddress));
        json_object_set_new(page, "size", addr_json((duint)mm.page[i].mbi.RegionSize));
        json_object_set_new(page, "state", addr_json(mm.page[i].mbi.State));
        json_object_set_new(page, "protect", addr_json(mm.page[i].mbi.Protect));
        json_object_set_new(page, "type", addr_json(mm.page[i].mbi.Type));
        json_object_set_new(page, "info", json_string(mm.page[i].info));
        json_array_append_new(pages, page);
    }
    BridgeFree(mm.page);

    json_t* data = json_object();
    json_object_set_new(data, "pages", pages);
    *out_resp = build_value_response(id, data);
}

static json_t* describe_stack_address(duint addr)
{
    json_t* details = json_object();
    json_object_set_new(details, "address", addr_json(addr));

    if(!addr)
    {
        json_object_set_new(details, "display", json_string(""));
        return details;
    }

    const DBGFUNCTIONS* funcs = DbgFunctions();
    duint base = funcs && funcs->ModBaseFromAddr ? funcs->ModBaseFromAddr(addr) : 0;
    char module[MAX_MODULE_SIZE] = {0};
    char label[MAX_LABEL_SIZE] = {0};
    char comment[MAX_COMMENT_SIZE] = {0};

    if(base && funcs && funcs->ModNameFromAddr)
    {
        funcs->ModNameFromAddr(addr, module, true);
        json_object_set_new(details, "module", json_string(module));
        json_object_set_new(details, "module_base", addr_json(base));
        json_object_set_new(details, "rva", addr_json(addr - base));
    }

    if(DbgGetLabelAt(addr, SEG_DEFAULT, label) && label[0])
        json_object_set_new(details, "label", json_string(label));
    if(DbgGetCommentAt(addr, comment) && comment[0])
        json_object_set_new(details, "comment", json_string(comment));

    char display[512] = {0};
    if(module[0] && label[0])
        snprintf(display, sizeof(display), "%s.%s", module, label);
    else if(module[0] && base)
        snprintf(display, sizeof(display), "%s+0x%llX", module, (unsigned long long)(addr - base));
    else if(label[0])
        snprintf(display, sizeof(display), "%s", label);
    else
        snprintf(display, sizeof(display), "0x%llX", (unsigned long long)addr);
    json_object_set_new(details, "display", json_string(display));

    return details;
}

static void handle_get_call_stack(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint stackWords = 4;
    get_int_param(params, "stack_words", 4, &stackWords);
    if(stackWords > 16)
        stackWords = 16;

    DBGCALLSTACK cs = {0};
    DbgFunctions()->GetCallStack(&cs);

    json_t* frames = json_array();
    for(int i = 0; i < cs.total; i++)
    {
        json_t* frame = json_object();
        json_object_set_new(frame, "addr", addr_json(cs.entries[i].addr));
        json_object_set_new(frame, "from", addr_json(cs.entries[i].from));
        json_object_set_new(frame, "to", addr_json(cs.entries[i].to));
        if(cs.entries[i].comment[0])
            json_object_set_new(frame, "comment", json_string(cs.entries[i].comment));

        json_object_set_new(frame, "index", json_integer(i));
        json_object_set_new(frame, "current", json_boolean(i == 0));
        json_object_set_new(frame, "stack_addr", addr_json(cs.entries[i].addr));
        json_object_set_new(frame, "return_to", addr_json(cs.entries[i].to));
        json_object_set_new(frame, "from_details", describe_stack_address(cs.entries[i].from));
        json_object_set_new(frame, "to_details", describe_stack_address(cs.entries[i].to));
        if(i + 1 < cs.total && cs.entries[i + 1].addr > cs.entries[i].addr)
        {
            json_object_set_new(frame, "next_stack_addr", addr_json(cs.entries[i + 1].addr));
            json_object_set_new(frame, "frame_size", addr_json(cs.entries[i + 1].addr - cs.entries[i].addr));
        }

        json_t* stack = json_array();
        for(duint word = 0; word < stackWords; word++)
        {
            duint stackAddr = cs.entries[i].addr + word * sizeof(duint);
            duint value = 0;
            bool ok = DbgMemRead(stackAddr, &value, sizeof(value));
            json_t* item = json_object();
            json_object_set_new(item, "addr", addr_json(stackAddr));
            json_object_set_new(item, "value", addr_json(value));
            json_object_set_new(item, "ok", json_boolean(ok));
            if(ok)
                json_object_set_new(item, "details", describe_stack_address(value));
            json_array_append_new(stack, item);
        }
        json_object_set_new(frame, "stack_words", stack);

        json_array_append_new(frames, frame);
    }
    if(cs.entries) BridgeFree(cs.entries);

    json_t* data = json_object();
    json_object_set_new(data, "total", json_integer(cs.total));
    json_object_set_new(data, "stack_words", addr_json(stackWords));
    json_object_set_new(data, "callstack", frames);
    *out_resp = build_value_response(id, data);
}

static void handle_get_label(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr))
    {
        *out_resp = build_error_response(id, "get_label requires addr (hex string)");
        return;
    }

    char label[MAX_LABEL_SIZE] = {0};
    bool ok = DbgGetLabelAt(addr, SEG_DEFAULT, label);

    json_t* data = json_object();
    json_object_set_new(data, "addr", addr_json(addr));
    json_object_set_new(data, "label", json_string(label));
    json_object_set_new(data, "ok", json_boolean(ok));
    *out_resp = build_value_response(id, data);
}

static void handle_set_label(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr) ||
       !json_is_string(json_object_get(params, "label")))
    {
        *out_resp = build_error_response(id, "set_label requires addr (hex string) and label (string)");
        return;
    }
    const char* label = json_string_value(json_object_get(params, "label"));

    bool ok = DbgSetLabelAt(addr, label);

    json_t* data = json_object();
    json_object_set_new(data, "ok", json_boolean(ok));
    *out_resp = build_value_response(id, data);
}

static void handle_get_comment(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr))
    {
        *out_resp = build_error_response(id, "get_comment requires addr (hex string)");
        return;
    }

    char comment[MAX_COMMENT_SIZE] = {0};
    bool ok = DbgGetCommentAt(addr, comment);

    json_t* data = json_object();
    json_object_set_new(data, "addr", addr_json(addr));
    json_object_set_new(data, "comment", json_string(comment));
    json_object_set_new(data, "ok", json_boolean(ok));
    *out_resp = build_value_response(id, data);
}

static void handle_set_comment(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr) ||
       !json_is_string(json_object_get(params, "comment")))
    {
        *out_resp = build_error_response(id, "set_comment requires addr (hex string) and comment (string)");
        return;
    }
    const char* comment = json_string_value(json_object_get(params, "comment"));

    bool ok = DbgSetCommentAt(addr, comment);

    json_t* data = json_object();
    json_object_set_new(data, "ok", json_boolean(ok));
    *out_resp = build_value_response(id, data);
}

static void handle_assemble(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr) ||
       !json_is_string(json_object_get(params, "instruction")))
    {
        *out_resp = build_error_response(id, "assemble requires addr (hex string) and instruction (string)");
        return;
    }
    const char* instruction = json_string_value(json_object_get(params, "instruction"));

    char error[MAX_ERROR_SIZE] = {0};
    bool ok = DbgFunctions()->AssembleAtEx(addr, instruction, error, true);

    json_t* data = json_object();
    json_object_set_new(data, "addr", addr_json(addr));
    json_object_set_new(data, "instruction", json_string(instruction));
    json_object_set_new(data, "ok", json_boolean(ok));
    if(!ok && error[0])
        json_object_set_new(data, "error", json_string(error));
    *out_resp = build_value_response(id, data);
}

static void handle_run_to(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr))
    {
        *out_resp = build_error_response(id, "run_to requires addr (hex string)");
        return;
    }
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "bpcswx %llX", (unsigned long long)addr);
    DbgCmdExecDirect(cmd);           // set one-shot silent temp BP
    DbgCmdExecDirect("run");
    json_t* data = json_object();
    json_object_set_new(data, "ok", json_true());
    *out_resp = build_value_response(id, data);
}

static void handle_set_eip(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr))
    {
        *out_resp = build_error_response(id, "set_eip requires addr (hex string)");
        return;
    }
    char cmd[256];
#ifdef _WIN64
    snprintf(cmd, sizeof(cmd), "rip=%llX", (unsigned long long)addr);
#else
    snprintf(cmd, sizeof(cmd), "eip=%llX", (unsigned long long)addr);
#endif
    bool ok = DbgCmdExecDirect(cmd);
    json_t* data = json_object();
    json_object_set_new(data, "ok", json_boolean(ok));
    *out_resp = build_value_response(id, data);
}

static void handle_get_threads(json_t* req, json_t* params, json_t** out_resp)
{
    (void)params;
    const char* id = json_string_value(json_object_get(req, "id"));

    THREADLIST tl = {0};
    DbgGetThreadList(&tl);

    json_t* threads = json_array();
    for(int i = 0; i < tl.count; i++)
    {
        json_t* t = json_object();
        json_object_set_new(t, "number", addr_json(tl.list[i].BasicInfo.ThreadNumber));
        json_object_set_new(t, "thread_id", addr_json(tl.list[i].BasicInfo.ThreadId));
        json_object_set_new(t, "handle", addr_json((duint)tl.list[i].BasicInfo.Handle));
        json_object_set_new(t, "start_addr", addr_json(tl.list[i].BasicInfo.ThreadStartAddress));
        json_object_set_new(t, "local_base", addr_json(tl.list[i].BasicInfo.ThreadLocalBase));
        json_object_set_new(t, "name", json_string(tl.list[i].BasicInfo.threadName));
        json_object_set_new(t, "cip", addr_json(tl.list[i].ThreadCip));
        json_object_set_new(t, "suspend_count", addr_json(tl.list[i].SuspendCount));
        json_object_set_new(t, "priority", addr_json(tl.list[i].Priority));
        json_object_set_new(t, "wait_reason", addr_json(tl.list[i].WaitReason));
        json_array_append_new(threads, t);
    }
    if(tl.list) BridgeFree(tl.list);

    json_t* data = json_object();
    json_object_set_new(data, "threads", threads);
    json_object_set_new(data, "current_thread", addr_json(tl.CurrentThread));
    *out_resp = build_value_response(id, data);
}

static void handle_get_breakpoint_condition(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr))
    {
        *out_resp = build_error_response(id, "get_breakpoint_condition requires addr");
        return;
    }

    BPXTYPE requestedType = bp_none;
    char error[256] = {0};
    if(!get_bp_type_param(params, &requestedType, error, sizeof(error)))
    {
        *out_resp = build_error_response(id, error);
        return;
    }

    char condition[MAX_CONDITIONAL_EXPR_SIZE] = {0};
    BPXTYPE actualType = bp_none;
    if(!read_break_condition(addr, requestedType, condition, sizeof(condition), &actualType))
    {
        *out_resp = build_error_response(id, "breakpoint not found at address");
        return;
    }

    json_t* data = json_object();
    json_object_set_new(data, "ok", json_true());
    json_object_set_new(data, "addr", addr_json(addr));
    json_object_set_new(data, "type", json_string(bp_type_to_string(actualType)));
    json_object_set_new(data, "condition", json_string(condition));
    json_object_set_new(data, "has_condition", json_boolean(condition[0] != '\0'));
    *out_resp = build_value_response(id, data);
}

static void handle_set_breakpoint_condition(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr))
    {
        *out_resp = build_error_response(id, "set_breakpoint_condition requires addr");
        return;
    }

    BPXTYPE requestedType = bp_none;
    char error[256] = {0};
    if(!get_bp_type_param(params, &requestedType, error, sizeof(error)))
    {
        *out_resp = build_error_response(id, error);
        return;
    }

    char condition[MAX_CONDITIONAL_EXPR_SIZE] = {0};
    if(!build_break_condition(params, condition, sizeof(condition), error, sizeof(error)))
    {
        *out_resp = build_error_response(id, error);
        return;
    }

    char previous[MAX_CONDITIONAL_EXPR_SIZE] = {0};
    BPXTYPE actualType = bp_none;
    if(!read_break_condition(addr, requestedType, previous, sizeof(previous), &actualType))
    {
        *out_resp = build_error_response(id, "breakpoint not found at address");
        return;
    }

    if(!write_break_condition(addr, actualType, condition, &actualType, error, sizeof(error)))
    {
        *out_resp = build_error_response(id, error);
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "bpcnd %llX,%s", (unsigned long long)addr, condition);
    log_msg("[BP Condition] Set %s breakpoint condition on %llX -> %s",
        bp_type_to_string(actualType), (unsigned long long)addr, condition);

    json_t* data = json_object();
    json_object_set_new(data, "ok", json_true());
    json_object_set_new(data, "addr", addr_json(addr));
    json_object_set_new(data, "type", json_string(bp_type_to_string(actualType)));
    json_object_set_new(data, "condition", json_string(condition));
    json_object_set_new(data, "previous_condition", json_string(previous));
    json_object_set_new(data, "has_condition", json_true());
    const char* responseOp = "";
    if(json_object_get(params, "conditions"))
    {
        const char* joiner = NULL;
        if(get_condition_joiner(params, &joiner, &responseOp, error, sizeof(error)))
            (void)joiner;
        else
            responseOp = "";
    }
    json_object_set_new(data, "op", json_string(responseOp));
    json_object_set_new(data, "command", json_string(cmd));
    *out_resp = build_value_response(id, data);
}

static void handle_append_breakpoint_condition(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr))
    {
        *out_resp = build_error_response(id, "append_breakpoint_condition requires addr");
        return;
    }

    BPXTYPE requestedType = bp_none;
    char error[256] = {0};
    if(!get_bp_type_param(params, &requestedType, error, sizeof(error)))
    {
        *out_resp = build_error_response(id, error);
        return;
    }

    char appended[MAX_CONDITIONAL_EXPR_SIZE] = {0};
    if(!build_break_condition(params, appended, sizeof(appended), error, sizeof(error)))
    {
        *out_resp = build_error_response(id, error);
        return;
    }

    char previous[MAX_CONDITIONAL_EXPR_SIZE] = {0};
    BPXTYPE actualType = bp_none;
    if(!read_break_condition(addr, requestedType, previous, sizeof(previous), &actualType))
    {
        *out_resp = build_error_response(id, "breakpoint not found at address");
        return;
    }

    char condition[MAX_CONDITIONAL_EXPR_SIZE] = {0};
    const char* responseOp = "and";
    if(!combine_break_conditions(previous, appended, params, condition, sizeof(condition), &responseOp, error, sizeof(error)))
    {
        *out_resp = build_error_response(id, error);
        return;
    }

    if(!write_break_condition(addr, actualType, condition, &actualType, error, sizeof(error)))
    {
        *out_resp = build_error_response(id, error);
        return;
    }

    log_msg("[BP Condition] Append %s breakpoint condition on %llX -> %s",
        bp_type_to_string(actualType), (unsigned long long)addr, condition);

    json_t* data = json_object();
    json_object_set_new(data, "ok", json_true());
    json_object_set_new(data, "addr", addr_json(addr));
    json_object_set_new(data, "type", json_string(bp_type_to_string(actualType)));
    json_object_set_new(data, "condition", json_string(condition));
    json_object_set_new(data, "previous_condition", json_string(previous));
    json_object_set_new(data, "appended_condition", json_string(appended));
    json_object_set_new(data, "has_condition", json_boolean(condition[0] != '\0'));
    json_object_set_new(data, "op", json_string(responseOp ? responseOp : ""));
    *out_resp = build_value_response(id, data);
}

static void handle_clear_breakpoint_condition(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr))
    {
        *out_resp = build_error_response(id, "clear_breakpoint_condition requires addr");
        return;
    }

    BPXTYPE requestedType = bp_none;
    char error[256] = {0};
    if(!get_bp_type_param(params, &requestedType, error, sizeof(error)))
    {
        *out_resp = build_error_response(id, error);
        return;
    }

    char previous[MAX_CONDITIONAL_EXPR_SIZE] = {0};
    BPXTYPE actualType = bp_none;
    if(!read_break_condition(addr, requestedType, previous, sizeof(previous), &actualType))
    {
        *out_resp = build_error_response(id, "breakpoint not found at address");
        return;
    }

    if(!write_break_condition(addr, actualType, "", &actualType, error, sizeof(error)))
    {
        *out_resp = build_error_response(id, error);
        return;
    }

    log_msg("[BP Condition] Clear %s breakpoint condition on %llX",
        bp_type_to_string(actualType), (unsigned long long)addr);

    json_t* data = json_object();
    json_object_set_new(data, "ok", json_true());
    json_object_set_new(data, "addr", addr_json(addr));
    json_object_set_new(data, "type", json_string(bp_type_to_string(actualType)));
    json_object_set_new(data, "condition", json_string(""));
    json_object_set_new(data, "previous_condition", json_string(previous));
    json_object_set_new(data, "has_condition", json_false());
    *out_resp = build_value_response(id, data);
}

static void handle_set_bp_filter(json_t* req, json_t* params, json_t** out_resp)
{
    handle_set_breakpoint_condition(req, params, out_resp);
}

static void handle_find_bytes(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    if(!json_is_string(json_object_get(params, "pattern")))
    {
        *out_resp = build_error_response(id, "find_bytes requires pattern (hex string like '48 8D 15')");
        return;
    }
    const char* hexPattern = json_string_value(json_object_get(params, "pattern"));

    // Decode hex pattern
    size_t hexLen = strlen(hexPattern);
    unsigned char* pat = (unsigned char*)BridgeAlloc(hexLen / 2 + 1);
    size_t patLen = hex_decode(hexPattern, pat);

    json_t* results = json_array();
    MEMMAP mm = {0};

    if(DbgMemMap(&mm))
    {
        for(int i = 0; i < mm.count; i++)
        {
            if(mm.page[i].mbi.State != MEM_COMMIT) continue;
            if(mm.page[i].mbi.Protect & PAGE_NOACCESS) continue;
            if(mm.page[i].mbi.Protect & PAGE_GUARD) continue;

            duint pageBase = (duint)mm.page[i].mbi.BaseAddress;
            duint pageSize = (duint)mm.page[i].mbi.RegionSize;
            if(pageSize > 1024 * 1024) pageSize = 1024 * 1024;

            unsigned char* pageBuf = (unsigned char*)BridgeAlloc(pageSize);
            if(!pageBuf) continue;

            if(DbgMemRead(pageBase, pageBuf, pageSize))
            {
                for(duint off = 0; off + patLen <= pageSize; off++)
                {
                    if(memcmp(pageBuf + off, pat, patLen) == 0)
                    {
                        json_t* r = json_object();
                        json_object_set_new(r, "addr", addr_json(pageBase + off));
                        json_object_set_new(r, "module", json_string(mm.page[i].info));
                        json_array_append_new(results, r);
                        off += patLen - 1; // skip past match
                        if(json_array_size(results) >= 50) break;
                    }
                }
            }
            BridgeFree(pageBuf);
            if(json_array_size(results) >= 50) break;
        }
        BridgeFree(mm.page);
    }
    BridgeFree(pat);

    json_t* data = json_object();
    json_object_set_new(data, "matches", results);
    *out_resp = build_value_response(id, data);
}

static void handle_get_function_info(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr))
    {
        *out_resp = build_error_response(id, "get_function_info requires addr (hex string)");
        return;
    }

    duint start = 0, end = 0;
    bool ok = DbgFunctionGet(addr, &start, &end);

    json_t* data = json_object();
    json_object_set_new(data, "ok", json_boolean(ok));
    if(ok)
    {
        json_object_set_new(data, "start", addr_json(start));
        json_object_set_new(data, "end", addr_json(end));
        json_object_set_new(data, "size", addr_json(end - start));
    }
    *out_resp = build_value_response(id, data);
}

static void handle_get_xrefs(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr))
    {
        *out_resp = build_error_response(id, "get_xrefs requires addr (hex string)");
        return;
    }

    XREF_INFO xrefInfo = {0};
    bool ok = DbgXrefGet(addr, &xrefInfo);

    json_t* xrefs = json_array();
    if(ok && xrefInfo.references)
    {
        for(duint i = 0; i < xrefInfo.refcount; i++)
        {
            json_t* xr = json_object();
            json_object_set_new(xr, "addr", addr_json(xrefInfo.references[i].addr));
            const char* typeStr = "unknown";
            switch(xrefInfo.references[i].type)
            {
            case XREF_DATA: typeStr = "data"; break;
            case XREF_JMP:  typeStr = "jump"; break;
            case XREF_CALL: typeStr = "call"; break;
            }
            json_object_set_new(xr, "type", json_string(typeStr));
            json_array_append_new(xrefs, xr);
        }
        BridgeFree(xrefInfo.references);
    }

    json_t* data = json_object();
    json_object_set_new(data, "addr", addr_json(addr));
    json_object_set_new(data, "count", addr_json(xrefInfo.refcount));
    json_object_set_new(data, "xrefs", xrefs);
    *out_resp = build_value_response(id, data);
}

static void handle_get_string(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    if(!get_addr_param(params, "addr", &addr))
    {
        *out_resp = build_error_response(id, "get_string requires addr (hex string)");
        return;
    }

    // Read raw memory
    unsigned char buf[1024] = {0};
    if(!DbgMemRead(addr, buf, sizeof(buf) - 1))
    {
        *out_resp = build_error_response(id, "Failed to read memory at address");
        return;
    }

    json_t* data = json_object();
    json_object_set_new(data, "addr", addr_json(addr));

    char* hex = (char*)BridgeAlloc(sizeof(buf) * 2 + 1);
    hex_encode(buf, sizeof(buf), hex);
    json_object_set_new(data, "hex", json_string(hex));
    BridgeFree(hex);

    *out_resp = build_value_response(id, data);
}

static char* normalize_string(const char* s)
{
    size_t len = strlen(s);
    char* out = (char*)BridgeAlloc(len + 1);
    size_t j = 0;
    for(size_t i = 0; i < len; i++)
    {
        char c = s[i];
        if(c == ' ' || c == ',' || c == '!' || c == '.' || c == '?' ||
           c == ';' || c == ':' || c == '\'' || c == '"' || c == '\t' ||
           c == '\n' || c == '\r')
            continue;
        if(c >= 'A' && c <= 'Z')
            c = (char)(c + 32);
        out[j++] = c;
    }
    out[j] = '\0';
    return out;
}

static void handle_find_string(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    if(!json_is_string(json_object_get(params, "pattern")))
    {
        *out_resp = build_error_response(id, "find_string requires pattern (string)");
        return;
    }
    const char* pattern = json_string_value(json_object_get(params, "pattern"));
    char* normPattern = normalize_string(pattern);
    size_t patLen = strlen(normPattern);

    json_t* results = json_array();
    MEMMAP mm = {0};

    if(DbgMemMap(&mm))
    {
        for(int i = 0; i < mm.count; i++)
        {
            // Only search readable committed memory
            if(mm.page[i].mbi.State != MEM_COMMIT) continue;
            if(mm.page[i].mbi.Protect & PAGE_NOACCESS) continue;
            if(mm.page[i].mbi.Protect & PAGE_GUARD) continue;

            duint pageBase = (duint)mm.page[i].mbi.BaseAddress;
            duint pageSize = (duint)mm.page[i].mbi.RegionSize;
            if(pageSize > 1024 * 1024) pageSize = 1024 * 1024; // limit per page

            unsigned char* pageBuf = (unsigned char*)BridgeAlloc(pageSize);
            if(!pageBuf) continue;

            if(DbgMemRead(pageBase, pageBuf, pageSize))
            {
                for(duint off = 0; off + patLen < pageSize; off++)
                {
                    // Try to match at this offset - convert potential string to normalized form
                    char candidate[256] = {0};
                    size_t candLen = 0;
                    for(size_t k = 0; k < sizeof(candidate) - 1 && (off + k) < pageSize; k++)
                    {
                        unsigned char b = pageBuf[off + k];
                        if(b == 0) break;
                        if(b < 0x20 || (b >= 0x7F && b < 0x80)) break;
                        if(b >= 'A' && b <= 'Z') b = (unsigned char)(b + 32);
                        candidate[k] = (char)b;
                        candLen = k + 1;
                    }

                    if(candLen >= patLen && memcmp(candidate, normPattern, patLen) == 0)
                    {
                        // Found - read original string
                        char origStr[512] = {0};
                        size_t origLen = 0;
                        for(size_t k = 0; k < sizeof(origStr) - 1 && (off + k) < pageSize; k++)
                        {
                            if(pageBuf[off + k] == 0) break;
                            origStr[k] = (char)pageBuf[off + k];
                            origLen = k + 1;
                        }
                        origStr[origLen] = '\0';

                        json_t* r = json_object();
                        json_object_set_new(r, "addr", addr_json(pageBase + off));
                        json_object_set_new(r, "string", json_string(origStr));
                        json_object_set_new(r, "module", json_string(mm.page[i].info));
                        json_array_append_new(results, r);

                        off += patLen; // skip past this match
                        if(json_array_size(results) >= 50) break; // limit
                    }
                }
            }
            BridgeFree(pageBuf);
            if(json_array_size(results) >= 50) break;
        }
        BridgeFree(mm.page);
    }

    BridgeFree(normPattern);

    json_t* data = json_object();
    json_object_set_new(data, "pattern", json_string(pattern));
    json_object_set_new(data, "matches", results);
    *out_resp = build_value_response(id, data);
}

static void handle_cmd_exec(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    if(!json_is_string(json_object_get(params, "command")))
    {
        *out_resp = build_error_response(id, "cmd_exec requires command (string)");
        return;
    }
    const char* command = json_string_value(json_object_get(params, "command"));

    bool ok = DbgCmdExecDirect(command);

    json_t* data = json_object();
    json_object_set_new(data, "command", json_string(command));
    json_object_set_new(data, "ok", json_boolean(ok));
    *out_resp = build_value_response(id, data);
}

typedef void (*cmd_handler)(json_t* req, json_t* params, json_t** out_resp);

struct handler_entry
{
    const char* method;
    cmd_handler handler;
};

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
};

static cmd_handler get_handler(const char* method)
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

static void process_request(json_t* req, char* out_buf, size_t out_buf_size)
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

static void get_target_hint(char* out, size_t outSize)
{
    out[0] = '\0';
    if(!DbgIsDebugging())
        return;

    duint cip = DbgValFromString("cip");
    char module[MAX_MODULE_SIZE] = {0};
    char path[MAX_PATH] = {0};
    if(DbgGetModuleAt(cip, module) && module[0])
        snprintf(out, outSize, "%s", module);

    const DBGFUNCTIONS* funcs = DbgFunctions();
    if(funcs && funcs->ModPathFromAddr && funcs->ModPathFromAddr(cip, path, MAX_PATH) && path[0])
        snprintf(out, outSize, "%s", path);
}

static bool get_plugin_config_dir(char* out, size_t outSize)
{
    char modulePath[MAX_PATH] = {0};
    if(!g_hModule || !GetModuleFileNameA(g_hModule, modulePath, MAX_PATH))
        return false;

    char* slash = strrchr(modulePath, '\\');
    if(!slash)
        return false;
    *slash = '\0';
    snprintf(out, outSize, "%s\\x64dbg-mcp", modulePath);
    return true;
}

static bool is_absolute_path(const char* path)
{
    if(!path || !path[0])
        return false;
    if(path[0] == '\\' || path[0] == '/')
        return true;
    return path[1] == ':' &&
        ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z'));
}

static void resolve_relative_path(const char* baseDir, char* path, size_t pathSize)
{
    if(!path[0] || is_absolute_path(path))
        return;
    char resolved[MAX_PATH] = {0};
    snprintf(resolved, sizeof(resolved), "%s\\%s", baseDir, path);
    snprintf(path, pathSize, "%s", resolved);
}

static void load_broker_config()
{
    char configDir[MAX_PATH] = {0};
    if(!get_plugin_config_dir(configDir, sizeof(configDir)))
        return;

    snprintf(g_brokerConfig.serverScript, sizeof(g_brokerConfig.serverScript), "%s\\server.py", configDir);
    snprintf(g_brokerConfig.webRoot, sizeof(g_brokerConfig.webRoot), "%s\\web", configDir);

    char configPath[MAX_PATH] = {0};
    snprintf(configPath, sizeof(configPath), "%s\\config.json", configDir);
    json_error_t error;
    json_t* root = json_load_file(configPath, 0, &error);
    if(!root)
    {
        log_msg("[MCP Bridge] Config not found, using defaults: %s", configPath);
        return;
    }

    const char* brokerUrl = json_string_value(json_object_get(root, "broker_url"));
    const char* pythonPath = json_string_value(json_object_get(root, "python_path"));
    const char* serverScript = json_string_value(json_object_get(root, "server_script"));
    const char* webRoot = json_string_value(json_object_get(root, "web_root"));
    json_t* interval = json_object_get(root, "watchdog_interval_ms");
    json_t* failures = json_object_get(root, "watchdog_failures_before_notify");
    json_t* autoRestart = json_object_get(root, "auto_restart_broker");

    if(brokerUrl && brokerUrl[0])
        snprintf(g_brokerConfig.brokerUrl, sizeof(g_brokerConfig.brokerUrl), "%s", brokerUrl);
    if(pythonPath && pythonPath[0])
        snprintf(g_brokerConfig.pythonPath, sizeof(g_brokerConfig.pythonPath), "%s", pythonPath);
    if(serverScript && serverScript[0])
        snprintf(g_brokerConfig.serverScript, sizeof(g_brokerConfig.serverScript), "%s", serverScript);
    if(webRoot && webRoot[0])
        snprintf(g_brokerConfig.webRoot, sizeof(g_brokerConfig.webRoot), "%s", webRoot);
    if(json_is_integer(interval))
        g_brokerConfig.watchdogIntervalMs = (DWORD)json_integer_value(interval);
    if(json_is_integer(failures))
        g_brokerConfig.failuresBeforeNotify = (int)json_integer_value(failures);
    if(json_is_boolean(autoRestart))
        g_brokerConfig.autoRestartBroker = json_is_true(autoRestart);

    json_decref(root);
    resolve_relative_path(configDir, g_brokerConfig.serverScript, sizeof(g_brokerConfig.serverScript));
    resolve_relative_path(configDir, g_brokerConfig.webRoot, sizeof(g_brokerConfig.webRoot));
    log_msg("[MCP Bridge] Broker config loaded: %s", configPath);
}

static bool parse_http_url(const char* url, char* host, size_t hostSize, unsigned short* port, char* path, size_t pathSize)
{
    const char* p = strstr(url, "://");
    p = p ? p + 3 : url;
    const char* slash = strchr(p, '/');
    const char* hostEnd = slash ? slash : p + strlen(p);
    const char* colon = NULL;
    for(const char* it = p; it < hostEnd; it++)
    {
        if(*it == ':')
        {
            colon = it;
            break;
        }
    }

    size_t hostLen = (size_t)((colon ? colon : hostEnd) - p);
    if(hostLen == 0 || hostLen >= hostSize)
        return false;
    memcpy(host, p, hostLen);
    host[hostLen] = '\0';

    *port = colon ? (unsigned short)atoi(colon + 1) : 80;
    snprintf(path, pathSize, "%s", slash ? slash : "/");
    return true;
}

static bool broker_request(const char* method, const char* pathSuffix, const char* body, char* response, size_t responseSize)
{
    char host[128] = {0};
    char basePath[256] = {0};
    unsigned short port = 0;
    if(!parse_http_url(g_brokerConfig.brokerUrl, host, sizeof(host), &port, basePath, sizeof(basePath)))
        return false;

    char path[512] = {0};
    if(strcmp(basePath, "/") == 0)
        snprintf(path, sizeof(path), "%s", pathSuffix);
    else
        snprintf(path, sizeof(path), "%s%s", basePath, pathSuffix);

    WSADATA wsa = {0};
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sock == INVALID_SOCKET)
    {
        WSACleanup();
        return false;
    }

    sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host);
    if(addr.sin_addr.s_addr == INADDR_NONE || connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0)
    {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    const char* payload = body ? body : "";
    char header[1024];
    int headerLen = snprintf(header, sizeof(header),
        "%s %s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "Accept: application/json\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n"
        "\r\n",
        method, path, host, (unsigned int)port, (unsigned int)strlen(payload));
    bool ok = headerLen > 0 && send_all(sock, header, headerLen) && (!payload[0] || send_all(sock, payload, (int)strlen(payload)));
    int total = 0;
    if(ok && response && responseSize > 0)
    {
        while(total < (int)responseSize - 1)
        {
            int received = recv(sock, response + total, (int)responseSize - 1 - total, 0);
            if(received <= 0)
                break;
            total += received;
        }
        response[total] = '\0';
    }
    else if(ok)
    {
        char discard[512];
        while(recv(sock, discard, sizeof(discard), 0) > 0) {}
    }

    closesocket(sock);
    WSACleanup();

    if(!ok || !response || responseSize == 0)
        return ok;
    return strstr(response, "HTTP/1.1 200") != NULL || strstr(response, "HTTP/1.0 200") != NULL;
}

static bool broker_health_ok()
{
    char response[1024] = {0};
    return broker_request("GET", "/api/health", "", response, sizeof(response));
}

static bool start_broker_process()
{
    if(g_brokerConfig.serverScript[0] == '\0')
    {
        log_msg("[MCP Bridge] Broker server_script is not configured");
        return false;
    }
    if(broker_health_ok())
        return true;

    char host[128] = {0};
    char basePath[256] = {0};
    unsigned short port = 0;
    parse_http_url(g_brokerConfig.brokerUrl, host, sizeof(host), &port, basePath, sizeof(basePath));

    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "\"%s\" \"%s\" --broker --host %s --port %u --web-root \"%s\"",
        g_brokerConfig.pythonPath,
        g_brokerConfig.serverScript,
        host[0] ? host : "127.0.0.1",
        (unsigned int)(port ? port : 21463),
        g_brokerConfig.webRoot);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    BOOL created = CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if(!created)
    {
        log_msg("[MCP Bridge] Failed to start broker: %s", cmd);
        return false;
    }

    if(g_hBrokerProcess)
        CloseHandle(g_hBrokerProcess);
    g_hBrokerProcess = pi.hProcess;
    CloseHandle(pi.hThread);
    log_msg("[MCP Bridge] Started broker: %s", cmd);

    for(int i = 0; i < 20; i++)
    {
        if(broker_health_ok())
            return true;
        Sleep(250);
    }
    return false;
}

static void notify_broker_down_once()
{
    static volatile LONG shown = 0;
    if(InterlockedCompareExchange(&shown, 1, 0) == 0)
    {
        MessageBoxA(NULL,
            "x64dbg MCP broker is not responding. Check x64dbg\\plugins\\x64dbg-mcp\\config.json and Python.",
            "x64dbg MCP",
            MB_ICONWARNING | MB_OK);
    }
}

static void register_or_unregister_session()
{
    bool debugging = DbgIsDebugging();
    if(debugging && g_httpPort != 0)
    {
        char targetHint[MAX_PATH] = {0};
        char controlUrl[128] = {0};
        char pluginId[64] = {0};
        get_target_hint(targetHint, sizeof(targetHint));
        snprintf(controlUrl, sizeof(controlUrl), "http://%s:%u", HTTP_HOST, (unsigned int)g_httpPort);
        snprintf(pluginId, sizeof(pluginId), "%lu:%u", GetCurrentProcessId(), (unsigned int)g_httpPort);

        json_t* root = json_object();
        json_object_set_new(root, "plugin_id", json_string(pluginId));
        json_object_set_new(root, "pid", json_integer(GetCurrentProcessId()));
        json_object_set_new(root, "state", json_string(get_debug_state_string()));
        json_object_set_new(root, "control_port", json_integer(g_httpPort));
        json_object_set_new(root, "control_url", json_string(controlUrl));
        json_object_set_new(root, "target_hint", json_string(targetHint));
        char* body = json_dumps(root, JSON_COMPACT);
        json_decref(root);
        if(body)
        {
            if(broker_request("POST", "/api/register_session", body, NULL, 0))
                InterlockedExchange(&g_sessionRegistered, 1);
            free(body);
        }
    }
    else if(InterlockedCompareExchange(&g_sessionRegistered, 0, 0))
    {
        char pluginId[64] = {0};
        snprintf(pluginId, sizeof(pluginId), "%lu:%u", GetCurrentProcessId(), (unsigned int)g_httpPort);
        json_t* root = json_object();
        json_object_set_new(root, "plugin_id", json_string(pluginId));
        char* body = json_dumps(root, JSON_COMPACT);
        json_decref(root);
        if(body)
        {
            if(broker_request("POST", "/api/unregister_session", body, NULL, 0))
                InterlockedExchange(&g_sessionRegistered, 0);
            free(body);
        }
    }
}

static DWORD WINAPI watchdog_thread(LPVOID param)
{
    (void)param;
    int failures = 0;
    start_broker_process();

    while(InterlockedCompareExchange(&g_running, 0, 0))
    {
        if(broker_health_ok())
        {
            failures = 0;
            register_or_unregister_session();
        }
        else
        {
            failures++;
            if(g_brokerConfig.autoRestartBroker)
                start_broker_process();
            if(failures >= g_brokerConfig.failuresBeforeNotify)
                notify_broker_down_once();
        }
        Sleep(g_brokerConfig.watchdogIntervalMs);
    }
    return 0;
}

static json_t* build_instance_info_json()
{
    char url[128];
    char targetHint[MAX_PATH] = {0};
    snprintf(url, sizeof(url), "http://%s:%u", HTTP_HOST, (unsigned int)g_httpPort);
    get_target_hint(targetHint, sizeof(targetHint));

    json_t* info = json_object();
    json_object_set_new(info, "ok", json_true());
    json_object_set_new(info, "transport", json_string("http"));
    json_object_set_new(info, "host", json_string(HTTP_HOST));
    json_object_set_new(info, "port", json_integer(g_httpPort));
    json_object_set_new(info, "url", json_string(url));
    json_object_set_new(info, "pid", json_integer(GetCurrentProcessId()));
    json_object_set_new(info, "state", json_string(get_debug_state_string()));
    json_object_set_new(info, "target_hint", json_string(targetHint));
    return info;
}

static void delete_instance_file()
{
    if(g_instanceFile[0])
    {
        DeleteFileA(g_instanceFile);
        g_instanceFile[0] = '\0';
    }
}

static bool write_instance_file()
{
    char tempPath[MAX_PATH] = {0};
    DWORD tempLen = GetTempPathA(MAX_PATH, tempPath);
    if(tempLen == 0 || tempLen >= MAX_PATH)
        return false;

    char rootDir[MAX_PATH] = {0};
    char instanceDir[MAX_PATH] = {0};
    snprintf(rootDir, sizeof(rootDir), "%s%s", tempPath, HTTP_INSTANCE_ROOT);
    CreateDirectoryA(rootDir, NULL);
    snprintf(instanceDir, sizeof(instanceDir), "%s\\%s", rootDir, HTTP_INSTANCE_DIR);
    CreateDirectoryA(instanceDir, NULL);
    snprintf(g_instanceFile, sizeof(g_instanceFile), "%s\\%lu.json", instanceDir, GetCurrentProcessId());

    json_t* info = build_instance_info_json();
    char* text = json_dumps(info, JSON_INDENT(2));
    json_decref(info);
    if(!text)
        return false;

    HANDLE file = CreateFileA(g_instanceFile, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(file == INVALID_HANDLE_VALUE)
    {
        free(text);
        return false;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(file, text, (DWORD)strlen(text), &written, NULL);
    CloseHandle(file);
    free(text);
    return ok == TRUE;
}

static bool send_all(SOCKET sock, const char* data, int len)
{
    int sentTotal = 0;
    while(sentTotal < len)
    {
        int sent = send(sock, data + sentTotal, len - sentTotal, 0);
        if(sent == SOCKET_ERROR || sent == 0)
            return false;
        sentTotal += sent;
    }
    return true;
}

static void send_http_response(SOCKET client, int status, const char* reason, const char* contentType, const char* body)
{
    if(!body)
        body = "";
    char header[512];
    int bodyLen = (int)strlen(body);
    int headerLen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n",
        status, reason, contentType ? contentType : "application/json", bodyLen);
    if(headerLen > 0)
        send_all(client, header, headerLen);
    if(bodyLen > 0)
        send_all(client, body, bodyLen);
}

static int get_http_content_length(const char* headers)
{
    const char* p = headers;
    while(p && *p)
    {
        const char* lineEnd = strstr(p, "\r\n");
        size_t lineLen = lineEnd ? (size_t)(lineEnd - p) : strlen(p);
        if(lineLen >= 15 && _strnicmp(p, "Content-Length:", 15) == 0)
            return atoi(p + 15);
        if(!lineEnd)
            break;
        p = lineEnd + 2;
    }
    return 0;
}

static void send_instance_info(SOCKET client)
{
    write_instance_file();
    json_t* info = build_instance_info_json();
    char* body = json_dumps(info, JSON_COMPACT);
    json_decref(info);
    if(body)
    {
        send_http_response(client, 200, "OK", "application/json", body);
        free(body);
    }
    else
    {
        send_http_response(client, 500, "Internal Server Error", "application/json", "{\"error\":\"failed to build info\"}");
    }
}

static void handle_http_client(SOCKET client)
{
    char* buf = (char*)BridgeAlloc(HTTP_BUFFER_SIZE);
    char* out_buf = (char*)BridgeAlloc(HTTP_BUFFER_SIZE);
    if(!buf || !out_buf)
    {
        if(buf) BridgeFree(buf);
        if(out_buf) BridgeFree(out_buf);
        send_http_response(client, 500, "Internal Server Error", "application/json", "{\"error\":\"allocation failed\"}");
        return;
    }

    int total = 0;
    int headerLen = 0;
    int contentLength = 0;
    while(total < HTTP_BUFFER_SIZE - 1)
    {
        int received = recv(client, buf + total, HTTP_BUFFER_SIZE - 1 - total, 0);
        if(received <= 0)
            break;
        total += received;
        buf[total] = '\0';

        char* headerEnd = strstr(buf, "\r\n\r\n");
        if(headerEnd)
        {
            headerLen = (int)(headerEnd - buf) + 4;
            contentLength = get_http_content_length(buf);
            if(contentLength < 0 || contentLength > HTTP_BUFFER_SIZE - headerLen - 1)
            {
                send_http_response(client, 413, "Payload Too Large", "application/json", "{\"error\":\"request body too large\"}");
                BridgeFree(buf);
                BridgeFree(out_buf);
                return;
            }
            if(contentLength == 0 || total >= headerLen + contentLength)
                break;
        }
    }

    char method[16] = {0};
    char path[256] = {0};
    if(sscanf(buf, "%15s %255s", method, path) != 2)
    {
        send_http_response(client, 400, "Bad Request", "application/json", "{\"error\":\"bad request\"}");
        BridgeFree(buf);
        BridgeFree(out_buf);
        return;
    }

    if(_stricmp(method, "GET") == 0 && (strcmp(path, "/health") == 0 || strcmp(path, "/info") == 0))
    {
        send_instance_info(client);
    }
    else if(_stricmp(method, "POST") == 0 && strcmp(path, "/rpc") == 0)
    {
        char* body = headerLen > 0 ? buf + headerLen : NULL;
        if(!body || contentLength <= 0)
        {
            send_http_response(client, 400, "Bad Request", "application/json", "{\"error\":\"missing json body\"}");
        }
        else
        {
            body[contentLength] = '\0';
            json_error_t error;
            json_t* req = json_loads(body, 0, &error);
            if(req)
            {
                process_request(req, out_buf, HTTP_BUFFER_SIZE);
                json_decref(req);
                send_http_response(client, 200, "OK", "application/json", out_buf[0] ? out_buf : "{}");
            }
            else
            {
                send_http_response(client, 400, "Bad Request", "application/json", "{\"error\":\"invalid json\"}");
            }
        }
    }
    else
    {
        send_http_response(client, 404, "Not Found", "application/json", "{\"error\":\"not found\"}");
    }

    BridgeFree(buf);
    BridgeFree(out_buf);
}

static DWORD WINAPI http_client_thread(LPVOID param)
{
    SOCKET client = (SOCKET)(UINT_PTR)param;
    handle_http_client(client);
    shutdown(client, SD_BOTH);
    closesocket(client);
    return 0;
}

static bool bind_http_socket(SOCKET listenSocket, unsigned short* outPort)
{
    sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    for(unsigned short port = HTTP_PORT_START; port <= HTTP_PORT_END; port++)
    {
        addr.sin_port = htons(port);
        if(bind(listenSocket, (sockaddr*)&addr, sizeof(addr)) == 0)
        {
            *outPort = port;
            return true;
        }
    }
    return false;
}

static DWORD WINAPI http_thread(LPVOID param)
{
    (void)param;

    WSADATA wsa = {0};
    if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        log_msg("[MCP Bridge] WSAStartup failed");
        return 0;
    }

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(listenSocket == INVALID_SOCKET)
    {
        log_msg("[MCP Bridge] Failed to create HTTP socket");
        WSACleanup();
        return 0;
    }

    unsigned short port = 0;
    if(!bind_http_socket(listenSocket, &port) || listen(listenSocket, SOMAXCONN) != 0)
    {
        log_msg("[MCP Bridge] Failed to bind HTTP server on %s:%u-%u", HTTP_HOST, HTTP_PORT_START, HTTP_PORT_END);
        closesocket(listenSocket);
        WSACleanup();
        return 0;
    }

    g_listenSocket = listenSocket;
    g_httpPort = port;
    write_instance_file();
    log_msg("[MCP Bridge] HTTP server listening on http://%s:%u", HTTP_HOST, (unsigned int)g_httpPort);

    while(InterlockedCompareExchange(&g_running, 0, 0))
    {
        SOCKET client = accept(listenSocket, NULL, NULL);
        if(client == INVALID_SOCKET)
        {
            if(InterlockedCompareExchange(&g_running, 0, 0))
                Sleep(50);
            continue;
        }
        HANDLE thread = CreateThread(NULL, 0, http_client_thread, (LPVOID)(UINT_PTR)client, 0, NULL);
        if(thread)
            CloseHandle(thread);
        else
        {
            shutdown(client, SD_BOTH);
            closesocket(client);
        }
    }

    delete_instance_file();
    g_listenSocket = INVALID_SOCKET;
    closesocket(listenSocket);
    WSACleanup();
    return 0;
}

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
