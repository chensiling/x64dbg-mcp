#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>

#include "../pluginsdk/bridgemain.h"
#include "../pluginsdk/_plugins.h"
#include "../pluginsdk/_dbgfunctions.h"
#include "../pluginsdk/jansson/jansson.h"
#include "protocol.h"

static HANDLE g_hPipeThread = NULL;
static volatile LONG g_running = 0;
static int g_pluginHandle = 0;
static bool g_consoleAllocated = false;

#define MAX_BP_FILTERS 16
static duint g_bpFilterAddrs[MAX_BP_FILTERS];
static char g_bpFilterPatterns[MAX_BP_FILTERS][256];
static int g_bpFilterCount = 0;

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
        printf("  Pipe: %s\n", PIPE_NAME_STR);
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

static void bp_filter_callback(CBTYPE cbType, void* callbackInfo)
{
    if(cbType != CB_BREAKPOINT) return;
    PLUG_CB_BREAKPOINT* bp = (PLUG_CB_BREAKPOINT*)callbackInfo;
    if(!bp || !bp->breakpoint) return;

    duint bpAddr = bp->breakpoint->addr;
    for(int i = 0; i < g_bpFilterCount; i++)
    {
        if(g_bpFilterAddrs[i] != bpAddr) continue;

        // Read RCX (filename pointer)
        REGDUMP_AVX512 regdump = {0};
        if(!DbgGetRegDumpEx(&regdump, sizeof(REGDUMP_AVX512))) return;
        duint rcx = regdump.regcontext.ccx;

        // Read wide string
        unsigned char buf[512] = {0};
        if(!DbgMemRead(rcx, buf, sizeof(buf) - 1)) return;
        wchar_t wbuf[256] = {0};
        memcpy(wbuf, buf, sizeof(buf) - 2);
        size_t wlen = 0;
        for(size_t j = 0; j < 256 && wbuf[j] != 0; j++) wlen++;

        char filename[512] = {0};
        if(wlen > 0)
        {
            int len = WideCharToMultiByte(CP_UTF8, 0, wbuf, (int)wlen, filename, sizeof(filename) - 1, NULL, NULL);
            if(len > 0) filename[len] = '\0';
        }

        // Case-insensitive substring match
        const char* pattern = g_bpFilterPatterns[i];
        bool matched = false;
        for(const char* h = filename; *h && !matched; h++)
        {
            const char* n = pattern;
            const char* hh = h;
            while(*n && *hh && tolower((unsigned char)*n) == tolower((unsigned char)*hh))
                { n++; hh++; }
            if(*n == '\0') matched = true;
        }

        if(!matched)
        {
            log_msg("[BP Filter] Skip %llX (not %s)", (unsigned long long)bpAddr, pattern);
            DbgCmdExec("run");
        }
        else
        {
            log_msg("[BP Filter] HIT %llX = %s", (unsigned long long)bpAddr, pattern);
        }
        break;
    }
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
    json_object_set_new(resp, "id", json_string(id));
    if(data)
        json_object_set_new(resp, "result", data);
    else
        json_object_set_new(resp, "error", json_string("no data"));
    return resp;
}

static json_t* build_error_response(const char* id, const char* msg)
{
    json_t* resp = json_object();
    json_object_set_new(resp, "id", json_string(id));
    json_object_set_new(resp, "error", json_string(msg));
    return resp;
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
    duint cur = addr;
    int i = 0;
    while(i < (int)count && (!endAddr || cur < endAddr))
    {
        BASIC_INSTRUCTION_INFO basicinfo = {0};
        DbgDisasmFastAt(cur, &basicinfo);

        DISASM_INSTR instr = {0};
        DbgDisasmAt(cur, &instr);

        json_t* entry = json_object();
        json_object_set_new(entry, "address", addr_json(cur));
        json_object_set_new(entry, "instruction", json_string(instr.instruction));
        json_object_set_new(entry, "size", addr_json(basicinfo.size));
        if(basicinfo.branch)
        {
            json_object_set_new(entry, "branch", json_true());
            json_object_set_new(entry, "branch_dest", addr_json(basicinfo.addr));
        }
        json_array_append_new(instructions, entry);

        if(basicinfo.size <= 0)
            break;
        cur += basicinfo.size;
    }

    json_t* data = json_object();
    json_object_set_new(data, "address", addr_json(addr));
    json_object_set_new(data, "count", addr_json(count));
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

        const char* condition = json_string_value(json_object_get(params, "condition"));
        if(ok && condition && condition[0])
        {
            snprintf(cmd, sizeof(cmd), "bpcnd %llX,%s", (unsigned long long)addr, condition);
            ok = DbgCmdExecDirect(cmd);
        }
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

    const char* state = "unknown";
    if(DbgIsDebugging())
    {
        if(DbgIsRunning())
            state = "running";
        else
            state = "paused";
    }
    else
    {
        state = "stopped";
    }

    json_t* data = json_object();
    json_object_set_new(data, "state", json_string(state));
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
    DbgCmdExecDirect("pause");
    json_t* data = json_object();
    json_object_set_new(data, "ok", json_true());
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

static void handle_get_call_stack(json_t* req, json_t* params, json_t** out_resp)
{
    (void)params;
    const char* id = json_string_value(json_object_get(req, "id"));

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
        json_array_append_new(frames, frame);
    }
    if(cs.entries) BridgeFree(cs.entries);

    json_t* data = json_object();
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

static void handle_set_bp_filter(json_t* req, json_t* params, json_t** out_resp)
{
    const char* id = json_string_value(json_object_get(req, "id"));
    duint addr = 0;
    const char* filename = json_string_value(json_object_get(params, "filename"));
    if(!get_addr_param(params, "addr", &addr) || !filename)
    {
        *out_resp = build_error_response(id, "set_bp_filter requires addr (hex string) and filename (string)");
        return;
    }

    json_t* data = json_object();
    if(g_bpFilterCount < MAX_BP_FILTERS)
    {
        g_bpFilterAddrs[g_bpFilterCount] = addr;
        strncpy(g_bpFilterPatterns[g_bpFilterCount], filename, 255);
        g_bpFilterPatterns[g_bpFilterCount][255] = '\0';
        g_bpFilterCount++;
        json_object_set_new(data, "ok", json_true());
        json_object_set_new(data, "count", addr_json(g_bpFilterCount));
        log_msg("[BP Filter] Set filter on %llX -> %s", (unsigned long long)addr, filename);
    }
    else
    {
        json_object_set_new(data, "ok", json_false());
        json_object_set_new(data, "error", json_string("Max filters reached"));
    }
    *out_resp = build_value_response(id, data);
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

static cmd_handler get_handler(const char* method)
{
    if(strcmp(method, CMD_READ_MEMORY) == 0)       return handle_read_memory;
    if(strcmp(method, CMD_WRITE_MEMORY) == 0)      return handle_write_memory;
    if(strcmp(method, CMD_DISASSEMBLE) == 0)        return handle_disassemble;
    if(strcmp(method, CMD_GET_REGISTERS) == 0)     return handle_get_registers;
    if(strcmp(method, CMD_SET_REGISTER) == 0)      return handle_set_register;
    if(strcmp(method, CMD_GET_BREAKPOINTS) == 0)   return handle_get_breakpoints;
    if(strcmp(method, CMD_SET_BREAKPOINT) == 0)    return handle_set_breakpoint;
    if(strcmp(method, CMD_DELETE_BREAKPOINT) == 0) return handle_delete_breakpoint;
    if(strcmp(method, CMD_TOGGLE_BREAKPOINT) == 0) return handle_toggle_breakpoint;
    if(strcmp(method, CMD_GET_DEBUG_STATE) == 0)   return handle_get_debug_state;
    if(strcmp(method, CMD_RUN) == 0)                return handle_run;
    if(strcmp(method, CMD_PAUSE) == 0)              return handle_pause;
    if(strcmp(method, CMD_STOP) == 0)               return handle_stop;
    if(strcmp(method, CMD_STEP_IN) == 0)            return handle_step_in;
    if(strcmp(method, CMD_STEP_OVER) == 0)          return handle_step_over;
    if(strcmp(method, CMD_STEP_OUT) == 0)           return handle_step_out;
    if(strcmp(method, CMD_GET_MODULES) == 0)        return handle_get_modules;
    if(strcmp(method, CMD_GET_MODULE_INFO) == 0)    return handle_get_module_info;
    if(strcmp(method, CMD_GET_SYMBOLS) == 0)        return handle_get_symbols;
    if(strcmp(method, CMD_EVALUATE) == 0)           return handle_evaluate;
    if(strcmp(method, CMD_GET_MEMORY_MAP) == 0)     return handle_get_memory_map;
    if(strcmp(method, CMD_GET_CALL_STACK) == 0)     return handle_get_call_stack;
    if(strcmp(method, CMD_GET_LABEL) == 0)          return handle_get_label;
    if(strcmp(method, CMD_SET_LABEL) == 0)          return handle_set_label;
    if(strcmp(method, CMD_GET_COMMENT) == 0)        return handle_get_comment;
    if(strcmp(method, CMD_SET_COMMENT) == 0)        return handle_set_comment;
    if(strcmp(method, CMD_ASSEMBLE) == 0)           return handle_assemble;
    if(strcmp(method, CMD_GET_STRING) == 0)         return handle_get_string;
    if(strcmp(method, CMD_FIND_STRING) == 0)        return handle_find_string;
    if(strcmp(method, CMD_RUN_TO) == 0)             return handle_run_to;
    if(strcmp(method, CMD_SET_EIP) == 0)            return handle_set_eip;
    if(strcmp(method, CMD_GET_THREADS) == 0)        return handle_get_threads;
    if(strcmp(method, CMD_FIND_BYTES) == 0)         return handle_find_bytes;
    if(strcmp(method, CMD_GET_FUNCTION_INFO) == 0)  return handle_get_function_info;
    if(strcmp(method, CMD_GET_XREFS) == 0)          return handle_get_xrefs;
    if(strcmp(method, CMD_SET_BP_FILTER) == 0)      return handle_set_bp_filter;
    if(strcmp(method, CMD_CMD_EXEC) == 0)           return handle_cmd_exec;
    return NULL;
}

static void process_request(json_t* req, char* out_buf, size_t out_buf_size)
{
    const char* method = json_string_value(json_object_get(req, "method"));
    json_t* params = json_object_get(req, "params");
    const char* id = json_string_value(json_object_get(req, "id"));

    json_t* resp = NULL;
    cmd_handler handler = get_handler(method);
    if(handler)
    {
        handler(req, params ? params : json_object(), &resp);
    }
    else
    {
        resp = json_object();
        json_object_set_new(resp, "id", json_string(id));
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
}

static DWORD WINAPI pipe_thread(LPVOID param)
{
    (void)param;

    while(InterlockedCompareExchange(&g_running, 0, 0))
    {
        HANDLE hPipe = CreateNamedPipeW(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            NULL);

        if(hPipe == INVALID_HANDLE_VALUE)
        {
            Sleep(1000);
            continue;
        }

        BOOL connected = ConnectNamedPipe(hPipe, NULL) ?
            TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

        if(connected)
        {
            log_msg("[MCP Bridge] Client connected");
            char* buf = (char*)BridgeAlloc(PIPE_BUFFER_SIZE);
            char* out_buf = (char*)BridgeAlloc(PIPE_BUFFER_SIZE);

            while(InterlockedCompareExchange(&g_running, 0, 0))
            {
                DWORD bytesRead = 0;
                BOOL ok = ReadFile(hPipe, buf, PIPE_BUFFER_SIZE - 1, &bytesRead, NULL);
                if(!ok || bytesRead == 0)
                    break;

                buf[bytesRead] = '\0';

                json_error_t error;
                json_t* req = json_loads(buf, 0, &error);
                if(req)
                {
                    process_request(req, out_buf, PIPE_BUFFER_SIZE);
                    json_decref(req);

                    if(out_buf[0])
                    {
                        DWORD written = 0;
                        WriteFile(hPipe, out_buf, (DWORD)strlen(out_buf), &written, NULL);
                    }
                }
                else
                {
                    const char* err = "{\"error\":\"invalid json\"}\n";
                    DWORD written = 0;
                    WriteFile(hPipe, err, (DWORD)strlen(err), &written, NULL);
                }
            }

            BridgeFree(buf);
            BridgeFree(out_buf);
            log_msg("[MCP Bridge] Client disconnected");
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }

    return 0;
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->sdkVersion = PLUG_SDKVERSION;
    initStruct->pluginVersion = 1;
    strncpy(initStruct->pluginName, "MCP Bridge Plugin", 256);
    g_pluginHandle = initStruct->pluginHandle;
    _plugin_registercallback(g_pluginHandle, CB_BREAKPOINT, bp_filter_callback);
    return true;
}

extern "C" __declspec(dllexport) bool plugstop()
{
    InterlockedExchange(&g_running, 0);
    if(g_hPipeThread)
    {
        WaitForSingleObject(g_hPipeThread, 3000);
        CloseHandle(g_hPipeThread);
        g_hPipeThread = NULL;
    }
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    (void)setupStruct;
    init_console();
    InterlockedExchange(&g_running, 1);
    g_hPipeThread = CreateThread(NULL, 0, pipe_thread, NULL, 0, NULL);
    log_msg("[MCP Bridge] Plugin loaded successfully");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)hModule;
    (void)lpReserved;
    if(ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        InterlockedExchange(&g_running, 0);
    }
    return TRUE;
}
