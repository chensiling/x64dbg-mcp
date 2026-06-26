#include "bridge_plugin.h"

void hex_encode(const unsigned char* data, size_t len, char* out)
{
    for(size_t i = 0; i < len; i++)
        sprintf(out + i * 2, "%02X", data[i]);
    out[len * 2] = '\0';
}

size_t hex_decode(const char* hex, unsigned char* out)
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

void init_console()
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

void log_msg(const char* format, ...)
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

bool get_addr_param(json_t* params, const char* key, duint* out)
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

bool get_int_param(json_t* params, const char* key, duint defaultVal, duint* out)
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

json_t* addr_json(duint value)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)value);
    return json_string(buf);
}

json_t* json_string_safe(const char* value)
{
    return json_string(value ? value : "");
}

char* json_escape(const char* src)
{
    json_t* j = json_string(src);
    const char* raw = json_string_value(j);
    size_t len = strlen(raw);
    char* escaped = (char*)BridgeAlloc(len + 1);
    memcpy(escaped, raw, len + 1);
    json_decref(j);
    return escaped;
}

json_t* build_value_response(const char* id, json_t* data)
{
    json_t* resp = json_object();
    json_object_set_new(resp, "id", json_string_safe(id));
    if(data)
        json_object_set_new(resp, "result", data);
    else
        json_object_set_new(resp, "error", json_string("no data"));
    return resp;
}

json_t* build_error_response(const char* id, const char* msg)
{
    json_t* resp = json_object();
    json_object_set_new(resp, "id", json_string_safe(id));
    json_object_set_new(resp, "error", json_string_safe(msg));
    return resp;
}
