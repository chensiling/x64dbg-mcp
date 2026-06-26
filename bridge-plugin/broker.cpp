#include "bridge_plugin.h"

void get_target_hint(char* out, size_t outSize)
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

bool get_plugin_config_dir(char* out, size_t outSize)
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

bool is_absolute_path(const char* path)
{
    if(!path || !path[0])
        return false;
    if(path[0] == '\\' || path[0] == '/')
        return true;
    return path[1] == ':' &&
        ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z'));
}

void resolve_relative_path(const char* baseDir, char* path, size_t pathSize)
{
    if(!path[0] || is_absolute_path(path))
        return;
    char resolved[MAX_PATH] = {0};
    snprintf(resolved, sizeof(resolved), "%s\\%s", baseDir, path);
    snprintf(path, pathSize, "%s", resolved);
}

void load_broker_config()
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

bool parse_http_url(const char* url, char* host, size_t hostSize, unsigned short* port, char* path, size_t pathSize)
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

bool broker_request(const char* method, const char* pathSuffix, const char* body, char* response, size_t responseSize)
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

bool broker_health_ok()
{
    char response[1024] = {0};
    return broker_request("GET", "/api/health", "", response, sizeof(response));
}

bool start_broker_process()
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

void notify_broker_down_once()
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

void register_or_unregister_session()
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

DWORD WINAPI watchdog_thread(LPVOID param)
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
