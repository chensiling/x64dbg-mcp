#include "bridge_plugin.h"

bool send_all(SOCKET sock, const char* data, int len)
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

void send_http_response(SOCKET client, int status, const char* reason, const char* contentType, const char* body)
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

int get_http_content_length(const char* headers)
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

void send_instance_info(SOCKET client)
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

void handle_http_client(SOCKET client)
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

DWORD WINAPI http_client_thread(LPVOID param)
{
    SOCKET client = (SOCKET)(UINT_PTR)param;
    handle_http_client(client);
    shutdown(client, SD_BOTH);
    closesocket(client);
    return 0;
}

bool bind_http_socket(SOCKET listenSocket, unsigned short* outPort)
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

DWORD WINAPI http_thread(LPVOID param)
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
