#include "bridge_plugin.h"

json_t* build_instance_info_json()
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

void delete_instance_file()
{
    if(g_instanceFile[0])
    {
        DeleteFileA(g_instanceFile);
        g_instanceFile[0] = '\0';
    }
}

bool write_instance_file()
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
