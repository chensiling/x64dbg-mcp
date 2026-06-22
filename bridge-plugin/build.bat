@echo off
REM Build script for the x64dbg MCP Bridge Plugin
REM Run from: "Developer Command Prompt for VS" or "vcvarsall.bat x64"

setlocal

set PLUGIN_NAME=mcp_bridge
set PLUGINSDK=..\pluginsdk
set OUT_DIR=build

if not exist "%OUT_DIR%" mkdir %OUT_DIR%

echo Building x64 plugin...

cl.exe /nologo /O2 /MD /LD /EHsc ^
    /I"%PLUGINSDK%" /I"%PLUGINSDK%\jansson" /I"%PLUGINSDK%\lz4" /I"%PLUGINSDK%\XEDParse" ^
    /DBUILD_BRIDGE /D_CRT_SECURE_NO_WARNINGS /D_WIN64 ^
    /Fe:"%OUT_DIR%\%PLUGIN_NAME%.dp64" ^
    bridge_plugin.cpp ^
    "%PLUGINSDK%\x64dbg.lib" ^
    "%PLUGINSDK%\x64bridge.lib" ^
    "%PLUGINSDK%\jansson\jansson_x64.lib" ^
    /link /NODEFAULTLIB:libcmt

if %ERRORLEVEL% EQU 0 (
    echo [OK] Plugin built: %OUT_DIR%\%PLUGIN_NAME%.dp64
    echo Copy to: x64dbg\release\x64\plugins\
) else (
    echo [FAIL] Build failed. Error code: %ERRORLEVEL%
)

endlocal
