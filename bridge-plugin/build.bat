@echo off
REM Build script for the x64dbg MCP Bridge Plugin
REM Run from: "Developer Command Prompt for VS" or "vcvarsall.bat x64"

setlocal

set "SCRIPT_DIR=%~dp0"
set "ROOT_DIR=%SCRIPT_DIR%.."
for %%I in ("%ROOT_DIR%") do set "ROOT_DIR=%%~fI"

set "PLUGIN_NAME=mcp_bridge"
set "PLUGINSDK=%ROOT_DIR%\pluginsdk"
set "OUT_DIR=%ROOT_DIR%\build"
set "PACKAGE_DIR=%OUT_DIR%\x64dbg-mcp"
set "MCP_SERVER_DIR=%ROOT_DIR%\mcp-server"

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

echo Building x64 plugin...

cl.exe /nologo /O2 /MD /LD /EHsc ^
    /I"%PLUGINSDK%" /I"%PLUGINSDK%\jansson" /I"%PLUGINSDK%\lz4" /I"%PLUGINSDK%\XEDParse" ^
    /DBUILD_BRIDGE /D_CRT_SECURE_NO_WARNINGS /D_WIN64 ^
    /Fe:"%OUT_DIR%\%PLUGIN_NAME%.dp64" ^
    "%SCRIPT_DIR%bridge_plugin.cpp" ^
    "%PLUGINSDK%\x64dbg.lib" ^
    "%PLUGINSDK%\x64bridge.lib" ^
    "%PLUGINSDK%\jansson\jansson_x64.lib" ^
    Ws2_32.lib ^
    User32.lib ^
    /link /NODEFAULTLIB:libcmt

if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Build failed. Error code: %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)

echo Assembling x64dbg-mcp package...

if not exist "%PACKAGE_DIR%" mkdir "%PACKAGE_DIR%"
if not exist "%PACKAGE_DIR%\web" mkdir "%PACKAGE_DIR%\web"

copy /Y "%MCP_SERVER_DIR%\server.py" "%PACKAGE_DIR%\server.py" >nul
copy /Y "%MCP_SERVER_DIR%\bridge_client.py" "%PACKAGE_DIR%\bridge_client.py" >nul
copy /Y "%MCP_SERVER_DIR%\tool_registry.py" "%PACKAGE_DIR%\tool_registry.py" >nul
copy /Y "%MCP_SERVER_DIR%\requirements.txt" "%PACKAGE_DIR%\requirements.txt" >nul
copy /Y "%MCP_SERVER_DIR%\config.json" "%PACKAGE_DIR%\config.json" >nul
copy /Y "%MCP_SERVER_DIR%\web\health.html" "%PACKAGE_DIR%\web\health.html" >nul

if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Package assembly failed. Error code: %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)

echo Cleaning build intermediates...
del /Q "%OUT_DIR%\%PLUGIN_NAME%.exp" 2>nul
del /Q "%OUT_DIR%\%PLUGIN_NAME%.lib" 2>nul
del /Q "%OUT_DIR%\%PLUGIN_NAME%.pdb" 2>nul
del /Q "%OUT_DIR%\%PLUGIN_NAME%.ilk" 2>nul
del /Q "%OUT_DIR%\*.obj" 2>nul

echo [OK] Plugin built: %OUT_DIR%\%PLUGIN_NAME%.dp64
echo [OK] Package assembled: %PACKAGE_DIR%

endlocal
