# AGENTS.md — x64dbg-mcp

## Architecture summary

```
AI (MCP stdio) → server.py (Python, mcp lib) → HTTP JSON-RPC → bridge_plugin.cpp (C++, x64dbg DLL) → x64dbg Bridge API
```

Two runtime modes in `server.py`:
- `server.py --broker` — HTTP broker on `127.0.0.1:21463` (started by the C plugin).
- `server.py` (no flag) — MCP stdio client; connects to broker or direct to a plugin HTTP instance.

All addresses are **hex strings** (`"0x7FF642030338"`), never integers. `bridge_client.py` has a safety net (`_convert_addrs`) but always pass hex strings.

## Build (C plugin only)

**Required**: Visual Studio 2022 Developer Command Prompt (x64 Native Tools).

```batch
cd bridge-plugin
build.bat
```

Output: `build\mcp_bridge.dp64` + `build\x64dbg-mcp\` (Python files, config.json, web/).

CMake alternative (also works, but `build.bat` is the canonical command):
```batch
cmake -S bridge-plugin -B build\cmake -G "Visual Studio 17 2022" -A x64
cmake --build build\cmake --config Release
```

`build\cmake` is a temp dir; delete after. The `.lib`, `.exp`, `.pdb`, `.obj` intermediates are auto-cleaned by `build.bat` but not by CMake.

**Pluginsdk is vendored**: `pluginsdk/` is gitignored but required. It must be present at the repo root for compilation.

## Testing

Python unit tests only (no C tests). Run from repo root:

```bash
python -m pytest mcp-server/tests/ -v
# or directly:
python mcp-server/tests/test_registry_and_bridge_client.py
```

Tests mock the `mcp` module (`mcp.types.Tool`) — they don't need the actual `mcp` package installed.

## Key files and their roles

| File | Role |
|------|------|
| `bridge-plugin/bridge_plugin.h` | Shared header — all includes, extern globals, function declarations |
| `bridge-plugin/bridge_plugin.cpp` | Plugin lifecycle (DllMain, pluginit, plugstop, plugsetup) + dispatch table + `process_request` |
| `bridge-plugin/util.cpp` | hex_encode/hex_decode, log_msg, init_console, JSON helpers |
| `bridge-plugin/commands.cpp` | All 40 command handlers + breakpoint condition helpers |
| `bridge-plugin/http_server.cpp` | HTTP server: socket bind, accept loop, client handler, response helpers |
| `bridge-plugin/broker.cpp` | Broker management: config loading, broker process start/health check, watchdog, session register |
| `bridge-plugin/instance_file.cpp` | Temp directory instance file read/write/delete |
| `bridge-plugin/protocol.h` | Shared command-name constants (must match `tool_registry.py`) |
| `mcp-server/server.py` | Either broker (HTTP) or MCP stdio client — both modes in one file |
| `mcp-server/bridge_client.py` | HTTP client to talk to plugin instances or broker |
| `mcp-server/tool_registry.py` | MCP tool definitions + `TOOL_TO_CMD` mapping (MCP name → bridge command) |
| `mcp-server/config.json` | Broker/plugin config (broker URL, Python path, watchdog settings) |
| `mcp-server/requirements.txt` | Single dependency: `mcp>=1.0.0` |
| `build/` | Build output AND deployment package directory |
| `.mcp.json` | OpenCode MCP client config pointing at the local broker |

## Tool-to-command mapping

`tool_registry.py:TOOL_TO_CMD` maps public MCP tool names to bridge command names. `set_bp_filter` and `breakpoint_condition_set` **both map to `set_breakpoint_condition`** — same bridge command, different MCP interface. `breakpoint_set` does NOT accept conditions; use the condition lifecycle tools for that.

## Important conventions

- **Never pass integer addresses** — JSON loses precision on >2^53 values. Always hex strings.
- **Adding a new tool requires touching THREE places**: (1) `tool_registry.py` (definition + mapping), (2) `protocol.h` (command constant if new), (3) `commands.cpp` (handler implementation) + `bridge_plugin.h` (declaration).
- **`build/` is `.gitignore`d** — never commit build artifacts.
- **`pluginsdk/` is `.gitignore`d** — it's vendored from x64dbg SDK; not part of this repo.
- **The broker runs Starlette+uvicorn** (imported lazily inside `run_broker`). These come with the `mcp` package, NOT from a separate pip install.
- **`server.py` has code duplication** — both `BrokerHandler` (stdlib `http.server`) and Starlette routes implement the same endpoints. They serve the same purpose through different HTTP servers. When modifying one, check the other.

## Multi-instance routing

- Multiple x64dbg instances get aliases (A, B, C…) assigned by the broker.
- Single-instance: MCP server auto-routes to the only session.
- Multi-instance: must route via `/<alias>/rpc` or set `X64DBG_MCP_PORT` / `X64DBG_MCP_URL` env vars.
- Instance files written to `%TEMP%\x64dbg-mcp\instances\<pid>.json`.

## Debugging gotchas

- The C plugin opens a console window on startup — check it for HTTP port and error messages.
- Broker health at `http://127.0.0.1:21463/health` (HTML) and `/api/health` (JSON).
- The plugin watchdog auto-restarts the broker if it goes down (configured in `config.json`).
- `string_read` auto-decodes UTF-16LE/ASCII/UTF-8; the decoded string is added to the response as `data.string`.
