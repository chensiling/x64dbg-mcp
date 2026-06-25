# x64dbg-mcp

x64dbg 的 MCP Server——通过 MCP 协议让任意 AI Agent 远程控制 x64dbg 调试器。

## 架构

```
AI 助手 (MCP 客户端)
    │  stdio (JSON-RPC, 十六进制字符串)
    ▼
Python MCP 服务端 / Broker (mcp 库 + HTTP)
    │  MCP 工具调用或 broker 路由
    ▼
Broker 固定入口: http://127.0.0.1:21463/health
    │  HTTP JSON-RPC (localhost, 十六进制字符串)
    ▼
C 桥接插件 (x64dbg .dp64 DLL)
    │  x64dbg Bridge API
    ▼
x64dbg 调试引擎
```

全链路十六进制字符串传递，任意 MCP 客户端零精度丢失。插件默认只监听 `127.0.0.1`，从 `21464` 开始自动选择可用端口。Broker 默认监听 `127.0.0.1:21463`，`/health` 提供可视化状态页，`/api/health` 提供 watchdog JSON 状态。

## 编译与安装

### 前置条件

| 组件 | 版本要求 | 说明 |
|------|---------|------|
| Windows | 10/11 x64 | |
| x64dbg | 2024+ snapshot | [下载地址](https://sourceforge.net/projects/x64dbg/files/snapshots/) |
| Visual Studio | 2022 | 需勾选"使用 C++ 的桌面开发"工作负载 |
| Python | 3.10+ | |

### 1. 编译桥接插件

打开 **开始菜单 → Visual Studio 2022 → x64 Native Tools Command Prompt for VS 2022**：

```batch
cd C:\path\to\x64dbg-mcp\bridge-plugin
build.bat
```

编译生成 `build\mcp_bridge.dp64`。如果用 CMake：

```batch
cmake -S bridge-plugin -B build\cmake -G "Visual Studio 17 2022" -A x64
cmake --build build\cmake --config Release
rmdir /s /q build\cmake
```

构建会在仓库根目录生成完整部署包：

```
build\
  mcp_bridge.dp64
  x64dbg-mcp\
    config.json
    server.py
    bridge_client.py
    tool_registry.py
    requirements.txt
    web\
      health.html
```

`build.bat` 会自动删除 `.lib`、`.exp`、`.pdb`、`.obj` 等中间产物。CMake 示例中 `build\cmake` 是临时生成目录，构建成功后可以删除；最终部署文件仍保留在根 `build`。

### 2. 安装 Python 依赖

```bash
pip install mcp
```

或用 requirements.txt 一键安装：

```bash
cd C:\path\to\x64dbg-mcp\mcp-server
pip install -r requirements.txt
```

依赖清单 (`requirements.txt`)：

```
mcp>=1.0.0
```

### 3. 部署插件

将 `mcp_bridge.dp64` 放到 x64dbg 的插件目录，并放置 `x64dbg-mcp` 配置目录：

```
C:\path\to\x64dbg\release\x64\plugins\
  mcp_bridge.dp64
  x64dbg-mcp\
    config.json
    server.py
    bridge_client.py
    tool_registry.py
    requirements.txt
    web\
      health.html
```

仓库中的源码来源：

```
bridge-plugin\
  bridge_plugin.cpp

mcp-server\
  config.json
  server.py
  bridge_client.py
  tool_registry.py
  requirements.txt
  web\
    health.html
```

`build` 是完整部署产物目录，由 build.bat 或 CMake 从 `bridge-plugin` 和 `mcp-server` 生成。部署时应整体使用 `build\mcp_bridge.dp64` 和 `build\x64dbg-mcp`，不要只放一个 `server.py`。

`config.json` 中的 `server_script` 默认是相对路径 `server.py`，C 插件会按 `x64dbg\plugins\x64dbg-mcp` 目录解析，不依赖仓库路径。`server.py --broker` 模式只启动 HTTP broker，不会加载 MCP stdio 依赖；作为 MCP 客户端入口运行时才会加载 `mcp` 包。

重启 x64dbg，插件自动加载后会检查并启动 broker，然后启动本实例 HTTP RPC 端口。

### 4. 配置 MCP 客户端

启动顺序：

1. 先启动 x64dbg，插件会用相对路径启动 `x64dbg-mcp\server.py --broker`
2. Broker 监听 `http://127.0.0.1:21463`
3. 再启动 Agent 工具（如 Claude、Cursor、VS Code 等），通过 HTTP 连接 broker

MCP 客户端配置使用 URL，不再让 Agent 工具启动 Python server：

```json
{
  "mcpServers": {
    "x64dbg": {
      "url": "http://127.0.0.1:21463",
      "enabled": true
    }
  }
}
```

`http://127.0.0.1:21463` 同时提供 MCP Streamable HTTP、`/health` 可视化页面、`/api/health` watchdog JSON，以及兼容用的 `/{alias}/rpc` broker 路由。

### 5. 使用

1. 启动 x64dbg，载入调试目标
2. 连接 MCP 客户端——桥接插件会自动弹控制台窗口，显示 HTTP 端口
3. 通过 AI 控制调试器

## Broker 与实例发现

插件会启动/复用 broker：

```
http://127.0.0.1:21463/health
http://127.0.0.1:21463/api/health
http://127.0.0.1:21463/api/instances
http://127.0.0.1:21463/api/sessions
```

每个 x64dbg 插件实例也会启动一个 HTTP server，并在临时目录写入实例文件：

```
%TEMP%\x64dbg-mcp\instances\<x64dbg_pid>.json
```

文件中包含 `pid`、`port`、`url`、`state` 和 `target_hint`。打开文件或 attach 进程后，插件会向 broker 注册 active session；stop/detach 后注销 session。Broker 会分配 alias，例如 `A`、`B`，并支持：

```
POST http://127.0.0.1:21463/A/rpc
```

如果只打开一个 x64dbg 实例，Python MCP server 会自动连接。如果同时打开多个实例，需要在 MCP 配置中指定目标：

```json
{
  "env": {
    "X64DBG_MCP_PORT": "21464"
  }
}
```

也可以直接指定完整 URL：

```json
{
  "env": {
    "X64DBG_MCP_URL": "http://127.0.0.1:21464"
  }
}
```

## 工具列表 (45)

### 内存操作
| 工具 | 说明 |
|------|------|
| `memory_read` | 读内存（返回十六进制） |
| `memory_write` | 写十六进制数据到内存 |
| `memory_map` | 获取虚拟内存映射 |

### 反汇编/汇编
| 工具 | 说明 |
|------|------|
| `disassemble` | 按数量或终止地址反汇编，返回机器码字节、符号名和可直接阅读的 `text` |
| `assemble` | 将汇编指令写入地址 |

### 寄存器
| 工具 | 说明 |
|------|------|
| `registers_get` | 读取全部寄存器（含段/DR/XMM/RFLAGS），支持单寄存器查询 |
| `register_set` | 设置寄存器值 |
| `set_eip` | 设置指令指针 (EIP/RIP) |

### 断点
| 工具 | 说明 |
|------|------|
| `breakpoint_set` | 设断点（普通/硬件/内存），支持硬件类型 |
| `breakpoint_delete` | 删除断点 |
| `breakpoint_toggle` | 切换断点启用/禁用 |
| `breakpoints_list` | 列出所有断点，包含条件、命中次数、日志/命令文本等扩展字段 |
| `set_bp_filter` | 设置 x64dbg 原生条件断点表达式 |
| `breakpoint_condition_get` | 读取断点当前条件 |
| `breakpoint_condition_set` | 设置断点条件 |
| `breakpoint_condition_append` | 追加一个或多个断点条件 |
| `breakpoint_condition_clear` | 清空断点条件 |
| `run_to` | 设临时一次性断点并运行到该地址 |

### 调试控制
| 工具 | 说明 |
|------|------|
| `debug_run` | 运行/继续 |
| `debug_pause` | 暂停 |
| `debug_stop` | 停止调试 |
| `debug_step_in` | 单步进入 |
| `debug_step_over` | 单步跳过 |
| `debug_step_out` | 跳出当前函数 |
| `debug_get_state` | 获取调试状态（运行/暂停/停止） |

### 模块与符号
| 工具 | 说明 |
|------|------|
| `modules_get` | 列出已加载模块及基址 |
| `module_info` | 获取模块名称、路径、大小 |
| `symbols_get` | 枚举模块的 PDB 调试符号、导入/导出 |
| `imports_list` | 列出指定模块的所有导入函数 (IAT) |
| `exports_list` | 列出指定模块的所有导出函数 (EAT) |

### 栈与线程
| 工具 | 说明 |
|------|------|
| `call_stack` | 获取调用栈 |
| `threads_get` | 列出所有线程及详细信息 |

### 搜索
| 工具 | 说明 |
|------|------|
| `find_string` | 模糊搜索字符串（自动处理空格/标点差异） |
| `find_bytes` | 搜索十六进制字节模式 |
| `get_xrefs` | 查询交叉引用（谁引用了该地址） |

### 信息
| 工具 | 说明 |
|------|------|
| `evaluate` | 求值 x64dbg 表达式 |
| `string_read` | 读取地址处的字符串（自动检测 UTF-16LE/ASCII/UTF-8） |
| `label_get` / `label_set` | 获取/设置单个标签 |
| `labels_list` | 列出所有用户自定义标签 |
| `comment_get` / `comment_set` | 获取/设置单个注释 |
| `comments_list` | 列出所有用户自定义注释 |
| `get_function_info` | 获取函数边界（起始/结束地址） |
| `cmd_exec` | 直接执行 x64dbg 控制台命令 |

## 条件断点

```
# 只有 RCX 等于目标值时才停下
breakpoint_set addr="0x7FFC91037160"
set_bp_filter addr="0x7FFC91037160" condition="rcx==0x1234"

# 等价的新接口，推荐用于条件断点生命周期管理
breakpoint_condition_set addr="0x7FFC91037160" condition="rcx==0x1234"
breakpoint_condition_get addr="0x7FFC91037160"

# 只有 RCX 指向内存的首字节是 'M' 时才停下
set_bp_filter addr="0x7FFC91037160" condition="byte:[rcx]==0x4D"

# 只有 RDX+8 指向的 qword 非零时才停下
set_bp_filter addr="0x7FFC91037160" condition="qword:[rdx+8]!=0"

# 多个条件全部成立时才停下，最终写入 ((rcx!=0)&&(rdx!=0)&&(byte:[rcx]==0x4D))
set_bp_filter addr="0x7FFC91037160" conditions='["rcx!=0","rdx!=0","byte:[rcx]==0x4D"]' op="and"

# 多个条件任一成立时停下
set_bp_filter addr="0x7FFC91037160" conditions='["rcx==0x1234","rdx==0x5678"]' op="or"

# 在已有条件后追加条件，默认用 and 拼接
breakpoint_condition_append addr="0x7FFC91037160" condition="r8!=0"

# 清空条件
breakpoint_condition_clear addr="0x7FFC91037160"
```

`set_bp_filter` 作为兼容入口保留；推荐新代码使用 `breakpoint_condition_set/get/append/clear`。设置和追加时可以传单个 `condition`，也可以传 `conditions` 数组并用 `op="and"` 或 `op="or"` 拼成一个表达式。表达式结果非 0 时停下，结果为 0 时由 x64dbg 自己继续执行。条件可引用寄存器、内存、算术表达式和 x64dbg 支持的表达式函数。

## 设计要点

- **全链路十六进制字符串**——无 JSON 整数传递，任意 MCP 客户端（JavaScript / Python / C++）零精度丢失
- **C 插件 + localhost HTTP**——支持多个 x64dbg 实例按端口区分，直接访问 x64dbg Bridge API
- **Broker health 页面**——`/health` 返回可视化 HTML，`/api/health` 返回 watchdog 使用的 JSON
- **插件 watchdog**——C 插件定期检查 broker，不可用时尝试重启，连续失败后弹窗提醒
- **Python MCP stdio 服务端**——标准 MCP 协议，兼容所有 MCP 客户端
- **自动检测编码**——`string_read` 自动识别 UTF-16LE / ASCII / UTF-8

## 依赖

- Windows 10/11 x64
- x64dbg（2024 及以后版本）
- Python 3.10+，安装 `mcp`
- Visual Studio 2022 Build Tools（编译插件用）
