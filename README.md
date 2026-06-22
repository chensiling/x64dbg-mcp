# x64dbg-mcp

x64dbg 的 MCP 服务端——让 AI 助手（Claude、Cursor、VS Code 等）直接控制 Windows 调试器。

## 架构

```
AI 助手 (MCP 客户端)
    │  stdio (JSON-RPC, 十六进制字符串)
    ▼
Python MCP 服务端 (mcp 库)
    │  命名管道 (十六进制字符串)
    ▼
C 桥接插件 (x64dbg .dp64 DLL)
    │  x64dbg Bridge API
    ▼
x64dbg 调试引擎
```

全链路十六进制字符串传递，任意 MCP 客户端零精度丢失。

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
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### 2. 安装 Python 依赖

```bash
pip install mcp pywin32
```

或用 requirements.txt 一键安装：

```bash
cd C:\path\to\x64dbg-mcp\mcp-server
pip install -r requirements.txt
```

依赖清单 (`requirements.txt`)：

```
mcp>=1.0.0
pywin32>=306
```

### 3. 部署插件

将 `mcp_bridge.dp64` 复制到 x64dbg 的插件目录：

```
C:\path\to\x64dbg\release\x64\plugins\mcp_bridge.dp64
```

重启 x64dbg，插件自动加载并弹出控制台窗口。

### 4. 配置 MCP 客户端

在 MCP 客户端配置中添加：

```json
{
  "mcpServers": {
    "x64dbg": {
      "type": "local",
      "command": ["python", "mcp-server\\server.py"],
      "cwd": "C:\\path\\to\\x64dbg-mcp",
      "enabled": true
    }
  }
}
```

### 5. 使用

1. 启动 x64dbg，载入调试目标
2. 连接 MCP 客户端——桥接插件会自动弹控制台窗口，显示连接状态
3. 通过 AI 控制调试器

## 工具列表 (37)

### 内存操作
| 工具 | 说明 |
|------|------|
| `memory_read` | 读内存（返回十六进制） |
| `memory_write` | 写十六进制数据到内存 |
| `memory_map` | 获取虚拟内存映射 |

### 反汇编/汇编
| 工具 | 说明 |
|------|------|
| `disassemble` | 按数量或终止地址反汇编 |
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
| `breakpoint_set` | 设断点（普通/硬件/内存），支持条件和硬件类型 |
| `breakpoint_delete` | 删除断点 |
| `breakpoint_toggle` | 切换断点启用/禁用 |
| `breakpoints_list` | 列出所有断点 |
| `set_bp_filter` | 设置文件名过滤——不匹配则自动跳过（大小写不敏感） |
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
| `symbols_get` | 枚举模块的导出/导入符号 |

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
| `label_get` / `label_set` | 获取/设置标签 |
| `comment_get` / `comment_set` | 获取/设置注释 |
| `get_function_info` | 获取函数边界（起始/结束地址） |
| `cmd_exec` | 直接执行 x64dbg 控制台命令 |

## 条件断点自动过滤

```
# 只有文件名包含 "Test1.txt" 时才停下
breakpoint_set addr="0x7FFC91037160"                      # 在 CreateFileW 设断点
set_bp_filter addr="0x7FFC91037160" filename="Test1.txt"   # 不匹配则自动 F9
```

桥接插件拦截断点命中事件，读取 RCX 指向的文件名参数，将 UTF-16LE 转为 UTF-8 后比对。不匹配自动继续运行，零人工干预。

## 设计要点

- **全链路十六进制字符串**——无 JSON 整数传递，任意 MCP 客户端（JavaScript / Python / C++）零精度丢失
- **C 插件 + 命名管道**——开销最小，直接访问 x64dbg Bridge API
- **Python MCP stdio 服务端**——标准 MCP 协议，兼容所有 MCP 客户端
- **自动检测编码**——`string_read` 自动识别 UTF-16LE / ASCII / UTF-8

## 依赖

- Windows 10/11 x64
- x64dbg（2024 及以后版本）
- Python 3.10+，安装 `mcp` 和 `pywin32`
- Visual Studio 2022 Build Tools（编译插件用）
