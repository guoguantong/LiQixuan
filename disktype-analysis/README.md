# ReAct Agent — disktype (MIPS 32-bit) 二进制静态漏洞挖掘

## 基本信息

| 项目 | 内容 |
|------|------|
| **学号** | 25140931 |
| **姓名** | 李琪轩 |
| **模型** | deepseek-chat（via langchain Tool Calling） |
| **日期** | 2026-06-22 |
| **分析对象** | disktype（MIPS 32-bit LSB ELF，uClibc 动态链接，已 strip） |
| **分析方式** | 纯静态分析，capstone + pyelftools（不涉及动态验证） |

## 实验目标

照搬 `react-agent-lab` 分支的 ReAct Agent 方法论，对跨架构（MIPS 32-bit）的
`disktype` 磁盘格式检测工具做静态漏洞挖掘。核心挑战：

1. **架构迁移**：从 x86_64 切换到 MIPS 32-bit
2. **工具链降级**：Windows 环境下 MIPS 工具链（r2/Ghidra）不可用，改用 capstone + pyelftools
3. **规模扩大**：目标从 10 个函数扩大到 98 个导出函数（含 60+ detect_* 格式检测函数）

Agent 通过 ReAct (Thought -> Action -> Observation) 闭环运行 5 轮。

## 工具设计

| 工具名 | 功能 | 核心 API |
|--------|------|---------|
| r2_analyze_binary | 加载 ELF，解析动态符号表 | pyelftools .dynsym |
| r2_disassemble_function | 反汇编指定函数（MIPS） | capstone CS_ARCH_MIPS |
| r2_analyze_xrefs_and_sinks | 追踪危险函数调用 | 静态代码审查 |
| ghidra_analyze_binary | 综合分析所有 detect_* 函数 | 全量静态审查 |

## 漏洞分析结论

### 漏洞 1 [HIGH]: get_buffer_real 整数溢出 -> 堆越界
- **位置**: get_buffer_real (0x4047cc)
- **关键指令**: 0x4048ec-0x4048f8，64位加法 total = offset + size 无溢出检查

### 漏洞 2 [HIGH]: detect_compressed 命令注入 -> RCE
- **位置**: detect_compressed (0x408950)
- **成因**: fork + pipe + dup2 + execlp，参数来自磁盘数据

### 漏洞 3 [MEDIUM]: error/bailout 4096 字节栈缓冲区
- **位置**: 0x4043f0-0x404620，四个函数均分配 4136 字节栈帧

### 漏洞 4 [MEDIUM]: get_string 无边界读取
- **位置**: get_string (0x404098)

### 漏洞 5 [MEDIUM]: detect_* 固定大小栈缓冲区
- detect_apple_volume (936B), detect_solaris_disklabel (752B), detect_iso (624B) 等

### 漏洞 6 [LOW]: 格式字符串 %s 无宽度限制

## 思考题

LLM 承担「决策与编排层」角色：通过函数名语义推断函数角色、
识别 fork+execlp 的进程创建模式、利用栈帧大小启发式定位格式化缓冲区，
将 98 个函数的审查范围缩小到约 15 个关键函数。

## 运行方法

```bash
pip install -r requirements.txt
python analyze_disktype.py
```

## 输出文件

| 文件 | 说明 |
|------|------|
| vuln_disktype.json | 漏洞结论 |
| logs/run.txt | 完整 ReAct 日志（5 轮） |
| analyze_disktype.py | Agent 源码 |
| requirements.txt | Python 依赖 |
