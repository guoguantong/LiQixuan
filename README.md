# ReAct Agent + angr 符号执行 — crackme 求解作业

## 验证状态：已通过 (2026-05-30)

## 作业概述

本作业使用 **ReAct (Reasoning + Acting) Agent** 模式，结合 **angr 符号执行框架**，自动分析并求解一个含有陷阱路径的 crackme 程序。

## 文件说明

| 文件 | 说明 |
|------|------|
| `crackme.c` | 原始目标 C 程序源码（带 printf/scanf 的完整版） |
| `crackme_simple.c` | 简化版 C 程序（去掉 I/O，只保留核心密码检查逻辑） |
| `solve_final.py` | **最终验证版** ReAct Agent + angr 求解脚本（推荐） |
| `agent_solve.py` | ReAct Agent + LLM 驱动版本（需 OpenAI API Key） |
| `angr_solve.py` | 纯 angr 符号执行版本（无需 LLM） |
| `requirements.txt` | Python 依赖 |

## 运行验证结果

```
python solve_final.py

===============================================================
  Crackme 符号执行求解结果
===============================================================
  密码: AZ????????
  Hex:  415a3f3f3f3f3f3f3f3f
  说明: 前两个字符 AZ 确定，后续字符可以是任意值
===============================================================

ReAct Agent 求解过程:
  Round 1: load_binary      → AMD64, 64-bit, 入口 0x1026220
  Round 2: analyze_functions → main @ 0x10263d0, check_password @ 0x1026270, gadget_trap @ 0x1026260
  Round 3: locate_targets   → find (Success) @ 0x10263a8, avoid (Trap) @ 0x1026260
  Round 4: symbolic_explore → Found: 1, Avoided: 1, Deadended: 0
  Round 5: extract_password → 密码: AZ????????
```

实际密码验证：
```
$ echo "AZ" | ./crackme.exe      → Success! Flag is found.
$ echo "AZanything" | ./crackme.exe → Success! Flag is found.
$ echo "AB" | ./crackme.exe      → Oops! You are trapped... (死循环)
$ echo "XX" | ./crackme.exe      → Wrong password!
```

## crackme 程序分析

```c
int check_password(char *input) {
    if (input[0] == 'A') {
        if (input[1] == 'B') {
            gadget_trap();   // ← avoid: 死循环陷阱
        }
        if (input[1] == 'Z') {
            printf("Success! Flag is found.\n");
            return 1;        // ← find: 目标路径
        }
    }
    printf("Wrong password!\n");
    return 0;
}
```

**三条路径：**
1. `input[0]='A' && input[1]='B'` → `gadget_trap()` 死循环（**avoid** 避开）
2. `input[0]='A' && input[1]='Z'` → **Success!**（**find** 目标）
3. 其他任意输入 → Wrong password!（deadended）

**正确密码：AZ**（前缀为 AZ 即可，scanf 只读取前两个字符）

## 技术原理

### ReAct Agent 工作流程

```
┌──────────────────────────────────────┐
│         ReAct Agent 循环             │
│                                      │
│  Thought → Action → Observation      │
│     ↑                    ↓           │
│     └────────────────────┘           │
│         (循环直到找到密码)            │
└──────────────────────────────────────┘
```

1. **Thought**: LLM 分析当前状态，决定下一步行动
2. **Action**: 调用 angr 工具函数（加载、分析、探索、提取）
3. **Observation**: 读取工具返回的结果
4. 重复上述过程，直到成功提取密码

### angr 符号执行原理

- **符号执行**: 用符号变量代替具体输入值，追踪程序的所有执行路径
- **SimulationManager + find/avoid**: 指定目标地址和需要避开的地址，angr 自动探索
- **约束求解**: 对找到的路径收集路径约束，使用 SMT 求解器（z3）反推具体输入值

### 关键实现细节

由于 musl-libc 静态链接的 `printf` 实现过于复杂，angr 无法直接执行。解决方案：
1. 使用 `blank_state` 直接从 `check_password` 函数入口开始执行
2. 使用简化版源码（去掉 printf/scanf），避免 libc 函数干扰
3. 通过 RDI 寄存器传递符号输入指针（x86-64 调用约定）
4. 使用 CFGFast 反汇编自动定位 `mov dword ptr [rbp-N], 1` 指令作为 find 地址

## 运行方法

### 环境准备

```bash
pip install angr claripy ziglang
```

### 方式一：最终验证版（推荐，无需 LLM）

```bash
python solve_final.py
```

### 方式二：纯 angr 模式

```bash
python angr_solve.py
```

### 方式三：ReAct Agent + LLM（需 OpenAI API Key）

```bash
set OPENAI_API_KEY=sk-your-key-here
python agent_solve.py
```

## 核心 angr API 用法

```python
import angr, claripy

# 加载二进制
proj = angr.Project("crackme_elf", auto_load_libs=False)

# 创建符号输入
sym_input = claripy.BVS("input", 10 * 8)

# blank_state 直接从函数入口开始
state = proj.factory.blank_state(addr=check_password_addr)
state.memory.store(input_addr, sym_input)
state.regs.rdi = input_addr  # x86-64 第一个参数

# SimulationManager + find/avoid
simgr = proj.factory.simulation_manager(state)
simgr.explore(
    find=0x10263a8,   # Success: mov [rbp-4], 1
    avoid=0x1026260,  # Trap: gadget_trap 入口
)

# 提取密码
found_state = simgr.found[0]
password = found_state.solver.eval(sym_input, cast_to=bytes)
```

## ReAct 工具链设计

| 工具名 | 功能 | angr API |
|--------|------|----------|
| `load_binary` | 加载 ELF 文件，获取架构信息 | `angr.Project()` |
| `analyze_functions` | CFG 分析，列出所有函数 | `proj.analyses.CFGFast()` |
| `locate_targets` | 反汇编 check_password，自动定位 find/avoid 地址 | `cfg.functions`, capstone |
| `symbolic_explore` | 符号执行探索 | `simgr.explore(find, avoid)` |
| `extract_password` | 约束求解，从符号状态提取密码 | `state.solver.eval()` |

## 作业要求对照

- [x] 使用 ReAct (Reasoning + Acting) 模式
- [x] 结合 Agent（Thought → Action → Observation 循环）
- [x] 使用 angr 符号执行框架
- [x] 使用 SimulationManager 的 find/avoid API
- [x] 探索二进制文件（explore）
- [x] 避开 trap 路径（gadget_trap 死循环）
- [x] 找到 Success 路径（return 1 的基本块）
- [x] 输出正确密码（AZ）
