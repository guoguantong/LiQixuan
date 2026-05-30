# ReAct Agent + angr 符号执行 — 自动化逆向分析

## 验证状态：已通过 (2026-05-30)

基于 agent-lab(3).pdf 要求，使用 **langchain Tool Calling** 封装 angr 工具，
通过 **ReAct (Thought → Action → Observation)** 闭环求解 crackme 密码。

## 文件说明

| 文件 | 说明 |
|------|------|
| `crackme.c` | 目标 C 程序（来自 PDF：4 位密码，含 XOR/加法约束） |
| `crackme_simple.c` | 简化版（去掉 strlen/printf/scanf，供 angr 分析） |
| `solve_final.py` | **主程序**：langchain 工具定义 + ReAct Agent + angr 符号执行 |
| `requirements.txt` | Python 依赖 |

## 运行验证结果

```
python solve_final.py

=================================================================
  ReAct Agent 求解过程演示 (离线演示模式)
=================================================================

--- Round 1 ---
Thought: 第一步需要加载 crackme 二进制文件，运行 CFG 分析获取所有函数的地址。
          重点关注 check_password（密码验证）和 gadget_trap（死循环陷阱）。
Action:  analyze_binary
Observation:
二进制加载成功: crackme_simple_elf
  架构: AMD64
  位数: 64-bit
  入口: 0x1026250

关键函数地址 (符号表):
  0x10262a0: check_password  ← 密码验证函数
  0x1026290: gadget_trap      ← 死循环陷阱

--- Round 2 ---
Thought: 已获取 check_password 和 gadget_trap 的地址。现在需要反汇编
          check_password 函数，找到 Success 路径（return 1）对应的基本块
          地址作为 find 目标，gadget_trap 地址作为 avoid 目标。
Action:  locate_success_address
Observation:
check_password 反汇编分析完成
  find  (Success): 0x1026702
  avoid (Trap):    0x1026290

check_password 基本块 (共 51 个):
  0x10262a0: push rbp ; mov rbp, rsp ; sub rsp, 0xd0 ...
  0x10262d0: ... cmp eax, 0 ; je 0x102644b        ← 检查 input[0] != '\0'
  0x102634b: ... cmp eax, 0 ; je 0x102644b        ← 检查 input[1] != '\0'
  0x10263c7: ... cmp eax, 0 ; je 0x102644b        ← 检查 input[2] != '\0'
  0x102643f: ... cmp eax, 0 ; jne 0x1026457       ← 检查 input[3] != '\0'
  0x1026478: ... cmp eax, 0x41 ; jne 0x1026711    ← 检查 input[0] == 'A'
  0x10264f3: ... cmp eax, 0x42 ; jne 0x102650c    ← 检查 input[1] == 'B'
  0x10264ff: call 0x1026290                        ← gadget_trap()!
  0x102658c: ... cmp eax, 0x5a ; jne 0x102670f    ← 检查 input[1] == 'Z'
  0x1026620: ... xor eax, 0x12 ; cmp eax, 0x71    ← 检查 (input[2]^0x12)=='q'
  0x10266f7: ... cmp eax, 0x48 ; jne 0x102670b    ← 检查 (input[3]+3)=='H'
  0x1026702: mov dword ptr [rbp-4], 1             ← FIND (Success!)
  0x1026711: mov dword ptr [rbp-4], 0 ; ... ret   ← return 0 (Wrong)

--- Round 3 ---
Thought: 已确定 find 和 avoid 地址。现在使用 angr SimulationManager.explore
          执行符号执行：用 blank_state 从 check_password 入口开始，将符号输入
          通过 RDI 传递，约束为可打印 ASCII，通过 find/avoid 避开陷阱路径。
Action:  symbolic_explore_and_extract
Observation:
符号执行成功！
  Found 状态数: 1
  Avoided 状态数: 1
  Active 状态数: 1
  Deadended 状态数: 0

密码提取结果: AZcE??????
  Hex: 415a63453f3f3f3f3f3f
  有效载荷 (前4字符): AZcE

=================================================================
  >>> 最终验证结果 <<<
=================================================================
  Agent 通过符号执行求解的密码: AZcE
  密码推导:
    input[0] = 'A'
    input[1] = 'Z'
    input[2] = chr(ord('q') ^ 0x12) = chr(0x63) = 'c'
    input[3] = chr(ord('H') - 3)  = chr(0x45) = 'E'

  实际运行 crackme_verify.exe 的输出:
  *** Enter password: Success! Flag is found. ***

=================================================================
  路径全覆盖验证
=================================================================
  echo AZcE | crackme_verify.exe  → 预期 Success
    实际: Enter password: Success! Flag is found.
  echo ABxx | crackme_verify.exe  → 预期 Trap (死循环)
    实际: (超时 — 陷入死循环)
  echo XXXX | crackme_verify.exe  → 预期 Wrong password
    实际: Enter password: Wrong password!
  echo AZ   | crackme_verify.exe  → 预期 Wrong password (长度 < 4)
    实际: Enter password: Wrong password!
```

## crackme 程序分析

```c
int check_password(char *input) {
    if (strlen(input) < 4) { puts("Wrong password!"); return 0; }
    if (input[0] == 'A') {
        if (input[1] == 'B') {
            gadget_trap();    // ← avoid: 死循环陷阱
        }
        if (input[1] == 'Z') {
            if ((input[2] ^ 0x12) == 'q') {    // input[2] = 'q' ^ 0x12 = 'c'
                if ((input[3] + 3) == 'H') {    // input[3] = 'H' - 3 = 'E'
                    puts("Success! Flag is found.");
                    return 1;                   // ← find: 目标路径
                }
            }
        }
    }
    puts("Wrong password!");
    return 0;
}
```

**密码约束推导：**
- `input[0] == 'A'` → `A`
- `input[1] == 'Z'` → `Z`
- `(input[2] ^ 0x12) == 'q'` → `chr(0x71 ^ 0x12)` = `chr(0x63)` = `c`
- `(input[3] + 3) == 'H'` → `chr(72 - 3)` = `chr(69)` = `E`

**正确密码：AZcE**

**四条路径：**
1. `ABxx` → `gadget_trap()` 死循环（**avoid** 避开）
2. `AZcE` → `Success! Flag is found.`（**find** 目标）
3. 长度 < 4 → `Wrong password!`
4. 其他任意输入 → `Wrong password!`

## 技术原理

### ReAct Agent 工作流程

```
┌──────────────────────────────────────────────────┐
│              ReAct Agent 循环                     │
│                                                   │
│   Thought → Action (Tool Calling) → Observation   │
│      ↑                                  ↓         │
│      └──────────────────────────────────┘         │
│              (循环直到找到密码)                     │
└──────────────────────────────────────────────────┘
```

每轮由 LLM 推理当前状态（Thought），调用 angr 工具（Action），
解析返回结果（Observation），形成完整的感知-决策-执行闭环。

### angr 符号执行原理

- **符号变量 (Symbolic Input)**: 用 `claripy.BVS` 创建符号输入替代具体值
- **blank_state**: 直接从 `check_password` 入口开始，避免 libc 函数路径爆炸
- **SimulationManager.explore(find, avoid)**: 指定目标地址和避开地址，自动探索
- **约束求解**: 对成功路径收集的约束（XOR、加法等）通过 z3 求解器反推具体密码

### LangChain Tool Calling 集成

```python
from langchain_core.tools import tool

@tool
def analyze_binary(binary_path: str) -> str:
    """加载 crackme 二进制文件，执行 CFG 分析。"""

@tool
def locate_success_address(binary_path: str) -> str:
    """反汇编 check_password，定位 Success 路径地址。"""

@tool
def symbolic_explore_and_extract(_dummy: str = "") -> str:
    """符号执行 + 约束求解，提取密码。"""
```

## ReAct 工具链设计

| 工具名 | 功能 | 核心 angr API |
|--------|------|--------------|
| `analyze_binary` | 加载 ELF，通过符号表定位关键函数 | `angr.Project()`, `loader.find_symbol()` |
| `locate_success_address` | CFG 分析 + capstone 反汇编，自动定位 find/avoid | `CFGFast()`, `factory.block()`, capstone |
| `symbolic_explore_and_extract` | 符号执行 explore + 约束求解提取密码 | `simgr.explore(find, avoid)`, `solver.eval()` |

## 运行方法

### 环境准备

```bash
pip install -r requirements.txt
```

### 离线演示模式（无需 API Key）

```bash
python solve_final.py
```

演示完整的 ReAct 过程（预录 LLM 推理 + 真实 angr 工具调用）。

### LLM 模式（需 OpenAI API Key）

```bash
set OPENAI_API_KEY=sk-your-key-here
python solve_final.py
```

使用 langchain ChatOpenAI + Tool Calling，真实 LLM 驱动 ReAct 循环。

## 思考题

**Q: LLM 在本实验中主要承担什么角色？它如何借助语义与常识，缓解纯符号执行在搜索空间上的困难？**

**A:** LLM 承担「决策与编排层」角色。它理解 crackme 的语义结构（密码检查逻辑、
陷阱路径），并能据此指定 find/avoid 地址。纯符号执行若无引导，会在 strlen、scanf
等 libc 函数内部遇到路径爆炸；LLM 通过语义理解直接定位关键函数（check_password、
gadget_trap），将探索范围缩小到几十个基本块内，从而高效求解。
此外，LLM 能根据观察结果调整策略（如重新选择 find 地址），形成闭环优化。

## 作业要求对照

- [x] angr 工具封装（3 个 @tool：analyze_binary, locate_success_address, symbolic_explore_and_extract）
- [x] ReAct 主循环（Thought → Action → Observation 闭环）
- [x] 使用 langchain-core Tool Calling 协议
- [x] 不少于 3 轮完整的 ReAct 交互
- [x] 符号执行避开 gadget_trap 陷阱
- [x] 找到 Success 路径并求解出密码 AZcE
- [x] 实际运行 crackme 打印 Success! Flag is found.
- [x] 思考题回答
