# ReAct Agent 二进制静态漏洞挖掘实验

## 基本信息

| 项目 | 内容 |
|------|------|
| **学号** | 25140931 |
| **姓名** | 李琪轩 |
| **模型** | deepseek-chat（via langchain Tool Calling） |
| **日期** | 2026-06-06 |
| **分析对象** | targets/challenge（Linux x86_64，已 strip，无源码） |
| **分析方式** | 纯静态分析，不涉及 exploit 与动态验证 |

## 实验目标

实现 ReAct 智能体：LLM 负责编排，radare2 与 Ghidra 作为可调用工具，
对 `targets/challenge`（黑盒 ELF）做静态分析，由 Agent 给出漏洞结论。

## 工具设计

### r2 工具（3 个）

| 工具名 | 功能 | 核心 r2 命令 |
|--------|------|-------------|
| `r2_analyze_binary` | 加载二进制，执行 aaa 分析，列出所有函数 | `ie`, `ii`, `aaa`, `afl`, `pdf @ entry0` |
| `r2_disassemble_function` | 反汇编指定函数，搜索危险调用 | `pdf @ addr`, `/c strcpy\|gets\|...` |
| `r2_analyze_xrefs_and_sinks` | 交叉引用分析，追踪危险 Sink 调用链 | `axt`, `izz` |

### Ghidra 工具（2 个）

| 工具名 | 功能 | 核心 Ghidra API |
|--------|------|----------------|
| `ghidra_decompile_function` | 反编译指定函数为伪 C 代码 | `DecompInterface.decompileFunction()` |
| `ghidra_analyze_binary` | 完整分析所有函数并标记安全发现 | 全函数反编译 + 安全摘要 |

### ReAct 循环

```
Thought → Action (Tool Calling) → Observation
   ↑                                    ↓
   └────────────────────────────────────┘
              (循环 6 轮直到得出漏洞结论)
```

每轮由 LLM 推理当前状态（Thought），调用 r2 或 Ghidra 工具（Action），
解析返回结果（Observation），形成完整的感知-决策-执行闭环。

观察仅来自工具返回，不依赖任何先验知识或手工标注。

## 漏洞分析结论

通过对 `targets/challenge` 的 6 轮 ReAct 分析（r2 × 3，Ghidra × 3），
发现以下漏洞：

### 漏洞详情

- **漏洞类型**：栈缓冲区溢出（stack_buffer_overflow）
- **Sink 位置**：main 函数偏移 0x401382 处的 `__strcpy_chk` 调用
- **数据流**：`stdin → fgets(128) → 用户输入缓冲区 → strlen 长度检查（≤100）→ __strcpy_chk(dst=rsp, src=input, dest_size=16)`

### 成因分析

`main` 函数在栈上分配了 160 字节（`sub rsp, 0xa0`），通过 `fgets` 从 stdin
读取最多 128 字节用户输入，经 `strcspn` 去除换行符后，仅做 `strlen ≤ 100`
的长度检查便传入 `__strcpy_chk`。但 `__strcpy_chk` 的第三参数 `dest_size` 被设为
`0x10`（16 字节），与实际栈帧 160 字节严重不匹配：

1. 若 FORTIFY_SOURCE 禁用：`strcpy` 无界复制导致栈缓冲区溢出，覆盖返回地址
2. 若 FORTIFY_SOURCE 启用：输入超过 16 字节触发 `__chk_fail`，程序异常终止（DoS）

### 程序行为

程序运行后打印 `[boot] profile-service ready` 和 `[selftest] selftest-payload-ok`，
然后等待 stdin 输入。输入 ≤16 字节正常退出，输入 17–100 字节触发漏洞。

## 运行方法

### 环境准备

```bash
pip install -r requirements.txt
```

### r2 安装（Linux）

```bash
sudo apt install radare2
# 或: git clone https://github.com/radareorg/radare2 && cd radare2 && sys/install.sh
```

### Ghidra 安装

从 https://github.com/NationalSecurityAgency/ghidra/releases 下载，
解压到 `/opt/ghidra`（Linux）或 `C:\ghidra`（Windows），
确保 `analyzeHeadless`（或 `analyzeHeadless.bat`）在 PATH 中。

### 运行 Agent

```bash
python agent.py
```

输出：
- `vuln.json` — 结构化漏洞结论（固定字段）
- `logs/run.txt` — 完整 ReAct 交互日志

如未安装 r2/Ghidra，Agent 自动进入 demo 模式，使用
capstone + pyelftools 预计算的分析结果，展示完整 ReAct 过程。

## 思考题

**Q: LLM 在本实验中主要承担什么角色？它如何借助语义与常识，
缓解纯静态分析在搜索空间上的困难？**

**A:** LLM 承担「决策与编排层」角色。面对已 strip 的黑盒 ELF，
纯工具可输出海量汇编和反编译代码，但缺乏语义理解能力筛选关键信息。
LLM 通过理解函数调用模式（`fgets → strlen → __strcpy_chk`）、
识别危险函数名（strcpy/fgets），以及对比参数与实际栈帧大小，
能在 6 轮内从 10 个函数中精确定位 main 函数的漏洞点。
此外，LLM 能根据观察结果调整策略——例如发现辅助函数
`__snprintf_chk` 参数正确后，排除误报、聚焦真正的 Sink。
这种「语义引导 + 工具验证」的闭环，将本来需要人工逆向
工程师数十分钟的分析压缩到分钟级完成。

## 输出文件

| 文件 | 说明 |
|------|------|
| `vuln.json` | 漏洞结论，固定字段 vuln_type / location / cause |
| `logs/run.txt` | 完整 ReAct 日志，含 6 轮 Thought→Action→Observation |
| `agent.py` | Agent 源码，一键运行 |
| `requirements.txt` | Python 依赖列表 |
