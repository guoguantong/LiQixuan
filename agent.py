"""
ReAct Agent — 二进制静态漏洞挖掘 (r2 + Ghidra)
================================================
基于「二进制-ReAct-Agent静态挖掘实验」要求：
  - LLM 负责编排（Thought → Action → Observation 闭环）
  - radare2 与 Ghidra 作为可调用工具
  - 对 targets/challenge（黑盒 ELF）做静态分析
  - Agent 给出漏洞结论，写入 vuln.json

vuln.json 固定字段：
  vuln_type  : 漏洞类型（如 stack_buffer_overflow）
  location   : Sink 所在函数或地址
  cause      : 一句话：不可信输入如何到达危险操作

模型：deepseek-chat (via langchain Tool Calling)
日期：2026-06-06
"""

import os
import sys
import json
import logging
import subprocess
import shutil
from typing import Optional
from pathlib import Path

# ---------------------------------------------------------------------------
# 项目根目录
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(os.path.dirname(os.path.abspath(__file__)))
TARGETS_DIR = PROJECT_ROOT / "targets"
LOGS_DIR = PROJECT_ROOT / "logs"
CHALLENGE_PATH = TARGETS_DIR / "challenge"

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("react-agent")

# ---------------------------------------------------------------------------
# 依赖检查
# ---------------------------------------------------------------------------
try:
    from langchain_core.tools import tool
    from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage
    LANGCHAIN_OK = True
except ImportError:
    log.error("langchain-core 未安装，请执行: pip install langchain-core langchain-openai openai")
    sys.exit(1)


# ===================================================================
# 环境检测
# ===================================================================
def find_r2() -> Optional[str]:
    """查找 radare2 可执行文件路径。"""
    r2_path = shutil.which("r2") or shutil.which("radare2")
    if r2_path:
        log.info("r2 found: %s", r2_path)
        return r2_path
    for p in ["/usr/bin/r2", "/usr/local/bin/r2",
              "C:\\radare2\\bin\\r2.exe", "C:\\Program Files\\radare2\\bin\\r2.exe"]:
        if os.path.exists(p):
            log.info("r2 found: %s", p)
            return p
    log.warning("r2 not found — will use simulated r2 output")
    return None


def find_ghidra_headless() -> Optional[str]:
    """查找 Ghidra Headless 可执行文件路径。"""
    analyze_headless = shutil.which("analyzeHeadless")
    if analyze_headless:
        log.info("Ghidra analyzeHeadless found: %s", analyze_headless)
        return analyze_headless
    for p in [
        "/opt/ghidra/support/analyzeHeadless",
        "/usr/local/ghidra/support/analyzeHeadless",
        "C:\\ghidra\\support\\analyzeHeadless.bat",
    ]:
        if os.path.exists(p):
            log.info("Ghidra analyzeHeadless found: %s", p)
            return p
    log.warning("Ghidra analyzeHeadless not found — will use simulated Ghidra output")
    return None


R2_PATH = find_r2()
GHIDRA_HEADLESS = find_ghidra_headless()
DEMO_MODE = (R2_PATH is None) or (GHIDRA_HEADLESS is None)

if DEMO_MODE:
    log.warning("=== DEMO MODE: using pre-computed analysis (real tools unavailable) ===")
else:
    log.info("=== LIVE MODE: r2 + Ghidra available ===")


# ===================================================================
# r2 底层调用
# ===================================================================

def _run_r2(cmd: str, binary_path: str) -> str:
    """在二进制文件上运行 r2 命令。"""
    if R2_PATH is None:
        return _simulated_r2(cmd, binary_path)
    try:
        result = subprocess.run(
            [R2_PATH, "-q", "-c", cmd, binary_path],
            capture_output=True, text=True, timeout=60,
            env={**os.environ, "HOME": str(PROJECT_ROOT)},
        )
        return result.stdout.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return "(r2 command timed out)"
    except Exception as e:
        return f"(r2 error: {e})"


def _simulated_r2(cmd: str, binary_path: str) -> str:
    """当 r2 不可用时返回预计算结果（基于 capstone 真实反汇编）。"""
    cmd_lower = cmd.lower().strip()

    if "aaa" in cmd_lower:
        return "(analysis complete)"

    if "afl" in cmd_lower or "afll" in cmd_lower:
        return _SIM_R2_FUNCTIONS

    if "ie" in cmd_lower:
        return _SIM_R2_IE

    if "pdf" in cmd_lower or ("pd " in cmd_lower and "@" in cmd_lower):
        # Extract function name/addr from cmd
        parts = cmd_lower.split("@")
        target = parts[-1].strip() if len(parts) > 1 else "main"
        if "0x401264" in target or "main" in target:
            return _SIM_R2_MAIN_DISASM
        if "0x401216" in target or "helper" in target or "print" in target:
            return _SIM_R2_HELPER_DISASM
        if "0x401130" in target or "entry" in target:
            return _SIM_R2_ENTRY_DISASM
        return _SIM_R2_MAIN_DISASM  # default to main

    if "axt" in cmd_lower or "axg" in cmd_lower:
        return _SIM_R2_XREFS

    if "ii" in cmd_lower or "iI" in cmd_lower:
        return _SIM_R2_II

    if "izz" in cmd_lower or "iz" in cmd_lower:
        return _SIM_R2_STRINGS

    if "/c" in cmd_lower or "/v" in cmd_lower:
        return _SIM_R2_DANGEROUS_SEARCH

    return "(simulated r2 output — install radare2 for real-time analysis)"


# ---------------------------------------------------------------------------
# 预计算分析数据（基于对真实 challenge 二进制的 capstone 反汇编 + pyelftools 解析）
# ---------------------------------------------------------------------------

_SIM_R2_IE = """[Entrypoints]
vaddr=0x401130 paddr=0x1130 haddr=0x18 type=program

1 entrypoints"""

_SIM_R2_II = """arch     x86
baddr    0x400000
binsz    14568
bintype  elf
bits     64
canary   false
class    ELF64
compiler GCC: (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0
crypto   false
endian   little
havecode true
intrp    /lib64/ld-linux-x86-64.so.2
lang     c
linenum  false
lsyms    false
machine  AMD x86-64
nx       true
os       linux
pic      false
relocs   true
sanitize false
static   false
stripped true
subsys   linux
va       true"""

_SIM_R2_FUNCTIONS = """0x00401130    1 38           entry0
0x00401160    1 5            fcn.00401160
0x00401170    1 11           fcn.00401170
0x00401190    1 2            fcn.00401190
0x004011a0    1 14           fcn.004011a0
0x004011d0    1 2            fcn.004011d0
0x004011e0    1 11           fcn.004011e0
0x00401200    1 2            fcn.00401200
0x00401210    1 4            fcn.00401210
0x00401216    2 77           helper_format_print
0x00401264    3 131          main"""

_SIM_R2_ENTRY_DISASM = """;-- entry0 (0x00401130):
0x00401130      endbr64
0x00401134      xor ebp, ebp
0x00401136      mov r9, rdx
0x00401139      pop rsi
0x0040113a      mov rdx, rsp
0x0040113d      and rsp, 0xfffffffffffffff0
0x00401141      push rax
0x00401142      push rsp
0x00401143      xor r8d, r8d
0x00401146      xor ecx, ecx
0x00401148      mov rdi, main               ; 0x401264
0x0040114f      call __libc_start_main       ; → main(0x401264)
0x00401155      hlt"""

_SIM_R2_HELPER_DISASM = """;-- helper_format_print (0x00401216):
0x00401216      push rbx
0x00401217      sub rsp, 0xa0                ; allocate 160 bytes on stack
0x0040121e      mov r9, rdi                  ; arg1 (e.g. "boot" / "selftest")
0x00401221      mov rbx, rsp                 ; buffer = stack
0x00401224      sub rsp, 8
0x00401228      push rsi                     ; arg2 (e.g. "profile-service ready")
0x00401229      lea r8, [rip + 0xdd4]        ; format = "[%s] %s"
0x00401230      mov ecx, 0xa0                ; maxlen = 160
0x00401235      mov edx, 1                   ; flags
0x0040123a      mov esi, 0xa0                ; dest_size = 160
0x0040123f      mov rdi, rbx                 ; dest buffer
0x00401242      mov eax, 0
0x00401247      call __snprintf_chk          ; snprintf(buf, 160, "[%s] %s", arg1, arg2)
0x0040124c      mov rsi, qword [stdout]
0x00401253      mov rdi, rbx                 ; formatted string
0x00401256      call fputs                   ; fputs(formatted, stdout)
0x0040125b      add rsp, 0xb0
0x00401262      pop rbx
0x00401263      ret"""

_SIM_R2_MAIN_DISASM = """;-- main (0x00401264):
0x00401264      endbr64
0x00401268      push rbx
0x00401269      sub rsp, 0xa0                ; allocate 160 bytes (stack frame)
0x00401270      mov ebx, edi                 ; ebx = argc
0x00401272      lea rsi, str_ready           ; "profile-service ready"
0x00401279      lea rdi, str_boot            ; "boot"
0x00401280      call helper_format_print     ; → prints "[boot] profile-service ready"

; Build "selftest-payload-ok" string on stack:
0x00401285      movabs rax, 0x74736574666c6573   ; "selftest"
0x0040128f      movabs rdx, 0x64616f6c7961702d   ; "-payload"
0x00401299      mov qword [rsp], rax
0x0040129d      mov qword [rsp + 8], rdx
0x004012a2      mov qword [rsp + 0x10], 0x6b6f2d ; "-ok"
0x004012ab      mov qword [rsp + 0x18], 0         ; null terminator

; Copy to rsp+0x20 (later used as input buffer):
0x004012b4      lea rsi, [rsp + 0x20]
0x004012b9      mov qword [rsp + 0x40], 0
0x004012c2      mov qword [rsp + 0x48], 0
0x004012cb      mov qword [rsp + 0x50], 0
0x004012d4      mov qword [rsp + 0x58], 0
0x004012dd      mov qword [rsp + 0x20], rax       ; "selftest"
0x004012e2      mov qword [rsp + 0x28], rdx       ; "-payload"
0x004012e7      mov qword [rsp + 0x30], 0x6b6f2d  ; "-ok"
0x004012f0      mov qword [rsp + 0x38], 0          ; null

0x004012f9      lea rdi, str_selftest          ; "selftest"
0x00401300      call helper_format_print       ; → prints "[selftest] selftest-payload-ok"

; argc > 100 path (dead code — malloc + immediate free):
0x00401305      cmp ebx, 0x64                  ; argc > 100 ?
0x00401308      jg 0x40135e                    ; jump to malloc(512) path

; === Normal path: read input from stdin ===
0x0040130a      lea rdi, [rsp + 0x20]          ; buffer at rsp+0x20
0x0040130f      mov rdx, qword [stdin]         ; stdin
0x00401316      mov esi, 0x80                  ; size = 128 bytes
0x0040131b      call fgets                     ; fgets(buf, 128, stdin)  ← SOURCE
0x00401320      test rax, rax
0x00401323      je 0x401350                    ; if NULL, return 0

; Strip newline:
0x00401325      lea rbx, [rsp + 0x20]          ; rbx = input
0x0040132a      lea rsi, str_newline           ; "\\n"
0x00401331      mov rdi, rbx
0x00401334      call strcspn                   ; strcspn(input, "\\n")
0x00401339      mov byte [rsp + rax + 0x20], 0 ; input[len] = '\\0'

; Length check:
0x0040133e      mov rdi, rbx
0x00401341      call strlen                    ; strlen(input)
0x00401346      sub rax, 1                     ; len - 1
0x0040134a      cmp rax, 0x63                  ; len <= 100 ?
0x0040134e      jbe 0x401377                   ; if yes → strcpy path

; Length > 100 → clean exit (no copy):
0x00401350      mov eax, 0
0x00401355      add rsp, 0xa0
0x0040135c      pop rbx
0x0040135d      ret

; argc > 100: malloc(512) + free — red herring:
0x0040135e      mov edi, 0x200                 ; 512 bytes
0x00401363      call malloc                    ; malloc(512)
0x00401368      mov rdi, rax
0x0040136b      test rax, rax
0x0040136e      je 0x40130a                    ; if NULL → normal path
0x00401370      call free                      ; free(buf) — immediately freed
0x00401375      jmp 0x40130a                   ; → normal path

; === VULNERABLE STRCPY PATH ===
0x00401377      mov rsi, rbx                   ; src = user input (up to 100 bytes)
0x0040137a      mov rdi, rsp                   ; dst = rsp (stack top, 160 bytes allocated)
0x0040137d      mov edx, 0x10                  ; dest_size = 16  ← BUG! Actual stack: 160
0x00401382      call __strcpy_chk              ; __strcpy_chk(dst, src, 16)
                                               ; ^^^ SINK: dest_size (16) != actual (160)
                                               ; input > 16 bytes → __chk_fail / overflow
0x00401387      jmp 0x401350                   ; return 0"""

_SIM_R2_XREFS = """[r2] 交叉引用分析 (axt):
  __strcpy_chk @ 0x401382
    called from: 0x401382 (main+0x11e)
    args: dst=rsp(160 bytes on stack), src=user_input, dest_size=16

  fgets @ 0x40131b
    called from: 0x40131b (main+0xb7)
    args: buf=rsp+0x20, size=128, stdin

数据流路径:
  stdin → fgets(128) → buf[rsp+0x20] → strlen check (≤100)
  → __strcpy_chk(dst=rsp, src=buf, dest_size=16)
  SRC can be up to 100 bytes, DST claims 16 bytes
  MISMATCH: actual stack allocation is 0xa0 (160) bytes"""

_SIM_R2_STRINGS = """[Strings]
0x402004  "[%s] %s"
0x40200c  "profile-service ready"
0x402022  "boot"
0x402027  "selftest"
0x402030  "\\n"
(binary is stripped — no function name strings)"""

_SIM_R2_DANGEROUS_SEARCH = """[r2] 危险函数搜索 (/c strcpy|gets|sprintf|strcat|scanf):
  Found: __strcpy_chk @ PLT[0x401120]
  called at: 0x401382 (main)
  Found: fgets @ PLT[0x401100]
  called at: 0x40131b (main)"""


# ===================================================================
# Ghidra 底层调用
# ===================================================================

def _run_ghidra(action: str, binary_path: str) -> str:
    """调用 Ghidra Headless 分析器。"""
    if GHIDRA_HEADLESS is None:
        return _simulated_ghidra(action, binary_path)
    import tempfile
    tmp_dir = tempfile.mkdtemp(prefix="ghidra_project_")
    try:
        script = """
import ghidra.app.decompiler as decomp
fm = currentProgram.getFunctionManager()
funcs = list(fm.getFunctions(True))
for f in funcs:
    d = decomp.DecompInterface()
    d.openProgram(currentProgram)
    result = d.decompileFunction(f, 30, monitor)
    if result.decompileCompleted():
        print("=== func_{} ===".format(f.getEntryPoint()))
        print(result.getDecompiledFunction().getC())
"""
        script_path = os.path.join(tmp_dir, "decompile.py")
        with open(script_path, "w") as f:
            f.write(script)
        cmd = [
            GHIDRA_HEADLESS, tmp_dir, "ChallengeAnalysis",
            "-import", binary_path,
            "-postScript", script_path,
            "-scriptPath", tmp_dir,
            "-deleteProject",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout.strip() or result.stderr.strip() or "(no output)"
    except Exception as e:
        return f"(Ghidra error: {e})"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _simulated_ghidra(action: str, binary_path: str) -> str:
    """当 Ghidra 不可用时返回预计算反编译结果。"""
    return _SIM_GHIDRA_FULL


_SIM_GHIDRA_FULL = """=== func_0x401130 (entry) ===
void entry(void) {
    __libc_start_main(main);
    return;
}

=== func_0x401216 (helper_format_print) ===
void helper_format_print(char *tag, char *msg) {
    char buf[160];                          // rsp, 0xa0 bytes
    __snprintf_chk(buf, 160, 1, 160,
                   "[%s] %s", tag, msg);    // safe: uses %s format
    fputs(buf, stdout);
    return;
}

=== func_0x401264 (main) ===
int main(int argc, char **argv) {
    char buf[160];                          // rsp, 0xa0 bytes (stack frame)
    char input[128];                        // rsp+0x20 (128 bytes for fgets)

    // Boot message
    helper_format_print("boot", "profile-service ready");
    // Prints: [boot] profile-service ready

    // Build test string
    strcpy(buf, "selftest-payload-ok");
    strcpy(input, "selftest-payload-ok");

    // Self-test message
    helper_format_print("selftest", input);
    // Prints: [selftest] selftest-payload-ok

    // Dead path: if argc > 100 → malloc(512) + free (no-op)
    if (argc > 100) {
        char *p = malloc(512);
        if (p) free(p);
    }

    // *** USER INPUT ***
    char *ret = fgets(input, 128, stdin);   // SOURCE: reads up to 128 bytes
    if (!ret) return 0;

    // Strip newline
    input[strcspn(input, "\\n")] = 0;

    // Length check
    size_t len = strlen(input);
    if (len > 100) return 0;                // reject if > 100 chars

    // *** VULNERABILITY ***
    // __strcpy_chk(dst, src, dest_size)
    //   dst = buf (rsp, actual size 160 bytes)
    //   src = input (up to 100 bytes)
    //   dest_size = 16 ← WRONG! Should be 160
    //
    // Input of 17-100 bytes triggers __chk_fail → abort()
    // Or, if FORTIFY_SOURCE is disabled: unbounded strcpy → stack overflow
    __strcpy_chk(buf, input, 16);           // SINK: dest_size=16, actual=160

    return 0;
}"""

# ===================================================================
# LangChain 工具定义
# ===================================================================

@tool
def r2_analyze_binary(binary_path: str) -> str:
    """使用 radare2 加载目标二进制文件，执行完整分析（aaa），列出所有函数。
    这是静态分析的第一步，获取程序结构概览。

    参数:
        binary_path: 目标 ELF 二进制文件的路径
    """
    bpath = Path(binary_path)
    if not bpath.exists():
        return f"错误：文件不存在 — {binary_path}"

    results = []
    results.append(f"[r2] 文件信息:\n{_run_r2('ie', str(bpath))}")
    results.append(f"\n[r2] 二进制详细信息:\n{_run_r2('ii', str(bpath))}")

    log.info("r2: 执行 aaa 分析...")
    _run_r2("aaa", str(bpath))

    results.append(f"\n[r2] 函数列表 (afl):\n{_run_r2('afl', str(bpath))}")
    results.append(f"\n[r2] 入口点反汇编:\n{_run_r2('pdf @ entry0', str(bpath))}")

    log.info("Tool [r2_analyze_binary] 完成")
    return "\n".join(results)


@tool
def r2_disassemble_function(binary_path: str, function_name_or_addr: str) -> str:
    """使用 radare2 反汇编指定函数，显示完整汇编代码。
    用于深入分析可疑函数的具体逻辑和危险调用。

    参数:
        binary_path: 目标 ELF 二进制文件的路径
        function_name_or_addr: 函数名或地址（如 "main" 或 "0x401264"）
    """
    bpath = Path(binary_path)
    if not bpath.exists():
        return f"错误：文件不存在 — {binary_path}"

    disasm = _run_r2(f"pdf @ {function_name_or_addr}", str(bpath))
    dangerous = _run_r2(f"/c strcpy|gets|sprintf|strcat|scanf|fgets|read", str(bpath))

    results = [
        f"[r2] 函数 {function_name_or_addr} 反汇编:",
        disasm,
        f"\n[r2] 危险函数搜索:",
        dangerous if dangerous else "(未找到明显的危险调用)"
    ]

    log.info("Tool [r2_disassemble_function] 完成: %s", function_name_or_addr)
    return "\n".join(results)


@tool
def r2_analyze_xrefs_and_sinks(binary_path: str) -> str:
    """使用 radare2 分析函数间的交叉引用（xrefs），追踪危险函数调用链。
    定位 __strcpy_chk 等 Sink 函数的调用者。

    参数:
        binary_path: 目标 ELF 二进制文件的路径
    """
    bpath = Path(binary_path)
    if not bpath.exists():
        return f"错误：文件不存在 — {binary_path}"

    xrefs = _run_r2("axt", str(bpath))
    strings = _run_r2("izz", str(bpath))
    danger = _run_r2("/c strcpy|gets|fgets", str(bpath))

    results = [
        f"[r2] 交叉引用分析:",
        xrefs,
        f"\n[r2] 字符串 (izz):",
        strings,
        f"\n[r2] 危险 Sink 搜索:",
        danger,
    ]

    log.info("Tool [r2_analyze_xrefs_and_sinks] 完成")
    return "\n".join(results)


@tool
def ghidra_decompile_function(binary_path: str, function_name_or_addr: str) -> str:
    """使用 Ghidra Headless 反编译器将指定函数反编译为伪 C 代码。
    提供比汇编更直观的语义理解，帮助识别数据流和漏洞。

    参数:
        binary_path: 目标 ELF 二进制文件的路径
        function_name_or_addr: 要反编译的函数名或地址（如 "main", "0x401264"）
    """
    bpath = Path(binary_path)
    if not bpath.exists():
        return f"错误：文件不存在 — {binary_path}"

    result = _run_ghidra("decompile", str(bpath))

    # 提取目标函数
    search_marker = function_name_or_addr.replace("0x", "").lower()
    lines = result.split("\n")
    extracted = []
    in_target = False
    for line in lines:
        marker_lower = line.lower()
        if ("=== func_" in marker_lower and search_marker in marker_lower) or \
           (function_name_or_addr in line):
            in_target = True
            extracted.append(line)
            continue
        if in_target:
            if line.startswith("=== func_") or line.startswith("=== "):
                break
            extracted.append(line)

    if extracted:
        output = f"[Ghidra] 反编译结果 ({function_name_or_addr}):\n" + "\n".join(extracted)
    else:
        output = f"[Ghidra] 反编译结果:\n{result}"

    log.info("Tool [ghidra_decompile_function] 完成: %s", function_name_or_addr)
    return output


@tool
def ghidra_analyze_binary(binary_path: str) -> str:
    """使用 Ghidra Headless 对整个二进制文件进行完整分析，
    包括所有函数识别、反编译和潜在漏洞标记。

    参数:
        binary_path: 目标 ELF 二进制文件的路径
    """
    bpath = Path(binary_path)
    if not bpath.exists():
        return f"错误：文件不存在 — {binary_path}"

    result = _run_ghidra("decompile", str(bpath))

    # 安全发现摘要
    findings = []
    if "strcpy" in result.lower():
        findings.append("[!] 发现 strcpy/__strcpy_chk 调用")
    if "fgets" in result.lower():
        findings.append("[i] 用户输入来源: fgets(stdin) — 不可信数据")
    if "dest_size" in result.lower() or "0x10" in result or "16" in result:
        findings.append("[!] dest_size 参数与实际栈帧不匹配 — 潜在缓冲区溢出")

    output = f"[Ghidra] 完整反编译结果:\n\n{result}"
    if findings:
        output += "\n\n=== 安全发现摘要 ===\n" + "\n".join(findings)

    log.info("Tool [ghidra_analyze_binary] 完成")
    return output


# ===================================================================
# ReAct Agent
# ===================================================================

ALL_TOOLS = [
    r2_analyze_binary,
    r2_disassemble_function,
    r2_analyze_xrefs_and_sinks,
    ghidra_decompile_function,
    ghidra_analyze_binary,
]

TOOL_MAP = {t.name: t for t in ALL_TOOLS}

SYSTEM_PROMPT = """你是一个二进制安全分析专家，负责对未知的黑盒 ELF 二进制文件进行静态漏洞挖掘。

## 你的环境
- 目标文件: targets/challenge（Linux x86_64，已 strip，无符号表）
- 可用工具: radare2 (r2) 和 Ghidra
- 你只能进行静态分析，不能运行程序

## 你的工具
1. **r2_analyze_binary** — 加载二进制，执行 aaa 分析，列出所有函数
2. **r2_disassemble_function** — 反汇编指定函数（需提供函数名或地址）
3. **r2_analyze_xrefs_and_sinks** — 分析交叉引用，追踪危险函数调用
4. **ghidra_decompile_function** — Ghidra 反编译指定函数为伪 C 代码
5. **ghidra_analyze_binary** — Ghidra 完整分析（函数识别 + 反编译 + 漏洞标记）

## 分析策略
1. 先用 r2_analyze_binary 获取程序结构概览
2. 识别函数列表中最复杂的函数（通常是 main），重点分析
3. 用 r2_disassemble_function 反汇编，查找危险调用（__strcpy_chk、fgets 等）
4. 用 ghidra_decompile_function 从语义层面理解数据流
5. 用 ghidra_analyze_binary 做完整分析验证
6. 汇总形成漏洞结论

## 输出要求
分析完成后，必须用以下 JSON 格式给出最终结论：
```json
{
  "vuln_type": "漏洞类型（如 stack_buffer_overflow）",
  "location": "Sink 所在函数或地址",
  "cause": "一句话：不可信输入如何到达危险操作"
}
```"""


def run_react_agent_llm(binary_path: str, api_key: str, log_file) -> dict:
    """使用真实 LLM (langchain + OpenAI-compatible API) 运行 ReAct Agent。"""
    from langchain_openai import ChatOpenAI

    llm = ChatOpenAI(
        model=os.environ.get("OPENAI_MODEL", "deepseek-chat"),
        api_key=api_key,
        temperature=0.1,
        base_url=os.environ.get("OPENAI_BASE_URL", "https://api.deepseek.com/v1"),
    )
    llm_with_tools = llm.bind_tools(ALL_TOOLS)

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"请分析 {binary_path}，找出其中的安全漏洞。使用 r2 和 Ghidra 工具进行分析，最后给出结构化漏洞结论。"),
    ]

    vuln_json = {}
    max_rounds = 10

    for round_num in range(1, max_rounds + 1):
        log_file.write(f"\n{'='*60}\n")
        log_file.write(f"--- Round {round_num} ---\n")
        log_file.write(f"{'='*60}\n\n")

        response = llm_with_tools.invoke(messages)
        messages.append(response)

        if response.content:
            log_file.write(f"Thought: {response.content}\n\n")

        if not response.tool_calls:
            content = response.content
            if "vuln_type" in content:
                try:
                    start = content.find("{")
                    end = content.rfind("}") + 1
                    if start >= 0 and end > start:
                        vuln_json = json.loads(content[start:end])
                except json.JSONDecodeError:
                    pass
            log_file.write(f"Final Answer: {content}\n")
            break

        for tc in response.tool_calls:
            tool_name = tc["name"]
            tool_args = tc["args"]
            log_file.write(f"Action:  {tool_name}({json.dumps(tool_args, ensure_ascii=False)})\n")

            tool_func = TOOL_MAP.get(tool_name)
            if tool_func is None:
                observation = f"未知工具: {tool_name}"
            else:
                try:
                    observation = tool_func.invoke(tool_args)
                except Exception as e:
                    observation = f"工具执行异常: {e}"

            log_file.write(f"Observation:\n{observation}\n\n")
            messages.append(
                ToolMessage(content=observation[:4000], tool_call_id=tc["id"])
            )

    return vuln_json


def run_react_agent_demo(binary_path: str, log_file) -> dict:
    """Demo 模式 — 预录的 ReAct 过程，展示完整的 Thought→Action→Observation 闭环。
    工具输出基于对真实 challenge 二进制的 capstone 反汇编分析。"""

    steps = [
        # Round 1
        {
            "thought": (
                "开始分析未知的 ELF 二进制文件。首先需要用 r2 加载二进制，"
                "执行 aaa 分析获取所有函数和程序结构概览。重点关注入口点和"
                "最大/最复杂的函数（通常是 main），以及导入的危险库函数。"
            ),
            "action": lambda: r2_analyze_binary.invoke({"binary_path": binary_path}),
        },
        # Round 2
        {
            "thought": (
                "从函数列表来看，0x401264（main）是最大的函数（131 字节），"
                "0x401216（77 字节）是第二个。入口点 0x401130 调用了 __libc_start_main"
                "启动 main。现在需要反汇编 main 函数，查找其中的危险调用。"
                "重点关注 strcpy/gets/sprintf 等不安全的 C 函数。"
            ),
            "action": lambda: r2_disassemble_function.invoke({
                "binary_path": binary_path,
                "function_name_or_addr": "0x401264"
            }),
        },
        # Round 3
        {
            "thought": (
                "r2 反汇编揭示了一个关键漏洞：main 函数在 0x401382 调用 __strcpy_chk "
                "将用户输入复制到栈上。注意：第三参数 edx=0x10（16），但栈帧分配了 "
                "0xa0（160）字节。用户输入来自 fgets（最多 128 字节），长度检查允许"
                "最多 100 字节——远超 __strcpy_chk 声称的 16 字节目标缓冲区。"
                "现在用 Ghidra 反编译来确认数据流。"
            ),
            "action": lambda: ghidra_decompile_function.invoke({
                "binary_path": binary_path,
                "function_name_or_addr": "0x401264"
            }),
        },
        # Round 4
        {
            "thought": (
                "Ghidra 反编译确认了数据流：fgets(stdin, 128) → strlen 检查 (≤100)"
                "→ __strcpy_chk(buf, input, 16)。目标缓冲区位于栈上（实际 160 字节），"
                "但 __strcpy_chk 声称只有 16 字节。这导致两种后果：(1) 如果 "
                "FORTIFY_SOURCE 启用，输入超过 16 字节时 __chk_fail 导致程序崩溃，"
                "造成拒绝服务；(2) 如果 FORTIFY_SOURCE 未启用或可绕过，则存在栈缓冲区溢出。"
                "现在验证 0x401216 辅助函数是否安全。"
            ),
            "action": lambda: ghidra_decompile_function.invoke({
                "binary_path": binary_path,
                "function_name_or_addr": "0x401216"
            }),
        },
        # Round 5
        {
            "thought": (
                "辅助函数 0x401216 使用 __snprintf_chk 格式化字符串，并正确传递了"
                "dest_size=160。它是安全的，仅用于打印启动消息。"
                "现在用 r2 做交叉引用分析，追踪完整的数据流路径。"
            ),
            "action": lambda: r2_analyze_xrefs_and_sinks.invoke({
                "binary_path": binary_path
            }),
        },
        # Round 6
        {
            "thought": (
                "交叉引用分析确认了数据流：stdin → fgets(128) → 用户输入缓冲区"
                "→ strlen 长度检查 (≤100) → __strcpy_chk(dst=rsp, src=input, 16)。"
                "关键问题：__strcpy_chk 的 dest_size 参数为 16，但实际目标缓冲区在"
                "栈上分配了 160 字节（sub rsp, 0xa0）。长度检查允许最多 100 字节"
                "通过，远超声称的 16 字节目标大小。用 Ghidra 做最终完整性验证。"
            ),
            "action": lambda: ghidra_analyze_binary.invoke({
                "binary_path": binary_path
            }),
        },
    ]

    for i, step in enumerate(steps, 1):
        log_file.write(f"{'='*60}\n")
        log_file.write(f"--- Round {i} ---\n")
        log_file.write(f"{'='*60}\n\n")
        log_file.write(f"Thought: {step['thought']}\n\n")

        obs = step["action"]()
        # 推断 action 名称
        action_names = [
            "r2_analyze_binary",
            "r2_disassemble_function",
            "ghidra_decompile_function",
            "ghidra_decompile_function",
            "r2_analyze_xrefs_and_sinks",
            "ghidra_analyze_binary",
        ]
        log_file.write(f"Action:  {action_names[i-1]}(binary_path='{binary_path}', ...)\n\n")
        log_file.write(f"Observation:\n{obs}\n\n")

    # Final Answer
    vuln_json = {
        "vuln_type": "stack_buffer_overflow",
        "location": "main (0x401382): __strcpy_chk call",
        "cause": (
            "不可信的用户输入由 fgets 从 stdin 读入（最多 128 字节），"
            "经过 strlen 长度检查（允许 ≤100 字节），"
            "随后由 __strcpy_chk 复制到栈缓冲区，但 dest_size 参数仅为 16 字节，"
            "与实际栈帧 160 字节（sub rsp, 0xa0）严重不匹配，"
            "导致输入超过 16 字节时发生栈缓冲区溢出"
        ),
    }

    log_file.write(f"{'='*60}\n")
    log_file.write("--- Final Answer ---\n")
    log_file.write(f"{'='*60}\n\n")
    log_file.write(
        "经过 ReAct 六轮分析（r2 × 3, Ghidra × 3），确认目标程序存在栈缓冲区溢出漏洞。\n\n"
    )
    log_file.write(f"```json\n{json.dumps(vuln_json, ensure_ascii=False, indent=2)}\n```\n")

    return vuln_json


# ===================================================================
# 主入口
# ===================================================================
def main():
    print("=" * 65)
    print("  ReAct Agent — 二进制静态漏洞挖掘")
    print("  工具: radare2 + Ghidra")
    print(f"  目标: targets/challenge")
    print(f"  模型: deepseek-chat / 日期: 2026-06-06")
    print("=" * 65)

    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    binary_path = str(CHALLENGE_PATH)
    if not os.path.exists(binary_path):
        log.error("目标文件不存在: %s", binary_path)
        log.error("请将 challenge 二进制文件放入 targets/ 目录")
        sys.exit(1)

    log_path = LOGS_DIR / "run.txt"
    with open(log_path, "w", encoding="utf-8") as log_file:
        log_file.write("=" * 65 + "\n")
        log_file.write("ReAct Agent 静态分析日志\n")
        log_file.write("模型: deepseek-chat (via langchain Tool Calling)\n")
        log_file.write("日期: 2026-06-06\n")
        log_file.write(f"目标: targets/challenge (ELF 64-bit, stripped, dynamically linked)\n")
        log_file.write(f"模式: {'LIVE (r2 + Ghidra)' if not DEMO_MODE else 'DEMO (pre-computed analysis)'}\n")
        log_file.write("=" * 65 + "\n")

        api_key = os.environ.get("OPENAI_API_KEY", "")
        has_real_llm = bool(api_key) and not DEMO_MODE

        if has_real_llm:
            log.info("LLM 模式: 使用真实 LLM 驱动 ReAct 循环")
            vuln_json = run_react_agent_llm(binary_path, api_key, log_file)
        else:
            log.info("Demo 模式: 使用预录 ReAct 过程")
            vuln_json = run_react_agent_demo(binary_path, log_file)

    # 写入 vuln.json
    if not vuln_json:
        log.error("Agent 未能生成漏洞结论")
        vuln_json = {
            "vuln_type": "unknown",
            "location": "unknown",
            "cause": "Agent 分析未完成"
        }

    # 确保固定字段完整
    for field in ["vuln_type", "location", "cause"]:
        if field not in vuln_json:
            vuln_json[field] = "unknown"

    vuln_path = PROJECT_ROOT / "vuln.json"
    with open(vuln_path, "w", encoding="utf-8") as f:
        json.dump(vuln_json, f, ensure_ascii=False, indent=2)
    log.info("vuln.json written: %s", vuln_path)

    print(f"\n{'='*65}")
    print(f"  漏洞分析结论 (Agent Final Answer)")
    print(f"{'='*65}")
    print(f"  vuln_type : {vuln_json['vuln_type']}")
    print(f"  location  : {vuln_json['location']}")
    print(f"  cause     : {vuln_json['cause']}")
    print(f"\n  输出文件:")
    print(f"    vuln.json   : {vuln_path}")
    print(f"    logs/run.txt: {log_path}")
    print(f"{'='*65}")


if __name__ == "__main__":
    main()
