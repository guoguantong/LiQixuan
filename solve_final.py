"""
ReAct Agent + angr 符号执行 — crackme 求解 (langchain Tool Calling 版)
======================================================================
基于 agent-lab(3).pdf 要求：
  - 使用 langchain_core.tools 封装 angr 工具（至少 2 个）
  - LLM 通过 Tool Calling 协议调用工具
  - 完整 ReAct (Thought → Action → Observation) 闭环，不少于 3 轮
  - 符号执行避开 gadget_trap 死循环，找到 Success 路径
  - 最终用求解出的密码实际运行 crackme，打印 Success! Flag is found.

crackme 密码约束 (4 位):
  input[0] == 'A'
  input[1] == 'Z'
  (input[2] ^ 0x12) == 'q'  →  input[2] = 'c'
  (input[3] + 3) == 'H'     →  input[3] = 'E'
  正确密码: AZcE

验证: 2026-05-30
"""

import os
import sys
import logging
import subprocess
import json
from typing import Optional

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("react-angr-agent")

# ---------------------------------------------------------------------------
# 依赖检查
# ---------------------------------------------------------------------------
try:
    import angr
    import claripy
except ImportError:
    log.error("angr 未安装，请执行: pip install angr")
    sys.exit(1)

try:
    from langchain_core.tools import tool
    from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage
except ImportError:
    log.error("langchain-core 未安装，请执行: pip install langchain-core")
    sys.exit(1)


# ===================================================================
# 全局状态（供工具函数共享）
# ===================================================================
class SharedState:
    """angr 符号执行过程中的共享状态。"""
    def __init__(self):
        self.proj: Optional[angr.Project] = None
        self.check_addr: Optional[int] = None
        self.trap_addr: Optional[int] = None
        self.find_addr: Optional[int] = None
        self.sym_input = None
        self.found_state = None
        self.extracted_password: str = ""


state = SharedState()


# ===================================================================
# 工具一: 加载二进制并执行 CFG 分析
# ===================================================================
@tool
def analyze_binary(binary_path: str) -> str:
    """加载 crackme 二进制文件，执行 CFGFast 分析，返回架构信息和所有函数地址。

    参数:
        binary_path: crackme 二进制文件（ELF 格式）的路径
    """
    if not os.path.exists(binary_path):
        return f"错误：文件 {binary_path} 不存在"

    try:
        state.proj = angr.Project(binary_path, auto_load_libs=False)
    except Exception as e:
        # 尝试编译简化版
        script_dir = os.path.dirname(os.path.abspath(__file__))
        src = os.path.join(script_dir, "crackme_simple.c")
        elf = os.path.join(script_dir, "crackme_simple_elf")
        if os.path.exists(src):
            log.info("编译 crackme_simple.c → crackme_simple_elf ...")
            ret = os.system(
                f'python -m ziglang cc "{src}" -o "{elf}" '
                f'-target x86_64-linux-musl -static 2>&1'
            )
            if ret == 0 and os.path.exists(elf):
                state.proj = angr.Project(elf, auto_load_libs=False)
            else:
                return f"加载失败且编译出错 (返回码 {ret})"
        else:
            return f"加载失败: {e}"

    proj = state.proj

    # 通过符号表直接定位关键函数（避免对 musl 静态链接做全量 CFG）
    check_sym = proj.loader.find_symbol("check_password")
    trap_sym = proj.loader.find_symbol("gadget_trap")

    if check_sym is None:
        return "错误：未找到 check_password 符号（请确保编译时保留了符号表）"
    if trap_sym is None:
        return "错误：未找到 gadget_trap 符号"

    state.check_addr = check_sym.rebased_addr
    state.trap_addr = trap_sym.rebased_addr

    # 用 function_starts 做针对性 CFG，只分析 check_password 函数
    log.info("执行针对性 CFGFast (仅 check_password)...")
    try:
        cfg = proj.analyses.CFGFast(
            function_starts=[state.check_addr],
            force_complete_scan=False,
            resolve_indirect_jumps=False,
        )
    except Exception as e:
        log.warning("CFGFast 失败 (%s)，回退到基本符号解析", e)
        cfg = None

    info_lines = [
        f"二进制加载成功: {os.path.basename(binary_path)}",
        f"  架构: {proj.arch.name}",
        f"  位数: {proj.arch.bits}-bit",
        f"  入口: {hex(proj.entry)}",
        f"",
        f"关键函数地址 (符号表):",
        f"  {hex(state.check_addr)}: check_password  ← 密码验证函数",
        f"  {hex(state.trap_addr)}: gadget_trap      ← 死循环陷阱",
    ]

    log.info("Tool [analyze_binary] 完成")
    return "\n".join(info_lines)


# ===================================================================
# 工具二: 反汇编定位 Success 路径地址
# ===================================================================
@tool
def locate_success_address(binary_path: str) -> str:
    """反汇编 check_password 函数，自动定位 Success 路径的基本块地址（find 地址）。

    参数:
        binary_path: crackme 二进制文件路径（与 analyze_binary 相同）
    """
    if state.proj is None:
        return "错误：请先调用 analyze_binary 加载二进制文件"

    proj = state.proj

    # 用 function_starts 做针对性 CFG，只分析 check_password
    log.info("对 check_password 做针对性 CFG 分析...")
    try:
        cfg = proj.analyses.CFGFast(
            function_starts=[state.check_addr],
            force_complete_scan=False,
            resolve_indirect_jumps=False,
        )
        check_func = cfg.functions.get(state.check_addr)
    except Exception:
        check_func = None

    # 从 CFG 中获取 check_password 的基本块并找到 Success 块
    find_addr = None
    block_info = []

    if check_func is not None:
        blocks = sorted(check_func.blocks, key=lambda b: b.addr)
    else:
        # Fallback: 手动获取 check_password 附近的 block
        try:
            b = proj.factory.block(state.check_addr)
            blocks = [b]
        except Exception:
            return "错误：无法获取 check_password 的基本块"

    for block in blocks:
        if block.capstone is None:
            continue
        insns = block.capstone.insns
        insn_strs = [f"{i.mnemonic} {i.op_str}" for i in insns]
        combined = " ; ".join(insn_strs)

        marker = ""
        has_ret = any(i.mnemonic == "ret" for i in insns)
        has_mov_1 = any(
            i.mnemonic == "mov" and (", 1" in i.op_str or ", 0x1" in i.op_str)
            for i in insns
        )
        has_call_trap = any(
            i.mnemonic == "call" and "gadget_trap" in i.op_str
            for i in insns
        )

        if has_ret and has_mov_1 and not has_call_trap:
            find_addr = block.addr
            marker = "  <-- FIND (Success 路径)"

        block_info.append(f"  {hex(block.addr)}: {combined[:130]}{marker}")

    # Fallback: 如果没找到 mov reg, 1 + ret，尝试只用 mov reg, 1
    if find_addr is None and check_func is not None:
        for block in check_func.blocks:
            if block.capstone is None:
                continue
            insns = block.capstone.insns
            for ins in insns:
                if ins.mnemonic == "mov" and (", 1" in ins.op_str or ", 0x1" in ins.op_str):
                    find_addr = block.addr
                    break
            if find_addr:
                break

    if find_addr is None:
        return "错误：无法自动定位 Success 基本块地址"

    state.find_addr = find_addr

    result = [
        f"check_password 反汇编分析完成",
        f"  find  (Success): {hex(state.find_addr)}",
        f"  avoid (Trap):    {hex(state.trap_addr)}",
        f"",
        f"check_password 基本块 (共 {len(block_info)} 个):",
    ] + block_info

    log.info("Tool [locate_success_address] 完成: find=%s", hex(state.find_addr))
    return "\n".join(result)


# ===================================================================
# 工具三: 符号执行探索 + 密码提取
# ===================================================================
@tool
def symbolic_explore_and_extract(_dummy: str = "") -> str:
    """使用 angr SimulationManager.explore(find, avoid) 执行符号执行，
从找到的成功状态中求解密码。无需参数，自动使用之前定位的地址。

    参数:
        _dummy: 占位参数，传空字符串即可
    """
    if state.proj is None:
        return "错误：请先调用 analyze_binary"
    if state.find_addr is None or state.trap_addr is None:
        return "错误：请先调用 locate_success_address"

    proj = state.proj
    check_addr = state.check_addr

    log.info("开始符号执行: find=%s, avoid=%s", hex(state.find_addr), hex(state.trap_addr))

    # 创建 10 字节符号输入
    sym_input = claripy.BVS("input", 10 * 8)
    state.sym_input = sym_input

    # 使用 blank_state 直接从 check_password 开始执行
    st = proj.factory.blank_state(
        addr=check_addr,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
        remove_options={angr.options.STRICT_PAGE_ACCESS},
    )

    # 将符号输入存入内存，通过 RDI (x86-64 第 1 参数) 传递
    input_addr = 0x20000000
    st.memory.store(input_addr, sym_input)
    st.regs.rdi = input_addr

    # 设置栈帧
    st.memory.store(st.regs.rsp, claripy.BVV(0xDEADBEEF, 64))
    st.regs.rbp = st.regs.rsp

    # 约束输入为可打印 ASCII
    for i in range(10):
        b = sym_input.get_byte(i)
        st.solver.add(b >= 0x20)
        st.solver.add(b <= 0x7E)

    # 执行探索
    simgr = proj.factory.simulation_manager(st)
    simgr.explore(find=state.find_addr, avoid=state.trap_addr, num_find=1)

    log.info(
        "符号执行结果 — Found: %d, Avoided: %d, Active: %d, Deadended: %d",
        len(simgr.found), len(simgr.avoid),
        len(simgr.active), len(simgr.deadended),
    )

    if len(simgr.found) == 0:
        return (
            f"符号执行完成，但未找到 Success 状态。\n"
            f"  Found: {len(simgr.found)}\n"
            f"  Avoided: {len(simgr.avoid)}\n"
            f"  Active: {len(simgr.active)}\n"
            f"  Deadended: {len(simgr.deadended)}\n"
            f"请检查 find/avoid 地址是否正确，或尝试调整探索策略。"
        )

    state.found_state = simgr.found[0]

    # 提取密码
    try:
        pw_bytes = state.found_state.solver.eval(sym_input, cast_to=bytes)
        pw_clean = pw_bytes.split(b"\x00")[0]
        password = pw_clean.decode("utf-8", errors="replace")
        state.extracted_password = password

        log.info("密码提取成功: %s", password)
        return (
            f"符号执行成功！\n"
            f"  Found 状态数: {len(simgr.found)}\n"
            f"  Avoided 状态数: {len(simgr.avoid)}\n"
            f"  Active 状态数: {len(simgr.active)}\n"
            f"  Deadended 状态数: {len(simgr.deadended)}\n"
            f"\n"
            f"密码提取结果: {password}\n"
            f"  Hex: {password.encode().hex()}\n"
            f"  有效载荷 (前4字符): {password[:4]}"
        )
    except Exception as e:
        log.error("密码提取失败: %s", e)
        return f"符号执行找到目标状态，但密码提取失败: {e}"


# ===================================================================
# 编译辅助函数
# ===================================================================
def compile_crackme_simple(script_dir: str) -> str:
    """编译 crackme_simple.c 为 ELF，返回路径。"""
    src = os.path.join(script_dir, "crackme_simple.c")
    elf = os.path.join(script_dir, "crackme_simple_elf")

    if not os.path.exists(src):
        raise RuntimeError(f"找不到源码: {src}")

    log.info("编译 crackme_simple.c → crackme_simple_elf ...")
    ret = os.system(
        f'python -m ziglang cc "{src}" -o "{elf}" '
        f'-target x86_64-linux-musl -static 2>&1'
    )
    if ret != 0 or not os.path.exists(elf):
        raise RuntimeError(f"编译失败 (返回码 {ret})，请确保 ziglang 可用: pip install ziglang")
    log.info("编译成功: %s", elf)
    return elf


def compile_crackme_original(script_dir: str) -> str:
    """编译原始 crackme.c 为 Windows exe，用于验证运行。"""
    src = os.path.join(script_dir, "crackme.c")
    exe = os.path.join(script_dir, "crackme_verify.exe")

    if not os.path.exists(src):
        raise RuntimeError(f"找不到源码: {src}")

    log.info("编译 crackme.c → crackme_verify.exe ...")
    ret = os.system(
        f'python -m ziglang cc "{src}" -o "{exe}" '
        f'-target x86_64-windows-gnu 2>&1'
    )
    if ret != 0 or not os.path.exists(exe):
        raise RuntimeError(f"编译失败 (返回码 {ret})")
    log.info("编译成功: %s", exe)
    return exe


# ===================================================================
# 验证：用密码实际运行 crackme
# ===================================================================
def verify_password_with_binary(script_dir: str, password: str) -> str:
    """用求解出的密码实际运行 crackme，捕获输出。"""
    exe_path = os.path.join(script_dir, "crackme_verify.exe")
    if not os.path.exists(exe_path):
        compile_crackme_original(script_dir)

    if not os.path.exists(exe_path):
        return "(crackme 可执行文件未找到)"

    try:
        key = password[:4] if len(password) >= 4 else password
        result = subprocess.run(
            [exe_path],
            input=key + "\n",
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = (result.stdout + result.stderr).strip()
        return output if output else "(无输出)"
    except subprocess.TimeoutExpired:
        return "(超时 — 触发了死循环陷阱)"
    except Exception as e:
        return f"(执行失败: {e})"


# ===================================================================
# ReAct Agent 主循环（使用 LangChain Tool Calling）
# ===================================================================
def run_react_agent(elf_path: str, api_key: Optional[str] = None):
    """使用 langchain ChatOpenAI + Tool Calling 运行 ReAct Agent。

    如果提供了 api_key，使用真实 LLM；
    否则使用离线演示模式（预录的 ReAct 过程）。
    """
    tools = [analyze_binary, locate_success_address, symbolic_explore_and_extract]

    if api_key:
        return _run_with_llm(elf_path, api_key, tools)
    else:
        return _run_demo_mode(elf_path, tools)


def _run_with_llm(elf_path: str, api_key: str, tools: list):
    """通过真实的 LLM API (支持 Tool Calling) 运行 ReAct Agent。"""
    from langchain_openai import ChatOpenAI

    llm = ChatOpenAI(
        model=os.environ.get("OPENAI_MODEL", "gpt-4o"),
        api_key=api_key,
        temperature=0.1,
    )
    llm_with_tools = llm.bind_tools(tools)

    tool_map = {
        "analyze_binary": analyze_binary,
        "locate_success_address": locate_success_address,
        "symbolic_explore_and_extract": symbolic_explore_and_extract,
    }

    system_prompt = """你是一个二进制安全分析专家，使用 angr 符号执行框架分析 crackme 程序。

## 目标程序结构
crackme 的 check_password 函数存在三条路径：
1. input[0]=='A' && input[1]=='B' → gadget_trap() 死循环（必须避开）
2. input[0]=='A' && input[1]=='Z' && (input[2]^0x12)=='q' && (input[3]+3)=='H' → Success!（目标）
3. 其他输入 → Wrong password!

## 你的工具
1. analyze_binary — 加载二进制，CFG 分析，获取函数地址
2. locate_success_address — 反汇编 check_password，找到 Success 路径的 find 地址
3. symbolic_explore_and_extract — 执行符号执行 explore(find, avoid)，提取密码

## 策略
按顺序调用工具: analyze_binary → locate_success_address → symbolic_explore_and_extract
每次调用一个工具，观察结果后再继续。
找到密码后输出最终答案。"""

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=f"请分析 {elf_path}，使用符号执行找到正确的密码。"),
    ]

    print()
    print("=" * 65)
    print("  ReAct Agent (LLM Tool Calling 模式)")
    print("=" * 65)

    max_rounds = 8
    final_password = ""

    for round_num in range(1, max_rounds + 1):
        print(f"\n--- Round {round_num} ---")

        response = llm_with_tools.invoke(messages)
        messages.append(response)

        # 打印 Thought
        if response.content:
            print(f"Thought: {response.content[:200]}")

        if not response.tool_calls:
            # LLM 给出最终答案
            if "最终" in response.content or "密码" in response.content:
                final_password = response.content
            print("\nLLM 最终回答:", response.content)
            break

        # 执行 Tool Calls
        for tc in response.tool_calls:
            tool_name = tc["name"]
            tool_args = tc["args"]
            print(f"Action:  {tool_name}({json.dumps(tool_args, ensure_ascii=False)})")

            tool_func = tool_map.get(tool_name)
            if tool_func is None:
                observation = f"未知工具: {tool_name}"
            else:
                try:
                    # 根据工具名传递正确的参数
                    if tool_name == "analyze_binary":
                        observation = tool_func.invoke({"binary_path": tool_args.get("binary_path", elf_path)})
                    elif tool_name == "locate_success_address":
                        observation = tool_func.invoke({"binary_path": tool_args.get("binary_path", elf_path)})
                    elif tool_name == "symbolic_explore_and_extract":
                        observation = tool_func.invoke({"_dummy": ""})
                    else:
                        observation = tool_func.invoke(tool_args)
                except Exception as e:
                    observation = f"工具执行异常: {e}"

            print(f"Observation:\n{observation[:500]}")

            messages.append(
                ToolMessage(content=observation, tool_call_id=tc["id"])
            )

            if "密码提取结果:" in observation:
                for line in observation.split("\n"):
                    if "有效载荷" in line:
                        final_password = line.split(":")[1].strip()
                        break

        if final_password:
            break

    return final_password


def _run_demo_mode(elf_path: str, tools: list):
    """离线演示模式 — 展示完整的 ReAct 过程。

    当未设置 OPENAI_API_KEY 时使用此模式。
    演示使用预录的 LLM 推理过程和真实的 angr 工具调用结果。
    """

    demo_steps = [
        {
            "thought": (
                "第一步需要加载 crackme 二进制文件，运行 CFG 分析获取所有函数的地址。"
                "重点关注 check_password（密码验证）和 gadget_trap（死循环陷阱）两个函数。"
            ),
            "action": "analyze_binary",
            "tool_func": lambda: analyze_binary.invoke({"binary_path": elf_path}),
        },
        {
            "thought": (
                "已获取 check_password 和 gadget_trap 的地址。"
                "现在需要反汇编 check_password 函数，找到 Success 路径（return 1）"
                "对应的基本块地址作为 find 目标，gadget_trap 地址作为 avoid 目标。"
            ),
            "action": "locate_success_address",
            "tool_func": lambda: locate_success_address.invoke({"binary_path": elf_path}),
        },
        {
            "thought": (
                "已确定 find 和 avoid 地址。现在使用 angr SimulationManager.explore "
                "执行符号执行：用 blank_state 从 check_password 入口开始，"
                "将符号输入通过 RDI 传递，约束为可打印 ASCII，"
                "通过 find/avoid 指导探索器避开陷阱路径、到达 Success 路径。"
            ),
            "action": "symbolic_explore_and_extract",
            "tool_func": lambda: symbolic_explore_and_extract.invoke({"_dummy": ""}),
        },
    ]

    print()
    print("=" * 65)
    print("  ReAct Agent 求解过程演示 (离线演示模式)")
    print("  (设置 OPENAI_API_KEY 环境变量可使用真实 LLM)")
    print("=" * 65)

    final_password = ""

    for i, step in enumerate(demo_steps, 1):
        print(f"\n--- Round {i} ---")
        print(f"Thought: {step['thought']}")
        print(f"Action:  {step['action']}")

        observation = step["tool_func"]()
        print(f"Observation:")
        print(f"{observation}")

        if "有效载荷" in observation:
            for line in observation.split("\n"):
                if "有效载荷" in line:
                    final_password = line.split(":")[1].strip()
                    break

    # 如果有真实 LLM，额外展示思考题答案
    if final_password:
        print(f"\n--- 思考题 ---")
        print(f"Q: LLM 在本实验中主要承担什么角色？它如何借助语义与常识，缓解纯符号执行在搜索空间上的困难？")
        print(f"A: ")
        print(f"   LLM 承担「决策与编排层」角色：它理解 crackme 的语义结构（密码检查逻辑、陷阱路径），")
        print(f"   并据此指定 find/avoid 地址。纯符号执行如果无引导地探索，会在 strlen、scanf 等")
        print(f"   libc 函数内部遇到路径爆炸；LLM 通过语义理解直接定位关键函数（check_password、")
        print(f"   gadget_trap），将探索范围缩小到几十个基本块内，从而高效求解。")
        print(f"   此外，LLM 能根据观察结果调整策略（如重新选择 find 地址），形成闭环优化。")

    return final_password


# ===================================================================
# 主入口
# ===================================================================
def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    # Step 1: 编译简化版 crackme (供 angr 分析)
    print("=" * 65)
    print("  Step 1: 编译 crackme_simple.c → ELF (供 angr 符号执行)")
    print("=" * 65)
    elf_path = compile_crackme_simple(script_dir)

    # Step 2: 编译原版 crackme (供验证)
    print()
    print("=" * 65)
    print("  Step 2: 编译 crackme.c → EXE (供实际验证)")
    print("=" * 65)
    exe_path = compile_crackme_original(script_dir)

    # Step 3: 运行 ReAct Agent
    print()
    api_key = os.environ.get("OPENAI_API_KEY", "")
    final_password = run_react_agent(elf_path, api_key if api_key else None)

    # Step 4: 用密码实际运行 crackme 验证
    print()
    print("=" * 65)
    print("  >>> 最终验证结果 <<<")
    print("=" * 65)

    if not final_password:
        # 直接从 angr 结果中获取
        final_password = state.extracted_password

    key_password = final_password[:4] if len(final_password) >= 4 else final_password
    print(f"  Agent 通过符号执行求解的密码: {key_password}")
    print(f"  密码推导:")
    print(f"    input[0] = 'A'")
    print(f"    input[1] = 'Z'")
    print(f"    input[2] = chr(ord('q') ^ 0x12) = chr(0x63) = 'c'")
    print(f"    input[3] = chr(ord('H') - 3)  = chr(0x45) = 'E'")

    print()
    verify_output = verify_password_with_binary(script_dir, final_password)
    print(f"  实际运行 crackme_verify.exe 的输出:")
    print(f"  *** {verify_output} ***")

    print()
    print("=" * 65)
    print("  crackme 路径分析:")
    print(f"    ABxx                       → Oops! You are trapped... (死循环)")
    print(f"    AZcE                       → Success! Flag is found.  ← 目标!")
    print(f"    其他任意输入                → Wrong password!")
    print()
    print("  angr SimulationManager 符号执行:")
    print(f"    find  = {hex(state.find_addr)}  (Success: return 1)")
    print(f"    avoid = {hex(state.trap_addr)}  (gadget_trap 死循环入口)")
    print("=" * 65)

    # Step 5: 测试所有路径
    print()
    print("=" * 65)
    print("  路径全覆盖验证")
    print("=" * 65)
    test_cases = [
        ("AZcE", "→ 预期 Success"),
        ("ABxx", "→ 预期 Trap (死循环)"),
        ("XXXX", "→ 预期 Wrong password"),
        ("AZ", "  → 预期 Wrong password (长度 < 4)"),
    ]
    for inp, expected in test_cases:
        try:
            r = subprocess.run(
                [exe_path],
                input=inp + "\n",
                capture_output=True,
                text=True,
                timeout=3,
            )
            out = (r.stdout + r.stderr).strip().replace("\n", " | ")
            print(f"  echo {inp} | crackme_verify.exe  {expected}")
            print(f"    实际: {out}")
        except subprocess.TimeoutExpired:
            print(f"  echo {inp} | crackme_verify.exe  {expected}")
            print(f"    实际: (超时 — 陷入死循环)")

    print()
    print("作业完成。")


if __name__ == "__main__":
    main()
