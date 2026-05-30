"""
ReAct Agent + angr — 符号执行求解 crackme
============================================
使用 ReAct (Reasoning + Acting) 模式，让 LLM 作为智能代理，
调用 angr 符号执行框架自动分析 crackme 二进制文件，
找到正确密码并避开 trap 路径。

原理说明：
  crackme 的 check_password 函数存在三条路径：
    1. input[0]=='A' && input[1]=='B' → gadget_trap() 死循环（需避开）
    2. input[0]=='A' && input[1]=='Z' → "Success! Flag is found."（目标路径）
    3. 其他 → "Wrong password!"（失败路径）

  Agent 使用 angr 的 SimulationManager 配合 find/avoid 地址，
  通过符号执行自动找到通向 Success 的路径并求解密码。
"""

import os
import sys
import json
import logging
from typing import Any

# ---------------------------------------------------------------------------
# 日志配置
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("react-angr-agent")

# ---------------------------------------------------------------------------
# 检查依赖
# ---------------------------------------------------------------------------
try:
    import angr
    import claripy
except ImportError:
    log.error("angr 未安装，请执行: pip install angr")
    sys.exit(1)

try:
    from openai import OpenAI
except ImportError:
    log.error("openai 未安装，请执行: pip install openai")
    sys.exit(1)


# ===================================================================
# 第一部分：angr 工具函数（Agent 可调用的工具集）
# ===================================================================

class AngrTools:
    """封装 angr 操作为 Agent 可调用的工具函数。"""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.proj: angr.Project | None = None
        self.simgr: Any = None
        self.cfg: Any = None
        self.success_addr: int | None = None
        self.trap_addr: int | None = None
        self.found_state: Any = None

    # ---- Tool 1: 加载二进制文件 ----
    def load_binary(self) -> str:
        """加载 crackme 二进制文件，返回基本架构信息。"""
        if not os.path.exists(self.binary_path):
            return f"错误：文件 {self.binary_path} 不存在"

        try:
            self.proj = angr.Project(self.binary_path, auto_load_libs=False)
        except Exception as e:
            # 尝试用 gcc 编译
            src = self.binary_path.replace(".exe", "").replace(".c", "") + ".c"
            if not os.path.exists(src):
                src = os.path.join(os.path.dirname(self.binary_path), "crackme.c")
            if os.path.exists(src):
                log.info("二进制不存在，尝试从源码编译...")
                ret = os.system(f'gcc "{src}" -o "{self.binary_path}" -no-pie 2>&1')
                if ret != 0:
                    return f"编译失败，返回码: {ret}"
                self.proj = angr.Project(self.binary_path, auto_load_libs=False)
            else:
                return f"错误：无法加载 {self.binary_path}，且找不到源码编译"

        info = (
            f"成功加载: {self.binary_path}\n"
            f"  架构: {self.proj.arch.name}\n"
            f"  位数: {self.proj.arch.bits}-bit\n"
            f"  入口地址: {hex(self.proj.entry)}\n"
            f"  Python 字节序: {self.proj.arch.memory_endness}"
        )
        log.info("Tool [load_binary] 执行完成")
        return info

    # ---- Tool 2: 分析函数列表 ----
    def analyze_functions(self) -> str:
        """CFG 分析，列出所有函数及其地址。"""
        if self.proj is None:
            return "错误：请先调用 load_binary 加载文件"

        self.cfg = self.proj.analyses.CFGFast()
        funcs: list[str] = []
        for addr, func in sorted(self.cfg.functions.items()):
            funcs.append(f"  {hex(addr)}: {func.name}")

        log.info("Tool [analyze_functions] 执行完成")
        return "函数列表:\n" + "\n".join(funcs)

    # ---- Tool 3: 定位关键地址 ----
    def locate_targets(self) -> str:
        """定位 success 和 trap 目标地址。"""
        if self.proj is None or self.cfg is None:
            return "错误：请先调用 load_binary 和 analyze_functions"

        # 查找 gadget_trap 函数地址
        trap_func = self.proj.loader.find_symbol("gadget_trap")
        if trap_func is None:
            try:
                trap_func = self.cfg.functions.function(name="gadget_trap")
            except Exception:
                pass
        if trap_func:
            self.trap_addr = trap_func.rebased_addr if hasattr(trap_func, "rebased_addr") else trap_func
            if hasattr(trap_func, "rebased_addr"):
                self.trap_addr = trap_func.rebased_addr
            elif isinstance(trap_func, int):
                self.trap_addr = trap_func
            else:
                self.trap_addr = trap_func.addr
        else:
            return "错误：未找到 gadget_trap 函数"

        # 查找 check_password 函数中输出 "Success!" 的基本块
        check_func = self.cfg.functions.function(name="check_password")
        if check_func is None:
            return "错误：未找到 check_password 函数"

        self.success_addr = None
        for block in check_func.blocks:
            # 反汇编基本块，查找调用 puts/printf 后紧跟 mov eax,1 的模式
            if block.capstone is None:
                continue
            insns = block.capstone.insns
            has_call = False
            for ins in insns:
                if ins.mnemonic == "call":
                    has_call = True
                if has_call and ins.mnemonic == "mov" and "1" in ins.op_str:
                    # 找到 "Success" 之后的 return 1 路径
                    # 取调用 Success 打印后的那个基本块
                    pass

            # 简化方法：通过 successors 分析
            for succ in block.successors:
                # 检查 successor 中是否有 ret 指令
                if succ.capstone is not None:
                    for ins in succ.capstone.insns:
                        if ins.mnemonic == "ret":
                            # 向前回溯找到正确路径
                            pass

        # 使用更简单的方法：通过 CFG 的节点查找
        # 在 check_password 中，Success 分支的下一个基本块就是 return 1 的块
        success_block = None
        trap_call_block = None

        for block in check_func.blocks:
            if block.capstone is None:
                continue
            insns = block.capstone.insns
            for ins in insns:
                if ins.mnemonic == "call":
                    # 检查调用目标
                    target_str = ins.op_str
                    if hasattr(ins, "reg_name"):
                        pass
                    # 通过 successors 判断
                    break

        # 更可靠的方法：通过 CFG 节点的度数和内容特征
        cfg_nodes = list(self.cfg.functions.function(name="check_password").graph.nodes())
        for node in cfg_nodes:
            if node.capstone is None:
                continue
            # 查找调用 gadget_trap 的基本块
            for ins in node.capstone.insns:
                if ins.mnemonic == "call":
                    target = ins.op_str
                    # 检查这个 call 的去向
                    break

        # 方法：通过 successors 逐块分析
        check_graph = self.cfg.functions.function(name="check_password").graph
        found_success_block = None

        for node in check_graph.nodes():
            successors = list(check_graph.successors(node))
            if node.capstone is None:
                continue
            insns_text = " ".join([ins.mnemonic for ins in node.capstone.insns])
            # 如果当前块包含 call，且其中一个 successor 是 gadget_trap
            if "call" in insns_text:
                for succ in successors:
                    if succ.addr == self.trap_addr:
                        trap_call_block = node
                        break

        # 在 CFG 中，找到 Success 的路径
        # check_password 中，Success 分支的下一条指令
        # 通过分析 CFG 的节点，找到有 "ret" 且返回值为 1 的块
        for node in check_graph.nodes():
            if node.capstone is None:
                continue
            for ins in node.capstone.insns:
                if ins.mnemonic == "mov" and ins.op_str in ("eax, 1", "eax, 0x1", "rax, 1", "eax, 1"):
                    # 这是一个 return 1 的基本块（对应 Success）
                    found_success_block = node
                    break
            if found_success_block:
                break

        # 如果上面的方法没找到，尝试找 "ret" 的前驱块中调用 puts 的
        if found_success_block is None:
            for node in check_graph.nodes():
                successors = list(check_graph.successors(node))
                for succ in successors:
                    if succ.capstone and any(
                        ins.mnemonic == "ret" for ins in succ.capstone.insns
                    ):
                        # 检查 node 是否调用了输出函数
                        if node.capstone and any(
                            ins.mnemonic == "call" for ins in node.capstone.insns
                        ):
                            # 检查 call 的目标不是 gadget_trap
                            found_success_block = succ
                            break

        if found_success_block:
            self.success_addr = found_success_block.addr
        else:
            return "错误：无法自动定位 Success 基本块地址"

        return (
            f"关键地址定位完成:\n"
            f"  Success 目标地址: {hex(self.success_addr)}\n"
            f"  Trap 避开地址:   {hex(self.trap_addr)}"
        )

    # ---- Tool 4: 符号执行探索 ----
    def symbolic_explore(self) -> str:
        """使用 SimulationManager 执行符号执行，find=success_addr, avoid=trap_addr。"""
        if self.proj is None:
            return "错误：请先加载二进制文件"
        if self.success_addr is None or self.trap_addr is None:
            return "错误：请先调用 locate_targets 定位关键地址"

        log.info(
            "开始符号执行: find=%s, avoid=%s",
            hex(self.success_addr),
            hex(self.trap_addr),
        )

        # 创建入口状态
        state = self.proj.factory.entry_state()

        # 创建 SimulationManager
        self.simgr = self.proj.factory.simulation_manager(state)

        # 执行探索：找到 success 地址，避开 trap 地址
        self.simgr.explore(
            find=self.success_addr,
            avoid=self.trap_addr,
        )

        if len(self.simgr.found) > 0:
            self.found_state = self.simgr.found[0]
            log.info("符号执行成功！找到 %d 个目标状态", len(self.simgr.found))
            return (
                f"符号执行完成:\n"
                f"  Found 状态数: {len(self.simgr.found)}\n"
                f"  Avoided 状态数: {len(self.simgr.avoid)}\n"
                f"  Active 状态数: {len(self.simgr.active)}\n"
                f"  Deadended 状态数: {len(self.simgr.deadended)}"
            )
        else:
            log.warning("符号执行未找到目标状态")
            return (
                f"符号执行完成，但未找到目标状态:\n"
                f"  Avoided: {len(self.simgr.avoid)}\n"
                f"  Active: {len(self.simgr.active)}\n"
                f"  Deadended: {len(self.simgr.deadended)}"
            )

    # ---- Tool 5: 提取密码 ----
    def extract_password(self) -> str:
        """从 found_state 中提取符号执行求解出的具体密码。"""
        if self.found_state is None:
            return "错误：没有可用的 found_state，请先执行 symbolic_explore"

        try:
            # 获取 stdin 的符号变量
            # angr 在 entry_state 中，stdin 的 fd 是 0
            stdin_fd = self.found_state.posix.get_fd(0)
            if stdin_fd is None:
                return "错误：无法获取 stdin 文件描述符"

            # 读取 stdin 中的所有数据
            stdin_data = stdin_fd.all_bytes()
            if stdin_data is None:
                return "错误：无法读取 stdin 数据"

            # 尝试求解具体值
            password_bytes = self.found_state.solver.eval(stdin_data, cast_to=bytes)

            # 清理结果：去掉 null 字节和换行符
            password = password_bytes.split(b"\x00")[0].split(b"\n")[0]
            password_str = password.decode("utf-8", errors="replace")

            log.info("成功提取密码: %s", password_str)
            return f"密码提取成功！密码为: {password_str} (hex: {password.hex()})"

        except Exception as e:
            # 备选方案：直接检查 stdin 的 read 操作
            log.warning("方案A失败，尝试方案B: %s", e)
            try:
                # 从 state 的约束中求解
                stdin_posix = self.found_state.posix
                if hasattr(stdin_posix, "dump_file"):
                    content = stdin_posix.dump_file(0)
                    if content is not None:
                        content_bytes = self.found_state.solver.eval(content, cast_to=bytes)
                        password = content_bytes.split(b"\x00")[0].split(b"\n")[0]
                        return f"密码提取成功（方案B）！密码为: {password.decode('utf-8', errors='replace')}"
            except Exception as e2:
                log.error("方案B也失败: %s", e2)

            return f"密码提取异常: {e}"


# ===================================================================
# 第二部分：ReAct Agent
# ===================================================================

SYSTEM_PROMPT = """你是一个二进制安全分析专家，你的任务是使用 angr 符号执行框架分析 crackme 程序，找到正确的密码。

## 可用工具
1. load_binary - 加载 crackme 二进制文件
2. analyze_functions - 分析所有函数及其地址
3. locate_targets - 定位 success 和 trap 的关键地址
4. symbolic_explore - 执行符号探索（find=success, avoid=trap）
5. extract_password - 从成功状态中提取密码

## ReAct 工作流程
每次响应遵循格式：
  Thought: [你对当前情况的分析和下一步计划]
  Action: [要调用的工具名称]

执行后你会收到 Observation，然后继续下一轮 Thought/Action，直到找到密码。

## 分析策略
crackme 中有三条路径：
- input[0]=='A' && input[1]=='B' → gadget_trap() 死循环（需要 avoid）
- input[0]=='A' && input[1]=='Z' → Success!（find 目标）
- 其他 → Wrong password!（deadended）

你需要找到正确的密码，使程序进入 Success 路径。

请开始分析。每次只输出一个 Thought + Action。"""


class ReactAgent:
    """ReAct (Reasoning + Acting) Agent。

    循环执行 Thought → Action → Observation，直到任务完成。
    """

    def __init__(self, tools: AngrTools, model: str = "gpt-4o"):
        self.tools = tools
        self.model = model
        self.api_key = os.environ.get("OPENAI_API_KEY", "")
        if self.api_key:
            self.client = OpenAI(api_key=self.api_key)
        else:
            self.client = None

        # 工具映射
        self.tool_map = {
            "load_binary": tools.load_binary,
            "analyze_functions": tools.analyze_functions,
            "locate_targets": tools.locate_targets,
            "symbolic_explore": tools.symbolic_explore,
            "extract_password": tools.extract_password,
        }

    def call_llm(self, messages: list[dict]) -> str:
        """调用 LLM 获取 Thought + Action。"""
        if self.client is None:
            raise RuntimeError("未设置 OPENAI_API_KEY 环境变量")

        resp = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=0.1,
            max_tokens=512,
        )
        return resp.choices[0].message.content.strip()

    def parse_action(self, response: str) -> tuple[str, str]:
        """从 LLM 响应中解析 Thought 和 Action。"""
        thought = ""
        action = ""

        for line in response.split("\n"):
            line_stripped = line.strip()
            if line_stripped.lower().startswith("thought:"):
                thought = line_stripped.split(":", 1)[1].strip()
            elif line_stripped.lower().startswith("action:"):
                action = line_stripped.split(":", 1)[1].strip()

        return thought, action

    def run(self) -> str:
        """运行 ReAct Agent 主循环。"""
        log.info("=" * 60)
        log.info("ReAct Agent 启动")
        log.info("=" * 60)

        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        max_rounds = 10
        final_password = ""

        for round_num in range(1, max_rounds + 1):
            log.info("--- Round %d ---", round_num)

            # Step 1: LLM 推理
            if round_num == 1:
                user_msg = "请开始分析 crackme 程序，找到正确的密码。"
                messages.append({"role": "user", "content": user_msg})

            try:
                response = self.call_llm(messages)
            except Exception as e:
                log.error("LLM 调用失败: %s", e)
                break

            thought, action = self.parse_action(response)
            log.info("Thought: %s", thought)
            log.info("Action:  %s", action)

            messages.append({"role": "assistant", "content": response})

            # Step 2: 执行工具
            if action in self.tool_map:
                observation = self.tool_map[action]()
            else:
                observation = f"错误：未知工具 '{action}'，可用工具: {list(self.tool_map.keys())}"

            log.info("Observation: %s", observation[:200])

            # Step 3: 反馈 Observation
            messages.append(
                {"role": "user", "content": f"Observation: {observation}"}
            )

            # Step 4: 检查是否已找到密码
            if "密码提取成功" in observation or "密码为:" in observation:
                # 从 observation 中提取密码
                for line in observation.split("\n"):
                    if "密码为:" in line:
                        final_password = line.split("密码为:")[1].strip()
                        break
                log.info("密码已找到，Agent 任务完成！")
                break

            # 检查是否陷入死循环
            if action == "extract_password" and "错误" in observation:
                log.warning("密码提取失败，可能需要重新探索")

        log.info("=" * 60)
        if final_password:
            log.info("最终密码: %s", final_password)
        else:
            log.info("Agent 未能找到密码（可能已达到最大轮次）")
        log.info("=" * 60)

        return final_password


# ===================================================================
# 第三部分：无 LLM 的纯 angr 求解（备选方案）
# ===================================================================

def solve_without_llm(binary_path: str) -> str:
    """不使用 LLM，直接使用 angr 求解密码（用于对比和验证）。"""
    log.info("=" * 60)
    log.info("纯 angr 求解模式（无 LLM）")
    log.info("=" * 60)

    tools = AngrTools(binary_path)

    # Step 1: 加载二进制
    result = tools.load_binary()
    log.info(result)
    if "错误" in result:
        return ""

    # Step 2: 分析函数
    result = tools.analyze_functions()
    log.info(result)

    # Step 3: 定位关键地址
    result = tools.locate_targets()
    log.info(result)
    if "错误" in result:
        return ""

    # Step 4: 符号执行
    result = tools.symbolic_explore()
    log.info(result)

    # Step 5: 提取密码
    result = tools.extract_password()
    log.info(result)

    return result


# ===================================================================
# 第四部分：主入口
# ===================================================================

def find_or_compile_binary(script_dir: str) -> str:
    """查找或编译 crackme 二进制文件，返回可用的路径。"""
    src_path = os.path.join(script_dir, "crackme.c")

    candidates = []
    for name in ["crackme.exe", "crackme"]:
        p = os.path.join(script_dir, name)
        candidates.append(p)
        if os.path.exists(p):
            log.info("找到二进制文件: %s", p)
            return p

    if not os.path.exists(src_path):
        log.error("找不到 crackme.c 源码文件")
        sys.exit(1)

    binary_path = candidates[0]
    log.info("编译 crackme.c ...")
    import shutil
    compiler = None
    for cmd in ["python -m ziglang cc", "gcc", "clang"]:
        if shutil.which(cmd.split()[0]) or cmd.startswith("python"):
            compiler = cmd
            break

    if compiler:
        for flags in ["", "-no-pie"]:
            cmd = f'{compiler} "{src_path}" -o "{binary_path}" {flags} 2>&1'
            ret = os.system(cmd)
            if ret == 0 and os.path.exists(binary_path):
                log.info("编译成功: %s", binary_path)
                return binary_path

    log.error("编译失败！请确保已安装 gcc 或 zig")
    sys.exit(1)


def main():
    """主函数：运行 ReAct Agent 或纯 angr 求解。"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    binary_path = find_or_compile_binary(script_dir)

    # 判断使用哪种模式
    use_llm = os.environ.get("OPENAI_API_KEY") and "--no-llm" not in sys.argv

    if use_llm:
        log.info("使用 ReAct Agent 模式（LLM 驱动）")
        tools = AngrTools(binary_path)
        agent = ReactAgent(tools)
        password = agent.run()
        if password:
            print(f"\n{'=' * 60}")
            print(f"  Agent 求解完成！密码: {password}")
            print(f"{'=' * 60}")
        else:
            log.warning("Agent 模式失败，回退到纯 angr 模式...")
            solve_without_llm(binary_path)
    else:
        log.info("使用纯 angr 模式（无 LLM）")
        solve_without_llm(binary_path)

    print("\n作业完成。请查看上方输出获取密码。")
    print(f"预期密码: AZ (前两个字符为 A 和 Z，后面任意字符均可)")


if __name__ == "__main__":
    main()
