"""
纯 angr 符号执行求解 crackme（无需 LLM）
==========================================
直接使用 angr 的 SimulationManager + find/avoid 功能，
通过符号执行自动探索二进制文件中的路径，找到正确密码。

核心原理：
  - find:   指向 "Success! Flag is found." 的基本块地址
  - avoid:  指向 gadget_trap() 函数的地址
  - angr 会自动探索所有路径，避开 avoid 地址，停在 find 地址
  - 从找到的状态中求解 stdin 的符号约束，得到具体密码
"""

import os
import sys
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("angr-solve")

try:
    import angr
except ImportError:
    log.error("angr 未安装，请执行: pip install angr")
    sys.exit(1)


def compile_crackme(src_path: str, out_path: str) -> bool:
    """编译 crackme.c。"""
    import platform

    flags = "-no-pie" if platform.system() == "Linux" else ""
    cmd = f'gcc "{src_path}" -o "{out_path}" {flags} 2>&1'
    log.info("编译命令: %s", cmd)
    ret = os.system(cmd)
    if ret != 0:
        cmd2 = f'gcc "{src_path}" -o "{out_path}" 2>&1'
        ret = os.system(cmd2)
    return ret == 0


def solve_crackme(binary_path: str):
    """使用 angr 符号执行求解 crackme 密码。

    步骤：
      1. 加载二进制文件
      2. 定位 gadget_trap (avoid) 和 Success (find) 的地址
      3. 设置 SimulationManager，执行 find/avoid 探索
      4. 从找到的状态中提取密码
    """
    log.info("=" * 60)
    log.info("angr 符号执行 — crackme 求解")
    log.info("=" * 60)

    # ---------- Step 1: 加载二进制 ----------
    log.info("\n[Step 1] 加载二进制文件: %s", binary_path)
    proj = angr.Project(binary_path, auto_load_libs=False)
    log.info("  架构: %s | %d-bit | 入口: %s",
             proj.arch.name, proj.arch.bits, hex(proj.entry))

    # ---------- Step 2: CFG 分析 ----------
    log.info("\n[Step 2] 执行 CFG 分析...")
    cfg = proj.analyses.CFGFast()

    # 列出所有函数
    log.info("  函数列表:")
    for addr in sorted(cfg.functions.keys()):
        func = cfg.functions[addr]
        log.info("    %s — %s", hex(addr), func.name)

    # ---------- Step 3: 定位 find 和 avoid 地址 ----------
    log.info("\n[Step 3] 定位关键地址...")

    # find 地址: check_password 中 "Success! Flag is found." 之后的 return 1 基本块
    # 策略: 在 check_password 的 CFG 节点中，找到 mov eax,1 后跟 ret 的基本块
    check_func = cfg.functions.function(name="check_password")
    if check_func is None:
        log.error("  未找到 check_password 函数！")
        return

    success_addr = None
    for block_addr in check_func.block_addrs_set:
        node = cfg.model.get_any_node(block_addr)
        if node is None or node.capstone is None:
            continue
        insns = node.capstone.insns
        for i, ins in enumerate(insns):
            # mov eax, 1 或类似指令，且后面紧跟 ret
            if ins.mnemonic == "mov" and ("1" in ins.op_str.split(",")[-1].strip()):
                if i + 1 < len(insns) and insns[i + 1].mnemonic == "ret":
                    success_addr = block_addr
                    break
        if success_addr:
            break

    if success_addr is None:
        log.error("  无法自动定位 Success 地址，尝试手动方法...")
        # 备选: 打印 check_password 中所有基本块信息
        log.info("  check_password 基本块列表:")
        for block_addr in check_func.block_addrs_set:
            node = cfg.model.get_any_node(block_addr)
            if node and node.capstone:
                disasm = " ; ".join(
                    f"{i.mnemonic} {i.op_str}" for i in node.capstone.insns[:5]
                )
                log.info("    %s: %s", hex(block_addr), disasm)
        return

    # avoid 地址: gadget_trap 函数入口
    trap_func = cfg.functions.function(name="gadget_trap")
    if trap_func is None:
        log.error("  未找到 gadget_trap 函数！")
        return
    avoid_addr = trap_func.addr

    log.info("  find  (Success): %s", hex(success_addr))
    log.info("  avoid (Trap):    %s", hex(avoid_addr))

    # ---------- Step 4: 符号执行探索 ----------
    log.info("\n[Step 4] 开始符号执行探索...")
    log.info("  find=%s, avoid=%s", hex(success_addr), hex(avoid_addr))

    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=success_addr, avoid=avoid_addr)

    log.info("  结果:")
    log.info("    Found:     %d", len(simgr.found))
    log.info("    Avoided:   %d", len(simgr.avoid))
    log.info("    Active:    %d", len(simgr.active))
    log.info("    Deadended: %d", len(simgr.deadended))

    if len(simgr.found) == 0:
        log.error("  未找到目标状态！")
        return

    # ---------- Step 5: 提取密码 ----------
    log.info("\n[Step 5] 提取密码...")
    found_state = simgr.found[0]

    try:
        # 从 stdin 读取符号数据并求解
        stdin_data = found_state.posix.stdin.content
        if stdin_data is not None:
            password_bytes = found_state.solver.eval(
                stdin_data[found_state.posix.stdin.pos:],
                cast_to=bytes,
            )
        else:
            # 备选方案
            stdin_fd = found_state.posix.get_fd(0)
            all_data = stdin_fd.all_bytes()
            password_bytes = found_state.solver.eval(all_data, cast_to=bytes)
    except Exception as e:
        log.warning("  标准方法失败 (%s)，尝试备选方案...", e)
        try:
            # 直接读取 stdin 文件内容
            simfile = found_state.posix.stdin
            content = simfile.content
            password_bytes = found_state.solver.eval(content, cast_to=bytes)
        except Exception as e2:
            log.error("  所有方法均失败: %s", e2)
            return

    # 清理结果
    password = password_bytes.split(b"\x00")[0].split(b"\n")[0]
    password_str = password.decode("utf-8", errors="replace")

    log.info("=" * 60)
    log.info("  求解成功！")
    log.info("  密码: %s", password_str)
    log.info("  Hex:  %s", password.hex())
    log.info("=" * 60)
    return password_str


def find_or_compile_binary(script_dir: str) -> str:
    """查找或编译 crackme 二进制文件，返回可用的路径。"""
    src_path = os.path.join(script_dir, "crackme.c")

    # 尝试多个可能的二进制文件名
    candidates = []
    for name in ["crackme.exe", "crackme"]:
        p = os.path.join(script_dir, name)
        candidates.append(p)
        if os.path.exists(p):
            log.info("找到二进制文件: %s", p)
            return p

    # 没有二进制，尝试编译
    if not os.path.exists(src_path):
        log.error("找不到 crackme.c，请确保源码文件存在")
        sys.exit(1)

    binary_path = candidates[0]  # 默认用 crackme.exe

    log.info("正在编译 crackme.c ...")
    # 优先用 zig，其次用 gcc
    import shutil
    compiler = None
    for cmd in ["python -m ziglang cc", "gcc", "clang"]:
        if shutil.which(cmd.split()[0]) or cmd.startswith("python"):
            compiler = cmd
            break

    if compiler:
        flags = "-no-pie" if compiler != "python -m ziglang cc" else ""
        cmd = f'{compiler} "{src_path}" -o "{binary_path}" {flags} 2>&1'
        log.info("编译命令: %s", cmd)
        ret = os.system(cmd)
        if ret == 0 and os.path.exists(binary_path):
            log.info("编译成功: %s", binary_path)
            return binary_path
        # 不带 flags 重试
        cmd = f'{compiler} "{src_path}" -o "{binary_path}" 2>&1'
        ret = os.system(cmd)
        if ret == 0 and os.path.exists(binary_path):
            log.info("编译成功: %s", binary_path)
            return binary_path

    log.error("编译失败！请确保已安装 gcc 或 zig")
    sys.exit(1)


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    binary_path = find_or_compile_binary(script_dir)
    solve_crackme(binary_path)


if __name__ == "__main__":
    main()
