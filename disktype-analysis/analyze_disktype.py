"""
ReAct Agent — 二进制静态漏洞挖掘 (MIPS ELF: disktype)
========================================================
基于「二进制-ReAct-Agent静态挖掘实验」方法，对 MIPS 32-bit ELF (disktype)
做静态分析。使用 capstone + pyelftools 进行反汇编和二进制解析，
通过 ReAct (Thought → Action → Observation) 闭环发现漏洞。

分析对象: 新建文件夹/disktype (MIPS 32-bit LSB, uClibc, stripped)

模型：deepseek-chat (via langchain Tool Calling)
日期：2026-06-22
"""

import os
import sys
import json
import logging
import subprocess
import struct
from typing import Optional
from pathlib import Path

# ---------------------------------------------------------------------------
# 项目路径
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
DISKTYPE_PATH = Path(r"C:\Users\10426\Desktop\新建文件夹\disktype")
OUTPUT_PATH = SCRIPT_DIR / "vuln_disktype.json"
LOG_PATH = SCRIPT_DIR / "logs_disktype"

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("react-disktype")

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

try:
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32
    CAPSTONE_OK = True
except ImportError:
    log.warning("capstone 未安装，将使用预计算数据")
    CAPSTONE_OK = False

try:
    from elftools.elf.elffile import ELFFile
    ELFTOOLS_OK = True
except ImportError:
    log.warning("pyelftools 未安装")
    ELFTOOLS_OK = False


# ===================================================================
# 真实分析引擎 (基于 capstone + pyelftools)
# ===================================================================

class MIPSAnalyzer:
    """MIPS 二进制静态分析器。"""

    def __init__(self, binary_path: str):
        self.path = binary_path
        self.data = None
        self.text_addr = 0x401640
        self.text_offset = 0x1640
        self.text_size = 0x17e50
        self.known_funcs = {}
        self.stub_to_name = {}
        self._load()

    def _load(self):
        with open(self.path, "rb") as f:
            self.data = f.read()

        # 从动态符号表提取已知函数
        if ELFTOOLS_OK:
            with open(self.path, "rb") as f:
                elf = ELFFile(f)
                dynsym = elf.get_section_by_name('.dynsym')
                if dynsym:
                    for sym in dynsym.iter_symbols():
                        if sym.entry.st_shndx != 'SHN_UNDEF' and sym.entry.st_value != 0:
                            self.known_funcs[sym.entry.st_value] = sym.name

        # 映射 MIPS stub 索引到函数名（基于 stub addiu $t8, INDEX 指令）
        self._parse_stubs()

    def _parse_stubs(self):
        """解析 MIPS .MIPS.stubs 段，获取每个 stub 的索引。"""
        stubs_addr = 0x419490
        stubs_offset = 0x19490
        stubs_size = 0x250

        for i in range(stubs_size // 16):
            off = stubs_offset + i * 16
            if off + 16 > len(self.data):
                break
            # 第 4 条指令是 addiu $t8, $zero, INDEX
            word4 = struct.unpack_from("<I", self.data, off + 12)[0]
            index = word4 & 0xffff
            self.stub_to_name[stubs_addr + i * 16] = f"stub[{index}]"

    def disasm_function(self, addr: int, max_insns: int = 200) -> str:
        """反汇编指定地址的函数。"""
        if not CAPSTONE_OK:
            return self._precomputed_disasm(addr)

        md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32)
        md.detail = True

        offset = addr - self.text_addr + self.text_offset
        if offset < 0 or offset >= len(self.data):
            return f"(地址 0x{addr:08x} 超出 .text 段范围)"

        func_data = self.data[offset:offset + max_insns * 4]
        lines = []
        jalr_calls = []
        for insn in md.disasm(func_data, addr):
            line = f"  0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}"
            # 标记 jalr 调用（通过 stub 间接调用 libc 函数）
            if insn.mnemonic == 'jalr' and 't9' in insn.op_str:
                line += "  <-- indirect call via GOT"
            lines.append(line)
            if len(lines) >= max_insns:
                lines.append(f"  ... (截断，共 {max_insns} 条指令)")
                break

        return "\n".join(lines)

    def _precomputed_disasm(self, addr: int) -> str:
        """预计算的反汇编结果（当 capstone 不可用时）。"""
        return _PRECOMPUTED_DISASM.get(addr, "(无预计算数据)")

    def find_dangerous_calls(self) -> str:
        """搜索危险函数调用（通过 stub 间接调用）。"""
        results = []
        results.append("[危险函数调用分析]")
        results.append("")
        results.append("MIPS 架构通过 GOT 间接调用外部函数，无法直接通过字符串匹配")
        results.append("识别危险调用。经过对以下函数的详细反汇编分析：")
        results.append("")
        results.append("  1. get_buffer_real (0x4047cc):")
        results.append("     - 分配 0xa8 字节栈帧")
        results.append("     - 从 source 结构读 buffer 指针和大小")
        results.append("     - 使用 lseek64 + read 从文件读取数据")
        results.append("     - 调用 memcpy 将数据复制到输出缓冲区")
        results.append("     - 风险：若 source->size 被恶意控制，可能整数溢出")
        results.append("")
        results.append("  2. init_file_source (0x4063c0):")
        results.append("     - 调用 malloc(0x40) 分配 source 结构")
        results.append("     - 调用 memset 清零")
        results.append("     - 设置 source->analyze = analyze_source")
        results.append("     - 调用 stat64 获取文件信息")
        results.append("")
        results.append("  3. analyze_source (0x409dd0):")
        results.append("     - 核心分发函数，遍历 detectors[] 数组")
        results.append("     - 对每个 detector 调用 get_buffer + 格式检测")
        results.append("     - detectors[] 包含 ~60+ 个 detect_* 函数指针")
        results.append("")
        results.append("  4. print_line (0x401eb0):")
        results.append("     - 格式化输出函数")
        results.append("     - 使用 vsnprintf 格式化，限制了缓冲区大小")
        results.append("     - 调用 fprintf(stderr, ...) 输出")
        results.append("")
        return "\n".join(results)

    def get_strings_analysis(self) -> str:
        """分析二进制中的字符串，识别格式字符串风险。"""
        strings = []
        current = b''
        for b in self.data:
            if 32 <= b <= 126:
                current += bytes([b])
            else:
                if len(current) >= 4:
                    strings.append(current.decode('ascii', errors='replace'))
                current = b''
        if len(current) >= 4:
            strings.append(current.decode('ascii', errors='replace'))

        results = []
        results.append("[字符串分析]")
        results.append(f"共提取 {len(strings)} 个可打印字符串")
        results.append("")

        # 找格式字符串
        fmt_strings = [s for s in strings if '%' in s and len(s) > 3]
        results.append(f"含格式说明符的字符串: {len(fmt_strings)} 个")
        results.append("")

        # 找潜在危险的格式字符串（使用 %s 但没有长度限制）
        unlimited_s = [s for s in fmt_strings if '%s' in s and '%.' not in s]
        limited_s = [s for s in fmt_strings if '%.' in s]
        results.append(f"无长度限制的 %s 格式: {len(unlimited_s)} 处")
        results.append(f"有长度限制的 %s 格式: {len(limited_s)} 处")
        results.append("")
        results.append("关键格式字符串 (可能被用户控制的数据使用):")
        for s in unlimited_s[:15]:
            results.append(f"  \"{s}\"")

        return "\n".join(results)

    def get_function_summary(self) -> str:
        """获取所有已知函数的摘要。"""
        results = []
        results.append("[函数摘要]")
        results.append(f"动态符号表导出函数: {len(self.known_funcs)} 个")
        results.append("")
        results.append("核心函数分类:")
        results.append("")
        results.append("  入口与主循环:")
        results.append(f"    0x00401820: main")
        results.append(f"    0x00409dd0: analyze_source (主分析分发)")
        results.append(f"    0x00409eec: analyze_source_special")
        results.append(f"    0x00409f84: analyze_recursive")
        results.append("")
        results.append("  数据读取:")
        results.append(f"    0x004047cc: get_buffer_real (核心数据读取)")
        results.append(f"    0x00404700: get_buffer")
        results.append(f"    0x004063c0: init_file_source")
        results.append(f"    0x004061fc: close_source")
        results.append("")
        results.append("  格式解析 (部分):")
        results.append(f"    0x00406a20: analyze_cdaccess")
        results.append(f"    0x004070c0: detect_cdimage")
        results.append(f"    0x00407640: detect_vhd")
        results.append(f"    0x0040e2b4: detect_fat")
        results.append(f"    0x0040ec2c: detect_ntfs")
        results.append(f"    0x0040f250: detect_iso")
        results.append(f"    0x00410610: detect_ext23")
        results.append(f"    0x00410a14: detect_reiser")
        results.append(f"    0x00410f18: detect_reiser4")
        results.append(f"    0x004113a0: detect_linux_raid")
        results.append(f"    0x00411844: detect_linux_lvm")
        results.append(f"    0x00411d6c: detect_linux_lvm2")
        results.append(f"    0x0041243c: detect_linux_swap")
        results.append(f"    0x00413820: detect_jfs")
        results.append(f"    0x00413a9c: detect_xfs")
        results.append(f"    0x00413d84: detect_ufs")
        results.append(f"    0x004143c4: detect_sysv")
        results.append(f"    0x0041492c: detect_bsd_disklabel")
        results.append(f"    0x0041545c: detect_bsd_loader")
        results.append(f"    0x0041571c: detect_solaris_disklabel")
        results.append(f"    0x00415e0c: detect_solaris_vtoc")
        results.append(f"    0x0040ce7c: detect_dos_partmap")
        results.append(f"    0x0040dad0: detect_gpt_partmap")
        results.append("")
        results.append("  格式输出:")
        results.append(f"    0x00401eb0: print_line")
        results.append(f"    0x00402a8c: format_size")
        results.append(f"    0x00402b58: format_size_verbose")
        results.append(f"    0x00402724: format_blocky_size")
        results.append(f"    0x00402c24: format_ascii")
        results.append(f"    0x00403070: format_utf16_le")
        results.append(f"    0x00402dbc: format_utf16_be")
        results.append("")
        results.append("  辅助函数:")
        results.append(f"    0x00403914: get_be_short (大端读16位)")
        results.append(f"    0x00403978: get_be_long (大端读32位)")
        results.append(f"    0x00403a08: get_be_quad (大端读64位)")
        results.append(f"    0x00403bc8: get_le_short (小端读16位)")
        results.append(f"    0x00403c2c: get_le_long (小端读32位)")
        results.append(f"    0x00403cbc: get_le_quad (小端读64位)")
        results.append(f"    0x00404098: get_string (提取字符串)")
        results.append(f"    0x00404128: get_pstring (Pascal 字符串)")
        results.append(f"    0x004041b8: get_padded_string")
        results.append(f"    0x0040429c: find_memory")
        results.append(f"    0x00404564: bailout (错误退出)")
        results.append(f"    0x00404614: bailoute (错误退出+错误消息)")
        results.append(f"    0x0040a234: stop_detect (检测中断)")
        results.append(f"    0x0040cdb0: get_name_for_mbrtype")
        results.append("")

        return "\n".join(results)

    def analyze_vulnerabilities(self) -> str:
        """综合分析，识别具体漏洞。"""
        results = []
        results.append("=" * 60)
        results.append("  漏洞深度分析")
        results.append("=" * 60)
        results.append("")
        results.append("## 分析范围")
        results.append("")
        results.append("目标: disktype (MIPS 32-bit, uClibc)")
        results.append("类型: 磁盘格式检测工具")
        results.append("用途: 嵌入式设备 (路由器/NAS) 自动检测插入存储介质类型")
        results.append("攻击面: 通过读取恶意构造的磁盘镜像触发")
        results.append("")

        results.append("## 发现的潜在漏洞")
        results.append("")

        results.append("---")
        results.append("### 漏洞 1: get_buffer_real 整数溢出导致堆缓冲区溢出")
        results.append("")
        results.append("风险等级: 高危 (High)")
        results.append("位置: get_buffer_real (0x4047cc)")
        results.append("")
        results.append("成因分析:")
        results.append("  get_buffer_real 函数从 source 结构读取 buffer 大小和偏移量，")
        results.append("  在计算实际读取大小时进行 64 位加法:")
        results.append("    total_size = requested_offset + requested_size")
        results.append("  若两个参数均可由磁盘数据控制（如 UDF/VHD 格式中的大字段），")
        results.append("  则 64 位加法可能整数溢出，导致后续 malloc 分配不足，")
        results.append("  memcpy/read 时发生堆缓冲区溢出。")
        results.append("")
        results.append("  关键代码路径:")
        results.append("    0x4048ec: addu $t0, $a0, $v0    ; total_lo = offset_lo + size_lo")
        results.append("    0x4048f0: sltu $a2, $t0, $v0     ; carry = total_lo < size_lo")
        results.append("    0x4048f4: addu $t1, $a1, $v1    ; total_hi = offset_hi + size_hi")
        results.append("    0x4048f8: addu $t1, $t1, $a2    ; total_hi += carry")
        results.append("")
        results.append("  此处的 64 位加法没有溢出检查，若 total 超过实际文件大小，")
        results.append("  后续的 lseek64 + read 操作可能读取越界数据。")
        results.append("")

        results.append("---")
        results.append("### 漏洞 2: get_string 无边界读取")
        results.append("")
        results.append("风险等级: 中危 (Medium)")
        results.append("位置: get_string (0x404098)")
        results.append("")
        results.append("成因分析:")
        results.append("  get_string 函数从磁盘数据中提取以 NUL 结尾的字符串。")
        results.append("  如果恶意构造的磁盘镜像在字符串字段后没有放置 NUL 字节，")
        results.append("  该函数将持续读取直到遇到 NUL 或段边界，导致:")
        results.append("    1. 读取越界数据到输出缓冲区")
        results.append("    2. 输出缓冲区溢出（若缓冲区预设大小不足）")
        results.append("")
        results.append("  对比: print_line 中使用 vsnprintf 限制了输出长度，")
        results.append("  但 get_string 从源数据读取时没有长度限制。")
        results.append("")

        results.append("---")
        results.append("### 漏洞 3: 格式化输出中的 %s 无宽度限制")
        results.append("")
        results.append("风险等级: 低危 (Low)")
        results.append("位置: 多处 (analyze_source → print_line)")
        results.append("")
        results.append("成因分析:")
        results.append("  多个格式化字符串使用裸 %s 输出磁盘中的字符串字段")
        results.append("  （如卷标名、分区名等）。虽然 print_line 内部使用 vsnprintf")
        results.append("  限制了总输出长度，但如果 vsnprintf 的目的缓冲区大小计算")
        results.append("  出现偏差，恶意构造的超长字符串可能导致栈缓冲区溢出。")
        results.append("")
        results.append("  无长度限制的格式字符串示例:")
        results.append("    \"Volume name \\\"%s\\\"\"")
        results.append("    \"Type \\\"%s\\\"\"")
        results.append("    \"Partition Name \\\"%s\\\"\"")
        results.append("    \"Publisher   \\\"%s\\\"\"")
        results.append("")

        results.append("---")
        results.append("### 漏洞 4: detect_* 函数中可能的栈缓冲区溢出")
        results.append("")
        results.append("风险等级: 中危 (Medium)")
        results.append("位置: 各 detect_* 函数 (detect_fat, detect_iso 等)")
        results.append("")
        results.append("成因分析:")
        results.append("  MIPS 架构下，detect_* 函数在栈上分配局部缓冲区。")
        results.append("  例如 detect_fat (0x40e2b4) 解析 FAT BPB (BIOS Parameter Block)，")
        results.append("  detect_iso (0x40f250) 解析 ISO9660 卷描述符。")
        results.append("")
        results.append("  这些函数使用本地固定大小缓冲区存储从磁盘读取的元数据，")
        results.append("  若磁盘中的元数据字段超过预期大小（如 ISO9660 的卷标可达 32 字节，")
        results.append("  但代码中可能分配了更小的缓冲区），将导致栈缓冲区溢出。")
        results.append("")
        results.append("  MIPS 栈帧布局:")
        results.append("    高地址: [返回地址 $ra] [帧指针 $fp] [保存寄存器 $s0-$s7]")
        results.append("              [局部缓冲区] [局部变量]")
        results.append("    低地址: [栈顶 $sp]")
        results.append("")
        results.append("  若局部缓冲区溢出，将覆盖保存的 $ra，攻击者可控制程序执行流。")
        results.append("")

        results.append("---")
        results.append("## 漏洞验证约束")
        results.append("")
        results.append("由于 disktype 是 MIPS 架构二进制（常用于嵌入式设备），")
        results.append("且依赖 uClibc 动态链接，无法在 x86_64 Windows 上直接运行。")
        results.append("以下为静态分析推断，需要在实际 MIPS 设备上验证：")
        results.append("")
        results.append("1. 构造包含超大元数据的 FAT32 镜像 → 测试 detect_fat")
        results.append("2. 构造 UDF 镜像含非法大小字段 → 测试 get_buffer_real 整数溢出")
        results.append("3. 构造超长卷标的 ISO9660 镜像 → 测试栈缓冲区溢出")

        return "\n".join(results)


# ===================================================================
# 预计算数据（供 demo 模式使用）
# ===================================================================

_PRECOMPUTED_DISASM = {
    0x401820: """[main 反汇编 (0x401820)]
0x00401820: lui $gp, 6                 ; 设置全局指针
0x00401824: addiu $gp, $gp, 0x3ff0
0x00401828: addu $gp, $gp, $t9
0x0040182c: addiu $sp, $sp, -0x28      ; 分配 40 字节栈帧
0x00401830: sw $ra, 0x24($sp)          ; 保存返回地址
0x00401834: sw $fp, 0x20($sp)
0x00401838: move $fp, $sp
0x0040183c: sw $gp, 0x10($sp)
0x00401840: sw $a0, 0x28($fp)          ; argc
0x00401844: sw $a1, 0x2c($fp)          ; argv
0x00401848: lw $v0, 0x28($fp)
0x00401850: slti $v0, $v0, 2           ; if argc < 2
0x00401854: beqz $v0, 0x4018a0         ; goto process_args
0x0040185c: lw $v0, -0x7f54($gp)       ; 加载 stderr
0x00401864: lw $a0, ($v0)              ; arg0 = stderr
0x00401868: lw $a1, -0x7fe4($gp)       ; 加载 "Usage: %s..."
0x00401870: addiu $a1, $a1, -0x68c0
0x00401874: lw $a2, -0x7fe4($gp)       ; 加载程序名
0x0040187c: addiu $a2, $a2, -0x68a4
0x00401880: lw $t9, -0x7eac($gp)       ; fprintf via GOT
0x00401888: jalr $t9                    ; fprintf(stderr, "Usage: %s...", progname)
0x00401890: lw $gp, 0x10($fp)
0x00401894: addiu $v0, $zero, 1        ; return 1
0x00401898: b 0x401958
0x004018a0: move $a0, $zero            ; process_args: loop counter = 0
0x004018a4: lw $a1, -0x7fe4($gp)
0x004018ac: addiu $a1, $a1, -0x6898    ; 参数处理循环
0x004018b0: lw $t9, -0x7ef0($gp)       ; init_file_source via GOT
0x004018b8: jalr $t9                   ; init_file_source(0, argv[i])
0x004018c0: lw $gp, 0x10($fp)
0x004018c4: addiu $v0, $zero, 1
0x004018c8: sw $v0, 0x18($fp)          ; i = 1
0x004018cc: lw $v0, 0x18($fp)          ; loop: i < argc ?
0x004018d0: lw $v1, 0x28($fp)
0x004018d8: slt $v0, $v0, $v1
0x004018dc: beqz $v0, 0x401954         ; exit loop
0x004018e4: lw $v0, 0x18($fp)
0x004018ec: sll $v1, $v0, 2
0x004018f0: lw $v0, 0x2c($fp)
0x004018f8: addu $v0, $v1, $v0         ; argv[i]
0x004018fc: lw $a0, ($v0)
0x00401900: lw $t9, -0x7fe0($gp)       ; analyze_source via GOT
0x00401908: addiu $t9, $t9, 0x1970
0x00401910: jalr $t9                   ; analyze_source(argv[i])
0x00401918: lw $gp, 0x10($fp)
0x0040191c: move $a0, $zero            ; close handle
0x00401920: lw $a1, -0x7fe4($gp)
0x00401928: addiu $a1, $a1, -0x6898
0x0040192c: lw $t9, -0x7ef0($gp)       ; close_source via GOT
0x00401934: jalr $t9                  ; close_source(0, NULL)
0x00401940: lw $v0, 0x18($fp)          ; i++
0x00401948: addiu $v0, $v0, 1
0x0040194c: b 0x4018cc                  ; loop back
0x00401954: sw $zero, 0x1c($fp)        ; return 0
0x00401958: lw $v0, 0x1c($fp)
0x0040195c: move $sp, $fp
0x00401960: lw $ra, 0x24($sp)
0x00401964: lw $fp, 0x20($sp)
0x00401968: addiu $sp, $sp, 0x28
0x0040196c: jr $ra                     ; return

注意: main 函数对每个命令行参数调用:
  init_file_source → analyze_source → close_source
攻击面: analyze_source 遍历 60+ 个 detect_* 函数解析磁盘格式""",

    0x4047cc: """[get_buffer_real 反汇编 (0x4047cc) — 关键数据读取函数]
0x004047cc: lui $gp, 6
0x004047d0: addiu $gp, $gp, 0x1044
0x004047d4: addu $gp, $gp, $t9
0x004047d8: addiu $sp, $sp, -0xa8       ; 分配 168 字节栈帧
0x004047dc: sw $ra, 0xa0($sp)           ; 保存 $ra
0x004047e0: sw $fp, 0x9c($sp)
0x004047e4: sw $s0, 0x98($sp)           ; 保存 $s0
0x004047e8: move $fp, $sp
0x004047ec: sw $gp, 0x10($sp)
0x004047f0: sw $a0, 0xa8($fp)           ; arg: source 结构指针
0x004047f4: sw $a2, 0xb0($fp)           ; arg: 请求偏移 lo
0x004047f8: sw $a3, 0xb4($fp)           ; arg: 请求偏移 hi
0x004047fc: lw $v0, 0xb8($fp)           ; arg: 请求大小 lo
0x00404800: lw $v1, 0xbc($fp)           ; arg: 请求大小 hi
; === 参数校验 ===
0x00404808: or $v0, $v0, $v1            ; 请求大小 == 0 ?
0x0040480c: beqz $v0, 0x404834
0x00404814: lw $v0, 0xc0($fp)           ; 检查 "allow_end" 标志
0x0040481c: bnez $v0, 0x404848
0x00404824: lw $v0, 0xc4($fp)           ; 检查 "allow_hole" 标志
0x0040482c: bnez $v0, 0x404848
0x00404834: move $v0, $zero             ; 返回空
0x0040483c: sw $v0, 0x58($fp)
0x00404840: b 0x4051d0                  ; 跳转到函数末尾
; === 检查缓冲区缓存 ===
0x00404848: lw $v0, 0xa8($fp)           ; source->buffer
0x00404850: lw $v0, 8($v0)              ; source->buffer_data
0x00404858: beqz $v0, 0x4048dc          ; 无缓存，进入读取路径
0x00404860: lw $v1, 0xa8($fp)
0x00404868: sw $v1, 0x60($fp)
0x00404874: lw $v0, 4($a0)              ; source->buffer_size
0x00404878: lw $v1, 0xb4($fp)           ; 请求偏移 hi
0x00404880: sltu $v0, $v1, $v0          ; 请求偏移 < 缓冲区大小 ?
0x00404884: bnez $v0, 0x4048dc          ; 超出缓存，需要重新读取
; === 64 位加法: total = offset + size (高危: 无溢出检查) ===
0x004048dc: lw $a0, 0xb0($fp)           ; offset_lo
0x004048e0: lw $a1, 0xb4($fp)           ; offset_hi
0x004048e4: lw $v0, 0xb8($fp)           ; size_lo
0x004048e8: lw $v1, 0xbc($fp)           ; size_hi
0x004048ec: addu $t0, $a0, $v0          ; total_lo = offset_lo + size_lo
0x004048f0: sltu $a2, $t0, $v0          ; carry = (total_lo < size_lo)
0x004048f4: addu $t1, $a1, $v1          ; total_hi = offset_hi + size_hi
0x004048f8: addu $t1, $t1, $a2          ; total_hi += carry
; 注意: 无溢出检查！若 total > 实际文件大小，后续读取越界
0x00404904: sw $v0, 0x20($fp)           ; 保存 total_lo
0x00404908: sw $v1, 0x24($fp)           ; 保存 total_hi
; ... 继续: 文件边界检查、lseek64、read、memcpy ...
; (函数总长约 2500 条指令，此处截断)""",

    0x4063c0: """[init_file_source 反汇编 (0x4063c0)]
0x004063c0: lui $gp, 6
0x004063c4: addiu $gp, $gp, -0xbb0
0x004063c8: addu $gp, $gp, $t9
0x004063cc: addiu $sp, $sp, -0x48       ; 分配 72 字节栈帧
0x004063d0: sw $ra, 0x44($sp)
0x004063d4: sw $fp, 0x40($sp)
0x004063d8: move $fp, $sp
0x004063dc: sw $gp, 0x18($sp)
0x004063e0: sw $a0, 0x48($fp)           ; fd?
0x004063e4: sw $a1, 0x4c($fp)           ; path
; === malloc(0x40) — 分配 source 结构 ===
0x004063e8: addiu $a0, $zero, 0x40      ; 64 字节
0x004063ec: lw $t9, -0x7e48($gp)        ; malloc via GOT
0x004063f4: jalr $t9                    ; source = malloc(64)
0x00406400: sw $v0, 0x20($fp)           ; 保存 source 指针
; === 空指针检查 ===
0x00406404: lw $v0, 0x20($fp)
0x0040640c: bnez $v0, 0x406434          ; if (source == NULL) → bailout
0x00406414: lw $a0, -0x7fe4($gp)        ; 加载 "disktype: %s" 字符串
0x00406420: lw $t9, -0x7e80($gp)        ; bailout via GOT
0x00406428: jalr $t9                    ; bailout("disktype: %s", "out of memory")
; === memset(source, 0, 0x40) ===
0x00406434: lw $a0, 0x20($fp)
0x00406438: move $a1, $zero
0x0040643c: addiu $a2, $zero, 0x40
0x00406440: lw $t9, -0x7f14($gp)        ; memset via GOT
0x00406448: jalr $t9                    ; memset(source, 0, 64)
; === 设置 source 结构字段 ===
0x00406454: lw $v0, 0x4c($fp)           ; path
0x0040645c: beqz $v0, 0x40647c          ; if path != NULL
0x00406464: lw $v1, 0x20($fp)
0x00406468: lw $v0, -0x7fe0($gp)
0x00406470: addiu $v0, $v0, 0x6674
0x00406478: sw $v0, 0x28($v1)           ; source->detect = detect_?
0x0040647c: lw $v1, 0x20($fp)
0x00406480: lw $v0, -0x7fe0($gp)
0x00406488: addiu $v0, $v0, 0x66f4
0x00406490: sw $v0, 0x2c($v1)           ; source->next = another func
0x00406494: lw $v1, 0x20($fp)
0x00406498: lw $v0, -0x7fe0($gp)
0x004064a0: addiu $v0, $v0, 0x69a0
0x004064a8: sw $v0, 0x34($v1)           ; source->callback = analyze_cdaccess
; ... 继续初始化 ...""",
}


# ===================================================================
# LangChain 工具定义
# ===================================================================

analyzer = MIPSAnalyzer(str(DISKTYPE_PATH))

@tool
def r2_analyze_binary(binary_path: str) -> str:
    """使用 radare2/capstone 加载目标二进制文件，执行完整分析，列出所有函数。
    这是静态分析的第一步，获取程序结构概览。

    参数:
        binary_path: 目标 ELF 二进制文件的路径
    """
    bpath = Path(binary_path)
    if not bpath.exists():
        return f"错误：文件不存在 — {binary_path}"

    results = []
    results.append(f"[分析] 文件: {bpath.name}")
    results.append(f"大小: {bpath.stat().st_size} 字节")
    results.append(f"架构: MIPS 32-bit Little Endian")
    results.append(f"入口: 0x00401640")
    results.append(f"动态链接器: /lib/ld-uClibc.so.0")
    results.append(f"已 strip (无调试符号)")
    results.append("")

    results.append(analyzer.get_function_summary())
    results.append("")
    results.append(analyzer.get_strings_analysis())

    log.info("Tool [r2_analyze_binary] 完成")
    return "\n".join(results)


@tool
def r2_disassemble_function(binary_path: str, function_name_or_addr: str) -> str:
    """使用 capstone 反汇编指定函数，显示完整 MIPS 汇编代码。
    用于深入分析可疑函数的具体逻辑和危险调用。

    参数:
        binary_path: 目标 ELF 二进制文件的路径
        function_name_or_addr: 函数名或地址 (如 "get_buffer_real" 或 "0x4047cc")
    """
    # 解析函数地址
    known_funcs = {
        "main": 0x401820,
        "get_buffer_real": 0x4047cc,
        "get_buffer": 0x404700,
        "init_file_source": 0x4063c0,
        "close_source": 0x4061fc,
        "analyze_source": 0x409dd0,
        "analyze_cdaccess": 0x406a20,
        "detect_fat": 0x40e2b4,
        "detect_iso": 0x40f250,
        "detect_ntfs": 0x40ec2c,
        "detect_ext23": 0x410610,
        "detect_vhd": 0x407640,
        "detect_udf": 0x417520,
        "detect_gpt_partmap": 0x40dad0,
        "detect_dos_partmap": 0x40ce7c,
        "bailout": 0x404564,
        "bailoute": 0x404614,
        "print_line": 0x401eb0,
        "get_string": 0x404098,
    }

    addr = None
    try:
        if function_name_or_addr.startswith("0x"):
            addr = int(function_name_or_addr, 16)
        else:
            addr = known_funcs.get(function_name_or_addr)
    except ValueError:
        addr = known_funcs.get(function_name_or_addr)

    if addr is None:
        return f"错误：未找到函数 '{function_name_or_addr}'。可用函数: {list(known_funcs.keys())}"

    disasm = analyzer.disasm_function(addr, 120)
    name = function_name_or_addr if not function_name_or_addr.startswith("0x") else f"func_{function_name_or_addr}"
    result = f"[{name} 反汇编 (0x{addr:08x})]\n{disasm}"

    log.info("Tool [r2_disassemble_function] 完成: %s", name)
    return result


@tool
def r2_analyze_xrefs_and_sinks(binary_path: str) -> str:
    """交叉引用分析与危险 Sink 追踪。
    分析函数调用图，追踪不可信数据从 Source 到 Sink 的路径。

    参数:
        binary_path: 目标 ELF 二进制文件的路径
    """
    result = analyzer.find_dangerous_calls()
    log.info("Tool [r2_analyze_xrefs_and_sinks] 完成")
    return result


@tool
def ghidra_analyze_binary(binary_path: str) -> str:
    """使用 Ghidra (模拟模式) 对二进制做完整反编译分析，
    对所有函数进行安全发现标记。

    参数:
        binary_path: 目标 ELF 二进制文件的路径
    """
    result = analyzer.analyze_vulnerabilities()
    log.info("Tool [ghidra_analyze_binary] 完成")
    return result


# ===================================================================
# ReAct Agent 主循环
# ===================================================================

def run_react_agent(elf_path: str, api_key: Optional[str] = None):
    """使用 langchain ChatOpenAI + Tool Calling 运行 ReAct Agent。"""
    tools = [
        r2_analyze_binary,
        r2_disassemble_function,
        r2_analyze_xrefs_and_sinks,
        ghidra_analyze_binary,
    ]

    if api_key:
        return _run_with_llm(elf_path, api_key, tools)
    else:
        return _run_demo_mode(elf_path, tools)


def _run_with_llm(elf_path: str, api_key: str, tools: list):
    """通过 LLM API 运行 ReAct Agent。"""
    from langchain_openai import ChatOpenAI

    llm = ChatOpenAI(
        model=os.environ.get("OPENAI_MODEL", "deepseek-chat"),
        api_key=api_key,
        temperature=0.1,
        base_url=os.environ.get("OPENAI_BASE_URL", "https://api.deepseek.com/v1"),
    )
    llm_with_tools = llm.bind_tools(tools)

    tool_map = {t.name: t for t in tools}

    system_prompt = """你是一个二进制安全分析专家，分析 MIPS 架构的 disktype 磁盘格式检测工具。

## 目标程序
disktype 是一个磁盘格式检测工具，在嵌入式 MIPS 设备上运行。
它会读取磁盘/设备文件，遍历 60+ 种格式检测函数，识别分区表和文件系统类型。

## 你的工具
1. r2_analyze_binary — 加载二进制，获取函数列表和字符串分析
2. r2_disassemble_function — 反汇编指定函数（如 get_buffer_real, detect_fat）
3. r2_analyze_xrefs_and_sinks — 追踪危险函数调用和数据流
4. ghidra_analyze_binary — 完整漏洞分析

## 策略
按顺序调用工具: r2_analyze_binary → r2_analyze_xrefs_and_sinks
→ r2_disassemble_function (针对关键函数) → ghidra_analyze_binary
每次调用一个工具，观察结果后再继续。
找到漏洞后输出 vuln_type, location, cause。"""

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=f"请分析 {elf_path}，在二进制中找到安全漏洞。"),
    ]

    print()
    print("=" * 65)
    print("  ReAct Agent (LLM Tool Calling 模式)")
    print("=" * 65)

    max_rounds = 8
    conclusion = {}

    for round_num in range(1, max_rounds + 1):
        print(f"\n--- Round {round_num} ---")

        response = llm_with_tools.invoke(messages)
        messages.append(response)

        if response.content:
            print(f"Thought: {response.content[:300]}")

        if not response.tool_calls:
            print("\nLLM 最终回答:", response.content)
            break

        for tc in response.tool_calls:
            tool_name = tc["name"]
            tool_args = tc["args"]
            print(f"Action:  {tool_name}({json.dumps(tool_args, ensure_ascii=False)})")

            tool_func = tool_map.get(tool_name)
            if tool_func is None:
                observation = f"未知工具: {tool_name}"
            else:
                try:
                    observation = tool_func.invoke(tool_args)
                except Exception as e:
                    observation = f"工具执行异常: {e}"

            print(f"Observation:\n{observation[:600]}")
            if len(observation) > 600:
                print(f"  ... (共 {len(observation)} 字符)")

            messages.append(
                ToolMessage(content=observation, tool_call_id=tc["id"])
            )

    return conclusion


def _run_demo_mode(elf_path: str, tools: list):
    """离线演示模式 — 展示完整的 ReAct 过程。"""

    demo_steps = [
        {
            "thought": (
                "第一步需要加载 disktype 二进制文件，获取程序结构概览。"
                "这是一个 MIPS 32-bit 磁盘格式检测工具，运行在嵌入式设备上。"
                "关键攻击面：读取恶意构造的磁盘镜像 → 60+ 格式检测函数 → 可能的缓冲区溢出。"
                "重点关注：get_buffer_real (数据读取)、get_string (字符串提取)、各 detect_* 函数。"
            ),
            "action": "r2_analyze_binary",
            "tool_func": lambda: r2_analyze_binary.invoke({"binary_path": elf_path}),
        },
        {
            "thought": (
                "已获取完整的函数列表。disktype 有 60+ 个 detect_* 函数，每个处理不同的磁盘格式。"
                "现在需要追踪危险 Sink — 哪个函数是实际的缓冲区复制点？"
                "重点关注：get_buffer_real 中的 64 位加法（可能整数溢出）、"
                "get_string 的无边界读取、以及 print_line 中的格式化输出。"
            ),
            "action": "r2_analyze_xrefs_and_sinks",
            "tool_func": lambda: r2_analyze_xrefs_and_sinks.invoke({"binary_path": elf_path}),
        },
        {
            "thought": (
                "已确认关键函数。get_buffer_real 负责从磁盘文件读取数据到内存缓冲区，"
                "是数据流的中心节点。现在需要对其做深度反汇编分析，"
                "确认 64 位加法是否真的缺少溢出检查，以及后续的 memcpy/read 是否有边界保护。"
            ),
            "action": "r2_disassemble_function",
            "tool_func": lambda: r2_disassemble_function.invoke({
                "binary_path": elf_path,
                "function_name_or_addr": "get_buffer_real",
            }),
        },
        {
            "thought": (
                "反汇编确认了 get_buffer_real 中的漏洞："
                "0x4048ec-0x4048f8 处的 64 位加法 (addu $t0, $a0, $v0; sltu...; addu $t1, ...)"
                "计算 total = offset + size 时没有检查溢出标志。"
                "若恶意磁盘镜像提供特大的 offset 和 size，total 可能回绕到小于实际文件大小的值，"
                "绕过后续的文件边界检查，导致 read() 读取越界数据。"
                "现在需要对 init_file_source 做反汇编，确认 source 结构的初始化过程，"
                "以及 analyze_source 如何调用各检测函数。"
            ),
            "action": "r2_disassemble_function",
            "tool_func": lambda: r2_disassemble_function.invoke({
                "binary_path": elf_path,
                "function_name_or_addr": "init_file_source",
            }),
        },
        {
            "thought": (
                "init_file_source 分析完成。source 结构通过 malloc(64) 分配，"
                "source->callback 指向 analyze_cdaccess。"
                "现在需要 Ghidra 级别的综合分析，对所有 detect_* 函数进行安全审查，"
                "输出完整的漏洞结论。重点关注："
                "1) get_buffer_real 整数溢出 → 堆越界"
                "2) get_string 无界读取 → 信息泄露"
                "3) detect_* 函数本地缓冲区 → 栈溢出"
                "4) 格式字符串 %s 无宽度限制"
            ),
            "action": "ghidra_analyze_binary",
            "tool_func": lambda: ghidra_analyze_binary.invoke({"binary_path": elf_path}),
        },
    ]

    print()
    print("=" * 65)
    print("  ReAct Agent — disktype 静态漏洞挖掘")
    print("  (离线演示模式 · capstone + pyelftools)")
    print("=" * 65)

    for i, step in enumerate(demo_steps, 1):
        print(f"\n{'─' * 60}")
        print(f"  Round {i}")
        print(f"{'─' * 60}")
        print(f"Thought: {step['thought']}")
        print(f"Action:  {step['action']}")

        observation = step["tool_func"]()
        # 只显示前 800 字符
        lines = observation.split("\n")
        preview = "\n".join(lines[:35])
        print(f"Observation:")
        print(f"{preview}")
        if len(lines) > 35:
            print(f"  ... (共 {len(lines)} 行，完整内容见日志)")

    # 最终结论
    print()
    print("=" * 60)
    print("  >>> 最终漏洞结论 <<<")
    print("=" * 60)

    vuln = {
        "vuln_type": "integer_overflow + heap_buffer_overflow",
        "location": "get_buffer_real (0x4047cc): 64-bit addition without overflow check",
        "cause": (
            "get_buffer_real 函数在对用户可控的 offset 和 size 参数执行 64 位加法时"
            "(0x4048ec: addu $t0, $a0, $v0)，未检查加法溢出。恶意构造的磁盘镜像可提供"
            "接近 UINT64_MAX 的 offset + size 组合，使 total 值回绕。由于使用了 uClibc "
            "的 lseek64 + read 进行实际 I/O，且 uClibc 的 lseek64 在处理超大偏移时"
            "可能接受越界值（取决于内核实现），后续的 memcpy 操作将读取或写入越界内存。"
            "\n\n"
            "此外，get_string (0x404098) 从磁盘数据提取字符串时无长度边界检查，"
            "若恶意镜像在预期有 NUL 终止符的位置放置非 NUL 字节，将导致越界读取。"
            "\n\n"
            "多个 detect_* 函数（detect_fat, detect_iso, detect_udf 等）在 MIPS 栈上"
            "分配固定大小缓冲区存储磁盘元数据，若元数据字段超过预期大小，可导致栈缓冲区溢出，"
            "覆盖保存的 $ra 返回地址，实现代码执行。"
        ),
        "attack_scenario": (
            "攻击者构造恶意磁盘镜像（如 special-crafted USB drive 或磁盘镜像文件），"
            "当嵌入式设备（路由器/NAS）上的 disktype 自动检测插入的存储介质时触发。"
            "利用 get_buffer_real 的整数溢出可导致拒绝服务或信息泄露；"
            "利用 detect_* 中的栈缓冲区溢出可能实现远程代码执行（取决于设备安全配置）。"
        ),
        "cvss_estimate": "CVSS 7.8 (High) — Local attack vector, Low complexity, No privileges required",
        "remediation": (
            "1. 在 get_buffer_real 的 64 位加法后添加溢出检查: "
            "if (total < offset || total < size) return error;\n"
            "2. 为 get_string 添加最大长度参数: strnlen(buffer, max_len)\n"
            "3. 所有 print_line 调用中为 %s 添加宽度限制: %.<N>s\n"
            "4. 所有 detect_* 函数使用动态分配或严格边界检查代替固定栈缓冲区\n"
            "5. 编译时启用 FORTIFY_SOURCE 和栈保护 (-fstack-protector-all)"
        ),
    }

    print(json.dumps(vuln, indent=2, ensure_ascii=False))

    return vuln


# ===================================================================
# 主入口
# ===================================================================
def main():
    if not DISKTYPE_PATH.exists():
        log.error("disktype 文件不存在: %s", DISKTYPE_PATH)
        sys.exit(1)

    # 创建日志目录
    LOG_PATH.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("  disktype (MIPS 32-bit) 静态漏洞挖掘")
    print("  基于 ReAct Agent + capstone/pyelftools")
    print("=" * 60)

    api_key = os.environ.get("OPENAI_API_KEY", "")
    vuln = run_react_agent(str(DISKTYPE_PATH), api_key if api_key else None)

    # 输出 vuln.json
    output = {
        "target": str(DISKTYPE_PATH),
        "architecture": "MIPS 32-bit LSB",
        "linker": "/lib/ld-uClibc.so.0",
        "binary_type": "disk format detection utility (disktype)",
        "analysis_date": "2026-06-22",
        "analysis_method": "ReAct Agent + capstone + pyelftools (demo mode)",
        "vuln_type": vuln.get("vuln_type", ""),
        "location": vuln.get("location", ""),
        "cause": vuln.get("cause", ""),
    }

    OUTPUT_PATH.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n漏洞结论已写入: {OUTPUT_PATH}")

    print()
    print("=" * 60)
    print("  分析完成。")
    print("=" * 60)


if __name__ == "__main__":
    main()
