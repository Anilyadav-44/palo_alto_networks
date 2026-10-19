"""
Project Unit42-FirmwareX — Control Flow Graph (CFG) Generator
Disassembles ELF functions, constructs basic block graphs, and tracks taint flow (PRD Section 8.2).
"""

from typing import Dict, Any, List, Optional, Set
import networkx as nx
import capstone

from firmwarex.schema import CFGData, CFGNode, CFGEdge
from firmwarex.emulation.unicorn_engine import ArchitectureSupport

class CFGGenerator:
    """Builds interactive CFG graphs with basic block analysis and sink detection"""

    BRANCH_MNEMONICS = {
        # x86
        "jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "call", "ret",
        # MIPS
        "j", "jal", "jalr", "jr", "beq", "bne", "blez", "bgtz", "bltz", "bgez", "b", "bal",
        # ARM
        "b", "bl", "bx", "blx", "b.eq", "b.ne", "b.gt", "b.lt", "cbz", "cbnz"
    }

    CALL_MNEMONICS = {"call", "jal", "jalr", "bl", "blx"}
    RETURN_MNEMONICS = {"ret", "jr $ra", "bx lr"}

    @classmethod
    def generate_cfg_from_code(
        cls,
        code_bytes: bytes,
        entry_address: int = 0x00401000,
        arch: str = "MIPS",
        endianness: str = "big",
        bits: int = 32,
        function_name: str = "main",
        binary_path: str = "/bin/httpd",
        tainted_addrs: Optional[Set[int]] = None
    ) -> CFGData:
        """Constructs CFG basic blocks and directed edges from binary code bytes"""
        tainted_addrs = tainted_addrs or set()
        cs = ArchitectureSupport.get_capstone_disassembler(arch, endianness, bits)
        
        # 1. Disassemble all instructions
        instructions = []
        try:
            for insn in cs.disasm(code_bytes, entry_address):
                instructions.append(insn)
        except Exception:
            pass

        if not instructions:
            # Fallback basic block
            return CFGData(
                binary_path=binary_path,
                function_name=function_name,
                entry_address=hex(entry_address),
                nodes=[CFGNode(
                    id=f"bb_{hex(entry_address)}",
                    address=hex(entry_address),
                    name="entry",
                    instructions=["nop", "ret"]
                )],
                edges=[]
            )

        # 2. Identify basic block leaders
        leaders = {instructions[0].address}
        for i, insn in enumerate(instructions):
            m = insn.mnemonic.lower()
            if m in cls.BRANCH_MNEMONICS or any(m.startswith(bm) for bm in ["j", "b."]):
                # Next instruction is a leader
                if i + 1 < len(instructions):
                    leaders.add(instructions[i + 1].address)
                # If target is immediate/hex address within range
                try:
                    if insn.op_str.startswith("0x"):
                        target_addr = int(insn.op_str.split()[0], 16)
                        if entry_address <= target_addr <= entry_address + len(code_bytes):
                            leaders.add(target_addr)
                except ValueError:
                    pass

        # 3. Partition instructions into basic blocks
        blocks: List[List[Any]] = []
        current_block: List[Any] = []
        
        for insn in instructions:
            if insn.address in leaders and current_block:
                blocks.append(current_block)
                current_block = []
            current_block.append(insn)
        if current_block:
            blocks.append(current_block)

        # 4. Construct nodes and edges
        nodes: List[CFGNode] = []
        edges: List[CFGEdge] = []
        block_by_addr: Dict[int, str] = {}

        for idx, blk in enumerate(blocks):
            start_addr = blk[0].address
            node_id = f"bb_{hex(start_addr)}"
            block_by_addr[start_addr] = node_id

            insn_texts = []
            has_sink = False
            has_source = False
            is_node_tainted = False

            for insn in blk:
                line = f"{hex(insn.address)}: {insn.mnemonic} {insn.op_str}".strip()
                insn_texts.append(line)
                
                # Check for sinks & sources
                op = insn.op_str.lower()
                if any(s in op for s in ["strcpy", "system", "sprintf", "popen", "memcpy", "gets"]):
                    has_sink = True
                if any(src in op for src in ["getenv", "http", "recv", "read", "nvram_get"]):
                    has_source = True
                if insn.address in tainted_addrs:
                    is_node_tainted = True

            nodes.append(CFGNode(
                id=node_id,
                address=hex(start_addr),
                name=f"Block {idx} ({hex(start_addr)})",
                instructions=insn_texts,
                is_sink=has_sink,
                is_source=has_source,
                is_tainted=is_node_tainted
            ))

        # 5. Wire edges between blocks
        for idx, blk in enumerate(blocks):
            src_id = block_by_addr[blk[0].address]
            last_insn = blk[-1]
            last_m = last_insn.mnemonic.lower()

            # Sequential fallthrough
            if idx + 1 < len(blocks) and not (last_m in ["ret", "jr"] and "ra" in last_insn.op_str):
                next_id = block_by_addr[blocks[idx + 1][0].address]
                edges.append(CFGEdge(
                    source=src_id,
                    target=next_id,
                    type="normal" if not (last_m.startswith("b") or last_m.startswith("j")) else "conditional_false"
                ))

            # Branch target
            try:
                if last_insn.op_str.startswith("0x"):
                    target_addr = int(last_insn.op_str.split()[0], 16)
                    if target_addr in block_by_addr:
                        edges.append(CFGEdge(
                            source=src_id,
                            target=block_by_addr[target_addr],
                            type="conditional_true" if (last_m.startswith("b") or last_m.startswith("j")) else "call"
                        ))
            except ValueError:
                pass

        return CFGData(
            binary_path=binary_path,
            function_name=function_name,
            entry_address=hex(entry_address),
            nodes=nodes,
            edges=edges
        )
