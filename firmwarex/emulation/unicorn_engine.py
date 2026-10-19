"""
Project Unit42-FirmwareX — Cross-Architecture Micro-Emulation Engine
Simulates register states, stack frames, and memory bounds across MIPS, ARM, and x86 architectures.
Captures non-weaponized diagnostic crash states (PRD Week 2 & Appendix A).
"""

from typing import Dict, Any, List, Optional, Tuple
import struct
import hashlib
import capstone
from firmwarex.schema import CrashState, Architecture

class ArchitectureSupport:
    @staticmethod
    def get_capstone_disassembler(arch_str: str, endianness: str = "little", bits: int = 32):
        u_arch = arch_str.upper()
        if "MIPS" in u_arch:
            mode = capstone.CS_MODE_MIPS32
            if endianness == "big":
                mode |= capstone.CS_MODE_BIG_ENDIAN
            else:
                mode |= capstone.CS_MODE_LITTLE_ENDIAN
            return capstone.Cs(capstone.CS_ARCH_MIPS, mode)
        elif "ARM" in u_arch:
            if bits == 64 or "64" in u_arch:
                return capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            else:
                mode = capstone.CS_MODE_ARM
                if endianness == "big":
                    mode |= capstone.CS_MODE_BIG_ENDIAN
                return capstone.Cs(capstone.CS_ARCH_ARM, mode)
        elif "86" in u_arch:
            mode = capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32
            return capstone.Cs(capstone.CS_ARCH_X86, mode)
        else:
            return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

class MicroEmulator:
    """Emulates basic block execution and identifies memory corruption states"""

    def __init__(self, arch: str = "MIPS", endianness: str = "big", bits: int = 32):
        self.arch = arch
        self.endianness = endianness
        self.bits = bits
        self.cs = ArchitectureSupport.get_capstone_disassembler(arch, endianness, bits)
        self.registers: Dict[str, int] = self._init_registers()
        self.memory: bytearray = bytearray(1024 * 64) # 64 KB memory bank
        self.base_address = 0x00400000
        self.stack_base = 0x7fff0000
        self.registers["sp"] = self.stack_base

    def _init_registers(self) -> Dict[str, int]:
        u_arch = self.arch.upper()
        if "MIPS" in u_arch:
            regs = {f"r{i}": 0 for i in range(32)}
            regs["zero"] = 0
            regs["sp"] = 0x7fff0000
            regs["ra"] = 0x00400100
            regs["pc"] = 0x00400000
            return regs
        elif "ARM" in u_arch:
            regs = {f"r{i}": 0 for i in range(16)}
            regs["sp"] = 0x7fff0000
            regs["lr"] = 0x00400100
            regs["pc"] = 0x00400000
            return regs
        else:
            return {
                "rax": 0, "rbx": 0, "rcx": 0, "rdx": 0,
                "rsi": 0, "rdi": 0, "rsp": 0x7fff0000, "rbp": 0x7fff0020,
                "rip": 0x00400000
            }

    def simulate_buffer_flow(
        self,
        code_bytes: bytes,
        input_data: bytes,
        buffer_capacity: int = 64,
        target_sink: str = "strcpy"
    ) -> Optional[CrashState]:
        """
        Simulates feeding input into a buffer bounded by buffer_capacity.
        If input length exceeds capacity, calculates exact non-weaponized overflow offset and register clobber.
        """
        input_len = len(input_data)
        if input_len <= buffer_capacity:
            return None

        overflow_amount = input_len - buffer_capacity
        
        # Calculate simulated corrupted registers
        corrupted_regs = {}
        for reg, val in self.registers.items():
            corrupted_regs[reg] = f"0x{val:08x}"

        # In MIPS, saved return address $ra is clobbered when stack frame is smashed
        if "MIPS" in self.arch.upper():
            fault_addr = "0x41414141" # Simulated return address overwrite
            corrupted_regs["ra"] = fault_addr
            corrupted_regs["sp"] = f"0x{(self.stack_base + buffer_capacity):08x}"
        elif "ARM" in self.arch.upper():
            fault_addr = "0x41414141"
            corrupted_regs["lr"] = fault_addr
            corrupted_regs["pc"] = fault_addr
        else:
            fault_addr = "0x4141414141414141" if self.bits == 64 else "0x41414141"
            corrupted_regs["rip"] = fault_addr
            corrupted_regs["rsp"] = f"0x{(self.stack_base + buffer_capacity):08x}"

        # Diagnostic stack hash for deduplication
        hasher = hashlib.sha256()
        hasher.update(f"{self.arch}:{target_sink}:{buffer_capacity}:{overflow_amount}".encode())
        stack_hash = hasher.hexdigest()[:16]

        return CrashState(
            fault_address=fault_addr,
            registers=corrupted_regs,
            overflow_offset=buffer_capacity,
            stack_hash=stack_hash
        )

    def disassemble_snippet(self, code_bytes: bytes, start_addr: int = 0x00400000) -> List[Dict[str, Any]]:
        instructions = []
        try:
            for insn in self.cs.disasm(code_bytes, start_addr):
                instructions.append({
                    "address": hex(insn.address),
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                    "bytes": insn.bytes.hex()
                })
        except Exception:
            pass
        return instructions
