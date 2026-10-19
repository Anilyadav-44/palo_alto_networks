"""
Project Unit42-FirmwareX — Binary Hardening Scanner (Checksec Equivalent)
Evaluates exploit mitigation posture: NX, PIE, RELRO, Stack Canaries, FORTIFY (PRD FR-1.4).
"""

from pathlib import Path
from typing import Dict, Any
import hashlib
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
from elftools.elf.sections import SymbolTableSection

from firmwarex.schema import BinaryAuditRecord, RelroStatus

FORTIFY_PATTERNS = {
    "__sprintf_chk", "__snprintf_chk", "__vsprintf_chk", "__vsnprintf_chk",
    "__strcpy_chk", "__strncpy_chk", "__strcat_chk", "__strncat_chk",
    "__memcpy_chk", "__memmove_chk", "__memset_chk", "__fprintf_chk", "__printf_chk"
}

class HardeningAuditor:
    """Inspects ELF binaries for binary protection mechanisms"""

    @classmethod
    def audit_binary(cls, file_path: Path, rootfs_rel_path: str = None) -> BinaryAuditRecord:
        rel_path = rootfs_rel_path or str(file_path)
        
        # Defaults
        arch = "UNKNOWN"
        endianness = "unknown"
        bits = 32
        nx = False
        pie = False
        relro = RelroStatus.NONE.value
        canary = False
        fortify = False
        stripped = True
        banned_calls_count = 0
        sha256_hash = None

        with open(file_path, "rb") as f:
            data = f.read()
            sha256_hash = hashlib.sha256(data).hexdigest()
            f.seek(0)
            
            try:
                elffile = ELFFile(f)
                
                # Architecture & Endianness
                machine = elffile.header.e_machine
                if "MIPS" in machine:
                    arch = "MIPSEL" if elffile.little_endian else "MIPS"
                elif "ARM" in machine or "AArch64" in machine:
                    arch = "ARM64" if "AArch64" in machine or elffile.elfclass == 64 else "ARM32"
                elif "X86" in machine or "386" in machine:
                    arch = "x86"
                elif "AMD64" in machine or "x86-64" in machine:
                    arch = "x86_64"
                else:
                    arch = machine

                endianness = "little" if elffile.little_endian else "big"
                bits = elffile.elfclass

                # 1. NX / DEP (Check PT_GNU_STACK program header)
                has_gnu_stack = False
                for seg in elffile.iter_segments():
                    if seg['p_type'] == 'PT_GNU_STACK':
                        has_gnu_stack = True
                        # PF_X = 1; if executable bit is NOT set, stack is non-executable (NX enabled)
                        if (seg['p_flags'] & 1) == 0:
                            nx = True
                        break
                # In older architectures without PT_GNU_STACK, default is non-NX
                if not has_gnu_stack:
                    nx = False

                # 2. PIE / ASLR (Check ELF type and dynamic section)
                e_type = elffile.header['e_type']
                if e_type == 'ET_DYN':
                    # Dynamic shared object or PIE binary
                    pie = True
                elif e_type == 'ET_EXEC':
                    pie = False

                # 3. RELRO (Check PT_GNU_RELRO & BIND_NOW)
                has_relro_segment = False
                for seg in elffile.iter_segments():
                    if seg['p_type'] == 'PT_GNU_RELRO':
                        has_relro_segment = True
                        break

                bind_now = False
                for section in elffile.iter_sections():
                    if isinstance(section, DynamicSection):
                        for tag in section.iter_tags():
                            if tag.entry.d_tag == 'DT_BIND_NOW':
                                bind_now = True
                            elif tag.entry.d_tag == 'DT_FLAGS' and (tag.entry.d_val & 0x08): # DF_BIND_NOW
                                bind_now = True
                            elif tag.entry.d_tag == 'DT_FLAGS_1' and (tag.entry.d_val & 0x01): # DF_1_NOW
                                bind_now = True

                if has_relro_segment:
                    relro = RelroStatus.FULL.value if bind_now else RelroStatus.PARTIAL.value
                else:
                    relro = RelroStatus.NONE.value

                # 4. Stack Canary & 5. FORTIFY
                all_symbols = set()
                has_symtab = False
                for section in elffile.iter_sections():
                    if section.name == '.symtab':
                        has_symtab = True
                    if isinstance(section, SymbolTableSection):
                        for sym in section.iter_symbols():
                            if sym.name:
                                all_symbols.add(sym.name)

                stripped = not has_symtab

                # Check canaries
                canary_symbols = {"__stack_chk_fail", "__stack_chk_guard", "__intel_security_cookie"}
                if any(sym in all_symbols for sym in canary_symbols):
                    canary = True

                # Check fortify
                if any(sym in all_symbols for sym in FORTIFY_PATTERNS):
                    fortify = True

            except Exception:
                pass

        # Calculate mitigation risk score (0.0 = safely hardened, 10.0 = high risk unprotected)
        risk = 0.0
        if not nx:
            risk += 3.0
        if not pie:
            risk += 2.0
        if relro == RelroStatus.NONE.value:
            risk += 2.0
        elif relro == RelroStatus.PARTIAL.value:
            risk += 1.0
        if not canary:
            risk += 2.5
        if not fortify:
            risk += 0.5

        return BinaryAuditRecord(
            path=rel_path,
            architecture=arch,
            endianness=endianness,
            bits=bits,
            nx=nx,
            pie=pie,
            relro=relro,
            stack_canary=canary,
            fortify=fortify,
            stripped=stripped,
            sha256=sha256_hash,
            banned_calls_count=banned_calls_count,
            risk_score=round(min(risk, 10.0), 2)
        )
