"""
Project Unit42-FirmwareX — ELF Binary Inspection Engine
Parses ELF headers, segments, sections, and symbols across MIPS, ARM, and x86 architectures.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.dynamic import DynamicSection

class ELFInspector:
    """Extracts low-level metadata from ELF executables and shared libraries"""

    @staticmethod
    def inspect(file_path: Path) -> Dict[str, Any]:
        result = {
            "is_elf": False,
            "architecture": "UNKNOWN",
            "endianness": "unknown",
            "bits": 32,
            "machine": "",
            "entry_point": "0x0",
            "sections": [],
            "symbols": [],
            "imported_functions": [],
            "error": None
        }

        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
                if magic != b"\x7fELF":
                    return result

                f.seek(0)
                elffile = ELFFile(f)
                result["is_elf"] = True
                
                # Architecture & Machine
                machine = elffile.header.e_machine
                result["machine"] = machine
                if "MIPS" in machine:
                    result["architecture"] = "MIPSEL" if elffile.little_endian else "MIPS"
                elif "ARM" in machine or "AArch64" in machine:
                    result["architecture"] = "ARM64" if "AArch64" in machine or elffile.elfclass == 64 else "ARM32"
                elif "X86" in machine or "386" in machine:
                    result["architecture"] = "x86"
                elif "AMD64" in machine or "x86-64" in machine:
                    result["architecture"] = "x86_64"
                else:
                    result["architecture"] = machine

                result["endianness"] = "little" if elffile.little_endian else "big"
                result["bits"] = elffile.elfclass
                result["entry_point"] = hex(elffile.header.e_entry)

                # Section names
                for section in elffile.iter_sections():
                    result["sections"].append(section.name)

                # Extract symbols and imported functions
                symbols = set()
                imported = set()

                for section in elffile.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        for sym in section.iter_symbols():
                            if sym.name:
                                symbols.add(sym.name)
                                if sym['st_shndx'] == 'SHN_UNDEF':
                                    imported.add(sym.name)

                result["symbols"] = sorted(list(symbols))
                result["imported_functions"] = sorted(list(imported))

        except Exception as e:
            result["error"] = str(e)

        return result
