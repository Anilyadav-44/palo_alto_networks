"""
Project Unit42-FirmwareX — Firmware Signature & Header Detection
Identifies common IoT firmware containers, compression types, and embedded filesystems.
"""

from typing import List, Dict, Any
import struct

SIGNATURES = [
    {"name": "SquashFS (Little Endian)", "magic": b"sqsh", "offset_align": 4, "type": "filesystem"},
    {"name": "SquashFS (Big Endian)", "magic": b"hsqs", "offset_align": 4, "type": "filesystem"},
    {"name": "SquashFS (Alternate LE)", "magic": b"qshs", "offset_align": 4, "type": "filesystem"},
    {"name": "SquashFS (Alternate BE)", "magic": b"shsq", "offset_align": 4, "type": "filesystem"},
    {"name": "CramFS (Little Endian)", "magic": b"\x45\x3d\xcd\x28", "offset_align": 4, "type": "filesystem"},
    {"name": "CramFS (Big Endian)", "magic": b"\x28\xcd\x3d\x45", "offset_align": 4, "type": "filesystem"},
    {"name": "JFFS2 (Little Endian)", "magic": b"\x85\x19", "offset_align": 2, "type": "filesystem"},
    {"name": "JFFS2 (Big Endian)", "magic": b"\x19\x85", "offset_align": 2, "type": "filesystem"},
    {"name": "UBIFS", "magic": b"\x31\x18\x10\x06", "offset_align": 4, "type": "filesystem"},
    {"name": "U-Boot uImage", "magic": b"\x27\x05\x19\x56", "offset_align": 4, "type": "container"},
    {"name": "Broadcom TRX Header", "magic": b"HDR0", "offset_align": 4, "type": "container"},
    {"name": "GZIP Compressed Stream", "magic": b"\x1f\x8b\x08", "offset_align": 1, "type": "compressed"},
    {"name": "BZIP2 Compressed Stream", "magic": b"BZh", "offset_align": 1, "type": "compressed"},
    {"name": "XZ Compressed Stream", "magic": b"\xfd\x37\x7a\x58\x5a\x00", "offset_align": 1, "type": "compressed"},
    {"name": "ZIP Archive", "magic": b"PK\x03\x04", "offset_align": 4, "type": "archive"},
    {"name": "POSIX TAR Archive", "magic": b"ustar", "offset_align": 1, "type": "archive"},
    {"name": "CPIO Archive", "magic": b"070701", "offset_align": 1, "type": "archive"},
    {"name": "ELF Executable/Library", "magic": b"\x7fELF", "offset_align": 4, "type": "executable"},
]

class FirmwareDetector:
    """Scans raw firmware image bytes for container headers and embedded filesystems"""

    @staticmethod
    def scan_signatures(data: bytes, max_matches: int = 50) -> List[Dict[str, Any]]:
        matches = []
        data_len = len(data)

        for sig in SIGNATURES:
            magic = sig["magic"]
            magic_len = len(magic)
            start = 0
            while start < data_len and len(matches) < max_matches:
                pos = data.find(magic, start)
                if pos == -1:
                    break
                
                # Check offset alignment
                if pos % sig.get("offset_align", 1) == 0:
                    matches.append({
                        "name": sig["name"],
                        "type": sig["type"],
                        "offset": pos,
                        "offset_hex": f"0x{pos:08x}",
                        "magic": magic.hex()
                    })
                start = pos + 1

        matches.sort(key=lambda m: m["offset"])
        return matches

    @staticmethod
    def detect_primary_container(data: bytes) -> str:
        """Determines the primary container format of the firmware"""
        if len(data) < 4:
            return "Unknown (Truncated)"

        # Check start of image
        if data.startswith(b"\x7fELF"):
            return "Standalone ELF Binary"
        if data.startswith(b"\x27\x05\x19\x56"):
            return "U-Boot uImage Header"
        if data.startswith(b"HDR0"):
            return "Broadcom TRX Image"
        if data.startswith(b"sqsh") or data.startswith(b"hsqs") or data.startswith(b"qshs") or data.startswith(b"shsq"):
            return "Raw SquashFS Image"
        if data.startswith(b"\x1f\x8b\x08"):
            return "GZIP Compressed Archive"
        if data.startswith(b"PK\x03\x04"):
            return "ZIP Firmware Container"
        if b"ustar" in data[:512]:
            return "TAR Archive"

        # Scan for first filesystem signature
        signatures = FirmwareDetector.scan_signatures(data[:65536], max_matches=10)
        for s in signatures:
            if s["type"] in ("container", "filesystem"):
                return f"{s['name']} (Offset: {s['offset_hex']})"

        return "Generic Firmware Blob"
