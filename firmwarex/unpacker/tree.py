"""
Project Unit42-FirmwareX — File System Inventory & Tree Generator
Generates structured inventory of all extracted files in rootfs (PRD FR-1.2).
"""

import os
from pathlib import Path
from typing import List, Dict, Any, Optional
import hashlib

from firmwarex.schema import FileSystemNode

class FileTreeGenerator:
    """Recursively audits reconstructed root filesystem and builds inventory"""

    @staticmethod
    def generate_inventory(rootfs_dir: Path) -> List[FileSystemNode]:
        inventory: List[FileSystemNode] = []
        root_path = Path(rootfs_dir).resolve()

        if not root_path.exists():
            return inventory

        for current_dir, dirs, files in os.walk(root_path):
            curr = Path(current_dir)
            rel_dir = curr.relative_to(root_path)

            for d in dirs:
                dir_path = curr / d
                rel_path = dir_path.relative_to(root_path)
                inventory.append(FileSystemNode(
                    path=f"/{rel_path.as_posix()}",
                    name=d,
                    type="directory",
                    size_bytes=0,
                    sha256=None,
                    mime_type="inode/directory",
                    permissions=oct(dir_path.stat().st_mode)[-3:] if hasattr(dir_path.stat(), "st_mode") else "755",
                    is_executable=False
                ))

            for f in files:
                file_path = curr / f
                rel_path = file_path.relative_to(root_path)
                
                try:
                    stat = file_path.stat()
                    size = stat.st_size
                    perms = oct(stat.st_mode)[-3:]
                    
                    # Compute SHA256 for file
                    sha256_val = None
                    is_exec = False
                    mime_type = "application/octet-stream"

                    if size > 0:
                        hasher = hashlib.sha256()
                        with open(file_path, "rb") as fp:
                            # Read first 1MB max for quick hash or stream
                            buf = fp.read(1024 * 1024)
                            hasher.update(buf)
                            # Check magic for mime
                            if buf.startswith(b"\x7fELF"):
                                mime_type = "application/x-executable"
                                is_exec = True
                            elif buf.startswith(b"#!/"):
                                mime_type = "text/x-shellscript"
                                is_exec = True
                            elif buf.startswith(b"<?xml") or buf.startswith(b"<!DOCTYPE"):
                                mime_type = "text/xml"
                            elif b"\x00" not in buf[:512]:
                                mime_type = "text/plain"
                        sha256_val = hasher.hexdigest()

                    inventory.append(FileSystemNode(
                        path=f"/{rel_path.as_posix()}",
                        name=f,
                        type="file",
                        size_bytes=size,
                        sha256=sha256_val,
                        mime_type=mime_type,
                        permissions=perms,
                        is_executable=is_exec
                    ))
                except Exception:
                    continue

        return inventory

    @staticmethod
    def find_binaries(rootfs_dir: Path) -> List[Path]:
        """Finds all ELF executables and shared libraries in rootfs"""
        binaries: List[Path] = []
        root_path = Path(rootfs_dir).resolve()

        if not root_path.exists():
            return binaries

        for file_path in root_path.rglob("*"):
            if file_path.is_file():
                try:
                    with open(file_path, "rb") as f:
                        magic = f.read(4)
                        if magic == b"\x7fELF":
                            binaries.append(file_path)
                except Exception:
                    continue
        return binaries
