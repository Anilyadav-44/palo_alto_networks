"""
Project Unit42-FirmwareX — Unpacking & Filesystem Extraction Engine
Safely carves, decompresses, and reconstructs firmware filesystems while enforcing containment quotas.
"""

import os
import shutil
import tarfile
import zipfile
import gzip
import bz2
from pathlib import Path
from typing import Dict, Any, Tuple
import hashlib

from firmwarex.config import settings
from firmwarex.unpacker.detector import FirmwareDetector
from firmwarex.unpacker.entropy import EntropyAnalyzer

class UnpackerQuotaExceeded(Exception):
    """Raised when extraction exceeds file count or size guardrails"""
    pass

class FirmwareExtractor:
    """Safe multi-format firmware unpacker and rootfs reconstructor"""

    def __init__(self, firmware_id: str, firmware_path: Path):
        self.firmware_id = firmware_id
        self.firmware_path = Path(firmware_path)
        self.output_dir = settings.EXTRACTION_DIR / firmware_id
        self.extracted_count = 0
        self.total_extracted_bytes = 0

    def unpack(self) -> Dict[str, Any]:
        """Main entry point to unpack firmware image into rootfs"""
        if self.output_dir.exists():
            shutil.rmtree(self.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        with open(self.firmware_path, "rb") as f:
            raw_data = f.read()

        file_size = len(raw_data)
        if file_size > settings.MAX_FIRMWARE_SIZE_BYTES:
            raise UnpackerQuotaExceeded(
                f"Firmware size {file_size} bytes exceeds maximum quota of {settings.MAX_FIRMWARE_SIZE_BYTES} bytes."
            )

        sha256 = hashlib.sha256(raw_data).hexdigest()
        container_format = FirmwareDetector.detect_primary_container(raw_data)
        entropy_stats = EntropyAnalyzer.analyze(raw_data)
        signatures = FirmwareDetector.scan_signatures(raw_data)

        # Extraction logic
        extracted = False
        
        # 1. Try standard tar / tar.gz / tar.bz2 / tar.xz
        if not extracted:
            try:
                with tarfile.open(self.firmware_path, "r:*") as tar:
                    self._extract_tar_safe(tar, self.output_dir)
                    extracted = True
            except Exception:
                pass

        # 2. Try standard ZIP archive
        if not extracted:
            try:
                with zipfile.ZipFile(self.firmware_path, "r") as zf:
                    self._extract_zip_safe(zf, self.output_dir)
                    extracted = True
            except Exception:
                pass

        # 3. Try GZIP decompression
        if not extracted and raw_data.startswith(b"\x1f\x8b\x08"):
            try:
                decompressed = gzip.decompress(raw_data)
                # Check if decompressed stream is a tar
                temp_tar = self.output_dir / "decompressed.tar"
                with open(temp_tar, "wb") as f_out:
                    f_out.write(decompressed)
                try:
                    with tarfile.open(temp_tar, "r:*") as tar:
                        self._extract_tar_safe(tar, self.output_dir)
                        extracted = True
                finally:
                    if temp_tar.exists():
                        temp_tar.unlink()
            except Exception:
                pass

        # 4. Check for embedded partitions from signatures (e.g. SquashFS, uImage, or embedded Tar)
        if not extracted and signatures:
            for sig in signatures:
                offset = sig["offset"]
                # If uImage header is present (64 bytes), skip header to find payload
                if sig["name"] == "U-Boot uImage":
                    payload_offset = offset + 64
                    payload = raw_data[payload_offset:]
                    if payload.startswith(b"\x1f\x8b\x08"):
                        try:
                            dec = gzip.decompress(payload)
                            tar_tmp = self.output_dir / "uimage_dec.tar"
                            with open(tar_tmp, "wb") as f_out:
                                f_out.write(dec)
                            with tarfile.open(tar_tmp, "r:*") as tar:
                                self._extract_tar_safe(tar, self.output_dir)
                                extracted = True
                            if tar_tmp.exists():
                                tar_tmp.unlink()
                            if extracted:
                                break
                        except Exception:
                            pass
                    else:
                        # Try parsing payload directly as tar
                        try:
                            tar_tmp = self.output_dir / "uimage_raw.tar"
                            with open(tar_tmp, "wb") as f_out:
                                f_out.write(payload)
                            with tarfile.open(tar_tmp, "r:*") as tar:
                                self._extract_tar_safe(tar, self.output_dir)
                                extracted = True
                            if tar_tmp.exists():
                                tar_tmp.unlink()
                            if extracted:
                                break
                        except Exception:
                            pass
                
                # Check for embedded tar
                if sig["type"] == "archive" and sig["name"] == "POSIX TAR Archive":
                    try:
                        tar_start = max(0, offset - 257)
                        tar_chunk = raw_data[tar_start:]
                        tar_tmp = self.output_dir / f"carved_offset_{tar_start}.tar"
                        with open(tar_tmp, "wb") as f_out:
                            f_out.write(tar_chunk)
                        with tarfile.open(tar_tmp, "r:*") as tar:
                            self._extract_tar_safe(tar, self.output_dir)
                            extracted = True
                        if tar_tmp.exists():
                            tar_tmp.unlink()
                        if extracted:
                            break
                    except Exception:
                        pass

        # 5. Fallback: If it's a standalone ELF or raw binary, save as binary in /bin
        if not extracted:
            if raw_data.startswith(b"\x7fELF"):
                bin_dir = self.output_dir / "bin"
                bin_dir.mkdir(parents=True, exist_ok=True)
                dest = bin_dir / self.firmware_path.name
                with open(dest, "wb") as f_out:
                    f_out.write(raw_data)
                self.extracted_count = 1
                self.total_extracted_bytes = len(raw_data)
                extracted = True
            else:
                # Carve any embedded ELFs discovered by signatures
                elf_sigs = [s for s in signatures if s["magic"] == "7f454c46"]
                if elf_sigs:
                    bin_dir = self.output_dir / "bin"
                    bin_dir.mkdir(parents=True, exist_ok=True)
                    for i, esig in enumerate(elf_sigs):
                        e_offset = esig["offset"]
                        # Read 256KB or until end
                        e_data = raw_data[e_offset:e_offset + 512*1024]
                        dest = bin_dir / f"carved_elf_{i}.bin"
                        with open(dest, "wb") as f_out:
                            f_out.write(e_data)
                        self.extracted_count += 1
                        self.total_extracted_bytes += len(e_data)
                    extracted = True

        return {
            "firmware_id": self.firmware_id,
            "filename": self.firmware_path.name,
            "size_bytes": file_size,
            "sha256": sha256,
            "format_detected": container_format,
            "signatures": signatures,
            "entropy": entropy_stats,
            "output_directory": str(self.output_dir),
            "files_extracted": self.extracted_count,
            "bytes_extracted": self.total_extracted_bytes,
            "success": extracted
        }

    def _extract_tar_safe(self, tar: tarfile.TarFile, target_dir: Path):
        """Extract tar safely, preventing directory traversal and zip slips"""
        for member in tar.getmembers():
            if self.extracted_count >= settings.MAX_FILE_EXTRACTION_COUNT:
                raise UnpackerQuotaExceeded(
                    f"Extraction exceeded max file quota of {settings.MAX_FILE_EXTRACTION_COUNT} files."
                )

            # Prevent directory traversal
            member_path = Path(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                continue

            target_path = (target_dir / member_path).resolve()
            if not str(target_path).startswith(str(target_dir.resolve())):
                continue

            try:
                if hasattr(tarfile, 'data_filter'):
                    tar.extract(member, path=target_dir, filter='data')
                else:
                    tar.extract(member, path=target_dir)
                self.extracted_count += 1
                self.total_extracted_bytes += member.size
            except Exception:
                continue

    def _extract_zip_safe(self, zf: zipfile.ZipFile, target_dir: Path):
        """Extract zip safely, preventing directory traversal and zip slips"""
        for member in zf.infolist():
            if self.extracted_count >= settings.MAX_FILE_EXTRACTION_COUNT:
                raise UnpackerQuotaExceeded(
                    f"Extraction exceeded max file quota of {settings.MAX_FILE_EXTRACTION_COUNT} files."
                )

            member_path = Path(member.filename)
            if member_path.is_absolute() or ".." in member_path.parts:
                continue

            target_path = (target_dir / member_path).resolve()
            if not str(target_path).startswith(str(target_dir.resolve())):
                continue

            try:
                zf.extract(member, path=target_dir)
                self.extracted_count += 1
                self.total_extracted_bytes += member.file_size
            except Exception:
                continue
