"""
Project Unit42-FirmwareX — Sample Firmware & Test Binary Generator
Generates realistic open-source IoT firmware images (MIPS, ARM, x86) with embedded root filesystems.
"""

import os
import struct
import tarfile
import gzip
from pathlib import Path
from typing import Dict, Any

def create_synthetic_elf(
    arch: str = "MIPS",
    endianness: str = "big",
    is_pie: bool = False,
    has_nx: bool = False,
    has_canary: bool = False,
    symbols: list = None
) -> bytes:
    """
    Constructs a structurally valid 32-bit ELF binary with specified mitigations and symbols.
    """
    symbols = symbols or ["main", "strcpy", "system", "MD5_Init"]
    
    # Header fields
    ei_class = 1 # 32-bit
    ei_data = 2 if endianness == "big" else 1 # 2=BE, 1=LE
    endian_prefix = ">" if endianness == "big" else "<"
    
    e_machine = 8 # MIPS
    if arch.upper() == "ARM":
        e_machine = 40
    elif "86" in arch:
        e_machine = 3

    e_type = 3 if is_pie else 2 # 3=ET_DYN, 2=ET_EXEC

    # Build symbol table and string table
    # String table starting with \x00
    strtab = b"\x00"
    sym_entries = []
    
    # First symbol is always UNDEF (null symbol)
    sym_entries.append((0, 0, 0, 0, 0, 0))

    for s_name in symbols:
        name_off = len(strtab)
        strtab += s_name.encode("utf-8") + b"\x00"
        # st_name, st_value, st_size, st_info, st_other, st_shndx (SHN_UNDEF = 0 for imports)
        sym_entries.append((name_off, 0x00401000 if s_name == "main" else 0, 16, 0x12, 0, 1 if s_name == "main" else 0))

    if has_canary:
        canary_sym = "__stack_chk_fail"
        name_off = len(strtab)
        strtab += canary_sym.encode("utf-8") + b"\x00"
        sym_entries.append((name_off, 0, 16, 0x12, 0, 0))

    # Binary code instructions (e.g. MIPS instructions or NOPs)
    if "MIPS" in arch.upper():
        # MIPS instructions: addiu $sp, $sp, -32; sw $ra, 28($sp); nop; lw $ra, 28($sp); jr $ra; nop
        code = bytes.fromhex("27bdffe0 afbf001c 00000000 8fbf001c 03e00008 00000000" if endianness == "big" else "e0ffbd27 1c00bfaf 00000000 1c00bf8f 0800e003 00000000")
    elif "ARM" in arch.upper():
        # ARM instructions: push {r4, lr}; sub sp, sp, #32; add sp, sp, #32; pop {r4, pc}
        code = bytes.fromhex("e92d4010 e24dd020 e28dd020 e8bd8010")
    else:
        # x86 instructions: push ebp; mov ebp, esp; sub esp, 0x40; leave; ret
        code = bytes.fromhex("55 89e5 83ec40 c9 c3")

    # Layout offsets
    ehdr_size = 52
    ph_entry_size = 32
    sh_entry_size = 40

    ph_num = 2 # PT_LOAD, PT_GNU_STACK
    sh_num = 5 # NULL, .text, .strtab, .symtab, .shstrtab

    ph_off = ehdr_size
    text_off = ph_off + (ph_num * ph_entry_size)
    text_size = max(len(code), 64)
    code_padded = code.ljust(text_size, b"\x00")

    symtab_off = text_off + text_size
    symtab_size = len(sym_entries) * 16 # each Elf32_Sym is 16 bytes
    
    strtab_off = symtab_off + symtab_size
    strtab_size = len(strtab)

    # Section header string table
    shstrtab = b"\x00.text\x00.strtab\x00.symtab\x00.shstrtab\x00"
    shstrtab_off = strtab_off + strtab_size
    shstrtab_size = len(shstrtab)

    sh_off = shstrtab_off + shstrtab_size

    # Pack ELF Header
    e_ident = b"\x7fELF" + bytes([ei_class, ei_data, 1, 0]) + (b"\x00" * 8)
    ehdr = struct.pack(
        f"{endian_prefix}16sHHIIIIIHHHHHH",
        e_ident,
        e_type,
        e_machine,
        1,              # e_version
        0x00401000,     # e_entry
        ph_off,         # e_phoff
        sh_off,         # e_shoff
        0,              # e_flags
        ehdr_size,
        ph_entry_size,
        ph_num,
        sh_entry_size,
        sh_num,
        4               # e_shstrndx (.shstrtab is section 4)
    )

    # Pack Program Headers
    # 1. PT_LOAD (type=1, offset, vaddr, paddr, filesz, memsz, flags=7 (RWX), align=0x1000)
    p_load = struct.pack(
        f"{endian_prefix}IIIIIIII",
        1,          # p_type PT_LOAD
        0,          # p_offset
        0x00400000, # p_vaddr
        0x00400000, # p_paddr
        sh_off + (sh_num * sh_entry_size), # p_filesz
        sh_off + (sh_num * sh_entry_size), # p_memsz
        5,          # p_flags: PF_R | PF_X
        0x1000      # p_align
    )

    # 2. PT_GNU_STACK (type=0x6474e551, flags: if has_nx, PF_R | PF_W (6); if not NX, PF_R | PF_W | PF_X (7))
    stack_flags = 6 if has_nx else 7
    p_stack = struct.pack(
        f"{endian_prefix}IIIIIIII",
        0x6474e551, # PT_GNU_STACK
        0, 0, 0, 0, 0,
        stack_flags,
        0x10
    )

    # Pack Section Headers
    # Section 0: NULL
    sh_null = bytes(sh_entry_size)
    # Section 1: .text (sh_name=1, sh_type=1 (PROGBITS), sh_flags=6 (ALLOC|EXEC), sh_addr=0x00401000, sh_offset=text_off, sh_size=text_size)
    sh_text = struct.pack(
        f"{endian_prefix}IIIIIIIIII",
        1, 1, 6, 0x00401000, text_off, text_size, 0, 0, 4, 0
    )
    # Section 2: .strtab (sh_name=7, sh_type=3 (STRTAB), sh_flags=0, sh_addr=0, sh_offset=strtab_off, sh_size=strtab_size)
    sh_strtab = struct.pack(
        f"{endian_prefix}IIIIIIIIII",
        7, 3, 0, 0, strtab_off, strtab_size, 0, 0, 1, 0
    )
    # Section 3: .symtab (sh_name=15, sh_type=2 (SYMTAB), sh_flags=0, sh_addr=0, sh_offset=symtab_off, sh_size=symtab_size, sh_link=2 (.strtab), sh_info=1, sh_addralign=4, sh_entsize=16)
    sh_symtab = struct.pack(
        f"{endian_prefix}IIIIIIIIII",
        15, 2, 0, 0, symtab_off, symtab_size, 2, 1, 4, 16
    )
    # Section 4: .shstrtab (sh_name=23, sh_type=3 (STRTAB), sh_flags=0, sh_addr=0, sh_offset=shstrtab_off, sh_size=shstrtab_size)
    sh_shstrtab = struct.pack(
        f"{endian_prefix}IIIIIIIIII",
        23, 3, 0, 0, shstrtab_off, shstrtab_size, 0, 0, 1, 0
    )

    # Pack symbols
    sym_bytes = bytearray()
    for st_name, st_value, st_size, st_info, st_other, st_shndx in sym_entries:
        sym_bytes += struct.pack(f"{endian_prefix}IIIBBH", st_name, st_value, st_size, st_info, st_other, st_shndx)

    # Assemble full ELF binary
    elf = bytearray()
    elf += ehdr
    elf += p_load
    elf += p_stack
    elf += code_padded
    elf += sym_bytes
    elf += strtab
    elf += shstrtab
    elf += sh_null
    elf += sh_text
    elf += sh_strtab
    elf += sh_symtab
    elf += sh_shstrtab

    return bytes(elf)

def generate_sample_firmware_image(output_path: Path) -> Path:
    """
    Creates an authentic sample IoT router firmware image package:
    - Target: NetCore / Tenda / D-Link style Linux IoT firmware
    - Arch: MIPS (Big Endian)
    - Services: /bin/httpd, /bin/upnpd, /bin/busybox
    - Embedded secrets: AWS API key, hardcoded passwords, private RSA key block
    - Weak crypto: MD5 hash function, DES encryption
    """
    output_path = Path(output_path)
    staging_dir = output_path.parent / "staging_rootfs"
    staging_dir.mkdir(parents=True, exist_ok=True)

    # Directories
    for d in ["bin", "sbin", "etc", "etc/ssl", "usr/bin", "www", "dev"]:
        (staging_dir / d).mkdir(parents=True, exist_ok=True)

    # 1. Create Binaries
    # /bin/httpd (MIPS, No-NX, No-PIE, No-Canary, Unchecked strcpy & system sinks)
    httpd_elf = create_synthetic_elf(
        arch="MIPS",
        endianness="big",
        is_pie=False,
        has_nx=False,
        has_canary=False,
        symbols=["main", "strcpy", "system", "sprintf", "popen", "getenv", "MD5_Init", "DES_ecb_encrypt"]
    )
    with open(staging_dir / "bin/httpd", "wb") as f:
        f.write(httpd_elf)

    # /bin/upnpd (ARM32, NX enabled, No Canary)
    upnpd_elf = create_synthetic_elf(
        arch="ARM",
        endianness="little",
        is_pie=False,
        has_nx=True,
        has_canary=False,
        symbols=["main", "memcpy", "sprintf", "recv", "RC4_set_key", "SHA1_Init"]
    )
    with open(staging_dir / "bin/upnpd", "wb") as f:
        f.write(upnpd_elf)

    # /bin/busybox (x86, hardened with NX & Canary)
    busybox_elf = create_synthetic_elf(
        arch="x86",
        endianness="little",
        is_pie=True,
        has_nx=True,
        has_canary=True,
        symbols=["main", "malloc", "free", "printf", "exit"]
    )
    with open(staging_dir / "bin/busybox", "wb") as f:
        f.write(busybox_elf)

    # 2. Configuration files and Hardcoded Secrets
    with open(staging_dir / "etc/shadow", "w") as f:
        f.write("root:$1$Unit42$9n823jknasd8923:18000:0:99999:7:::\nadmin:$1$Router$pass1234:18000:0:99999:7:::\n")

    with open(staging_dir / "etc/passwd", "w") as f:
        f.write("root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:admin:/home/admin:/bin/sh\n")

    # Hardcoded AWS Cloud Credential
    with open(staging_dir / "etc/cloud_telemetry.conf", "w") as f:
        f.write(
            "# Unit 42 Diagnostic Telemetry Config\n"
            "TELEMETRY_ENDPOINT=https://iot-telemetry.unit42.internal/v1\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "DEVICE_REGION=us-west-2\n"
        )

    # Hardcoded Private RSA Key
    with open(staging_dir / "etc/ssl/device_private.key", "w") as f:
        f.write(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0YkZ7G8VbVqM+W8fFqfVj5hL0O9d8r7s6t5u4v3w2x1y0z\n"
            "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+abcdefghijklmnopqrstuvwx\n"
            "yzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmnopqrstu\n"
            "-----END RSA PRIVATE KEY-----\n"
        )

    # Hardcoded Web UI Password
    with open(staging_dir / "www/auth.js", "w") as f:
        f.write(
            "function verifyLogin() {\n"
            "  var default_admin_password = 'SuperSecretBackdoor2026!';\n"
            "  var api_key = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.G3_4q81_test_jwt_sample_token';\n"
            "}\n"
        )

    # 3. Pack staging rootfs into a tar.gz container
    temp_tar = output_path.parent / "rootfs.tar"
    with tarfile.open(temp_tar, "w") as tar:
        for item in staging_dir.rglob("*"):
            rel = item.relative_to(staging_dir)
            tar.add(item, arcname=str(rel))

    with open(temp_tar, "rb") as f_in:
        tar_bytes = f_in.read()

    # Authentically compress rootfs tarball using gzip
    gzipped_tar = gzip.compress(tar_bytes)

    # Prepend authentic U-Boot uImage header (64 bytes)
    # Magic: 0x27051956
    uimage_hdr = struct.pack(
        ">IIIIIIIBBBB32s",
        0x27051956,             # ih_magic
        0x12345678,             # ih_hcrc
        1700000000,             # ih_time
        len(gzipped_tar),       # ih_size
        0x80000000,             # ih_load
        0x80000000,             # ih_ep
        0x87654321,             # ih_dcrc
        5,                      # ih_os (Linux)
        8,                      # ih_arch (MIPS)
        2,                      # ih_type (Kernel / Ramdisk)
        1,                      # ih_comp (gzip)
        b"OpenWrt-Router-FirmwareX".ljust(32, b"\x00")
    )

    with open(output_path, "wb") as f_out:
        f_out.write(uimage_hdr + gzipped_tar)

    # Clean up temporary staging
    temp_tar.unlink(missing_ok=True)
    import shutil
    shutil.rmtree(staging_dir, ignore_errors=True)

    return output_path

if __name__ == "__main__":
    out = Path("samples/openwrt_mips_router.bin")
    generate_sample_firmware_image(out)
    print(f"Generated sample firmware image at {out} ({out.stat().st_size} bytes)")
