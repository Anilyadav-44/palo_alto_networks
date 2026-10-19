"""
Project Unit42-FirmwareX — IoT NVRAM & Peripheral Stubbing Engine
Stubs common router and IP camera NVRAM variables to allow services to initialize cleanly without hardware.
"""

from pathlib import Path
from typing import Dict, Any

DEFAULT_NVRAM_VALUES = {
    # System & Credentials
    "http_username": "admin",
    "http_passwd": "password123",
    "http_password": "admin",
    "login_name": "admin",
    "login_password": "password",
    "preshared_key": "WirelessSecret2026",
    
    # Network interfaces
    "lan_ipaddr": "192.168.1.1",
    "lan_netmask": "255.255.255.0",
    "lan_gateway": "192.168.1.1",
    "lan_hwaddr": "00:11:22:33:44:55",
    "wan_ipaddr": "10.0.0.2",
    "wan_netmask": "255.255.255.0",
    "wan_gateway": "10.0.0.1",
    "wan_proto": "dhcp",
    
    # Wireless & Web
    "wlan_ssid": "Unit42_Test_AP",
    "http_enable": "1",
    "http_port": "80",
    "https_port": "443",
    "upnp_enable": "1",
    "telnetd_enable": "0",
    "sshd_enable": "0",
    
    # Device identity
    "model_name": "Unit42-SecureGW-X1",
    "hardware_version": "v1.0",
    "firmware_version": "1.0.42-BUILD2026"
}

class NVRAMStubber:
    """Injects simulated NVRAM environment and default configurations into rootfs"""

    @classmethod
    def apply_stubs(cls, rootfs_dir: Path, custom_overrides: Dict[str, str] = None) -> Dict[str, Any]:
        nvram_data = DEFAULT_NVRAM_VALUES.copy()
        if custom_overrides:
            nvram_data.update(custom_overrides)

        etc_dir = rootfs_dir / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)
        
        # 1. Write /etc/nvram.conf (key=value format)
        conf_file = etc_dir / "nvram.conf"
        with open(conf_file, "w") as f:
            for k, v in nvram_data.items():
                f.write(f"{k}={v}\n")

        # 2. Write /etc/default_nvram
        def_file = etc_dir / "default_nvram"
        with open(def_file, "w") as f:
            for k, v in nvram_data.items():
                f.write(f"{k}={v}\n")

        # 3. Create /dev/null, /dev/urandom dummy placeholders if not present
        dev_dir = rootfs_dir / "dev"
        dev_dir.mkdir(parents=True, exist_ok=True)

        return {
            "applied_keys_count": len(nvram_data),
            "config_path": str(conf_file),
            "keys": list(nvram_data.keys())
        }
