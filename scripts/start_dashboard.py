"""
Project Unit42-FirmwareX — Dashboard Launcher
Launches Streamlit interactive security dashboard.
"""

import os
import subprocess
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from firmwarex.config import settings

def main():
    dashboard_path = (PROJECT_ROOT / "firmwarex" / "dashboard" / "app.py").resolve()
    print(f"Launching Unit42-FirmwareX Dashboard on port {settings.DASHBOARD_PORT}...")
    
    # Ensure subprocess inherits PYTHONPATH
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")

    cmd = [
        sys.executable, "-m", "streamlit", "run",
        str(dashboard_path),
        "--server.port", str(settings.DASHBOARD_PORT),
        "--server.headless", "true"
    ]
    subprocess.run(cmd, cwd=str(PROJECT_ROOT), env=env)

if __name__ == "__main__":
    main()
