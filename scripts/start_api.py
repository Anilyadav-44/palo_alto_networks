"""
Project Unit42-FirmwareX — API Server Launcher
Starts FastAPI server on configured host and port.
"""

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import uvicorn
from firmwarex.config import settings

def main():
    host = os.environ.get("FIRMWAREX_API_HOST", settings.API_HOST)
    port = int(os.environ.get("PORT", settings.API_PORT))
    print(f"Starting Unit42-FirmwareX API Server on http://{host}:{port}...")
    uvicorn.run("firmwarex.api.app:app", host=host, port=port, reload=False)

if __name__ == "__main__":
    main()
