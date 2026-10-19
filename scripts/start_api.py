"""
Project Unit42-FirmwareX — API Server Launcher
Starts FastAPI server on configured host and port.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import uvicorn
from firmwarex.config import settings

def main():
    print(f"Starting Unit42-FirmwareX API Server on http://{settings.API_HOST}:{settings.API_PORT}...")
    uvicorn.run("firmwarex.api.app:app", host=settings.API_HOST, port=settings.API_PORT, reload=False)

if __name__ == "__main__":
    main()
