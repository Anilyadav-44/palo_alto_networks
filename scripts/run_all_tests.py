"""
Project Unit42-FirmwareX — Automated Test Runner
Runs complete test suite and outputs coverage metrics.
"""

import subprocess
import sys

def main():
    print("=" * 60)
    print(" Unit42-FirmwareX: Running Verification Test Suite")
    print("=" * 60)
    cmd = [sys.executable, "-m", "pytest", "tests", "-v", "--cov=firmwarex"]
    result = subprocess.run(cmd)
    sys.exit(result.returncode)

if __name__ == "__main__":
    main()
