import sys
import os

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Import and execute demo test scenarios directly
from cli_client import run_all_scenarios, SERVER_URL

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else SERVER_URL
    run_all_scenarios(url)
