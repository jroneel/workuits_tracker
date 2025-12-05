"""Run the Streamlit development server for this package.

This wrapper invokes the Streamlit CLI using the project's Python interpreter
so the app (`sl_difuzion/main.py`) is executed under Streamlit's runner.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    """Launch Streamlit pointing at the package's `main.py`.

    Any additional CLI args passed to this entry point are forwarded to
    Streamlit. Returns Streamlit's exit code.
    """
    pkg_root = Path(__file__).resolve().parent
    script = pkg_root / "main.py"
    if not script.exists():
        print(f"Error: cannot find {script}")
        return 2

    cmd = [sys.executable, "-m", "streamlit", "run", str(script)] + sys.argv[1:]
    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
