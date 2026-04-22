"""
run_project.py
==============
Master launcher for the EDR system.

Starts all services in separate threads:
  • File Monitor
  • Process Monitor
  • Network Capture
  • SOC Dashboard

Each service is wrapped in try/except so a crash in one module
does not bring down the entire system.

Usage:
    python run_project.py              # start all services
    python run_project.py --dashboard  # dashboard only (no live capture)
"""

import sys
import os
import threading
import time
import subprocess

PYTHON = sys.executable
ROOT   = os.path.dirname(os.path.abspath(__file__))


def _run_module(label: str, module_path: str) -> None:
    """Launch a Python module as a subprocess and stream its stdout."""
    try:
        print(f"[LAUNCH] {label}")
        proc = subprocess.Popen(
            [PYTHON, module_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=ROOT,
        )
        for line in proc.stdout:
            print(f"[{label}] {line.rstrip()}")
    except Exception as exc:
        print(f"[ERROR] {label}: {exc}")


def _thread(label: str, path: str) -> threading.Thread:
    return threading.Thread(
        target=_run_module,
        args=(label, path),
        daemon=True,
    )


def main() -> None:
    dashboard_only = "--dashboard" in sys.argv

    print("\n" + "=" * 60)
    print("   SOC EDR — RANSOMWARE DETECTION SYSTEM")
    print("=" * 60)

    services = []

    if not dashboard_only:
        services += [
            _thread("FileMonitor",     os.path.join(ROOT, "monitoring", "file_monitor.py")),
            _thread("ProcMonitor",     os.path.join(ROOT, "monitoring", "process_monitor.py")),
            _thread("NetCapture",      os.path.join(ROOT, "capture",    "capture_packets.py")),
        ]

    services += [
        _thread("Dashboard",       os.path.join(ROOT, "dashboard",  "dash_ui.py")),
    ]

    for svc in services:
        svc.start()
        time.sleep(0.5)   # stagger startup

    print("\n[+] All services started")
    print("[+] Dashboard → http://127.0.0.1:8050")
    print("[+] Press CTRL+C to stop all services\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Shutdown signal received — stopping all services")
        sys.exit(0)


if __name__ == "__main__":
    main()