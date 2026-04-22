"""
monitoring/process_monitor.py
==============================
Real-time process behavioural monitor using psutil.

Detects ransomware-typical process patterns:
  • Execution of known ransomware CLI commands (vssadmin, bcdedit…)
  • Script interpreters running from TEMP / AppData / Downloads
  • Process spawn bursts (many new processes in a short window)
  • Abnormally high CPU usage from unexpected processes

Writes structured alerts to logs/process_system.log and exposes
detect_ransomware_behavior() for use by the correlation engine.
"""

import os
import sys
import time
import logging
from datetime import datetime
from typing import List, Set

import psutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.security_event import SecurityEvent

# ------------------------------------------------------------------ #
# Configuration                                                        #
# ------------------------------------------------------------------ #
CPU_THRESHOLD = 40             # % CPU to flag as suspicious
PROCESS_BURST_THRESHOLD = 6    # new processes in BURST_WINDOW seconds
BURST_WINDOW = 5               # seconds

LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "process_system.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

# ------------------------------------------------------------------ #
# Detection lists                                                      #
# ------------------------------------------------------------------ #
SUSPICIOUS_COMMANDS = [
    "vssadmin", "shadowcopy", "bcdedit", "wbadmin",
    "cipher", "-enc", "encodedcommand", "invoke-expression",
    "downloadstring", "bypass", "hidden",
]

SCRIPT_HOSTS = {
    "powershell.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "python.exe", "mshta.exe",
}

TRUSTED_PROCESSES = {
    "system", "system idle process", "explorer.exe",
    "svchost.exe", "chrome.exe", "msedge.exe", "zoom.exe",
    "teams.exe", "code.exe", "dwm.exe", "wmiprvse.exe",
    "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
    "taskhostw.exe", "sihost.exe", "fontdrvhost.exe",
}

TEMP_PATH = os.environ.get("TEMP", "").lower()
APPDATA_PATH = os.environ.get("APPDATA", "").lower()
DOWNLOAD_PATH = os.path.join(os.path.expanduser("~"), "downloads").lower()

# ------------------------------------------------------------------ #
# Runtime state                                                        #
# ------------------------------------------------------------------ #
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("process_monitor")

_seen_pids: Set[int] = set()
_spawn_times: List[float] = []
_cpu_alerted: Set[int] = set()
_current_alerts: List[str] = []   # latest cycle results for correlator


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

def _alert(msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} [PROCESS ALERT] {msg}"
    with open(LOG_PATH, "a") as fh:
        fh.write(line + "\n")
    logger.warning(msg)
    print(line)
    _current_alerts.append(msg)


# ------------------------------------------------------------------ #
# Public API                                                           #
# ------------------------------------------------------------------ #

def detect_ransomware_behavior() -> List[str]:
    """
    Scan all running processes for ransomware behavioural indicators.

    Returns a list of alert strings for the current cycle.
    Called repeatedly by the monitoring loop and by capture_packets.py.
    """
    global _spawn_times
    _current_alerts.clear()

    now = time.time()

    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid"]):
        try:
            pid = proc.info["pid"]
            name = (proc.info["name"] or "").lower()

            if not name or name in TRUSTED_PROCESSES:
                continue

            exe = proc.info.get("exe") or ""
            cmdline_list = proc.info.get("cmdline") or []
            cmd = " ".join(cmdline_list).lower()
            exe_lower = exe.lower()

            logger.debug(f"Monitoring: {name} | PID={pid}")

            # ---- Rule 1: Suspicious CLI commands ----
            for keyword in SUSPICIOUS_COMMANDS:
                if keyword in cmd:
                    _alert(
                        f"[T1059] Ransomware command detected: {name} (PID={pid}) → {cmd[:120]}"
                    )
                    break

            # ---- Rule 2: Script host in suspicious path ----
            if name in SCRIPT_HOSTS and exe:
                if any(p in exe_lower for p in [TEMP_PATH, APPDATA_PATH, DOWNLOAD_PATH] if p):
                    _alert(
                        f"[T1059] Script host from suspicious path: {exe} (PID={pid})"
                    )

            # ---- Rule 3: Process burst ----
            if pid not in _seen_pids:
                _seen_pids.add(pid)
                _spawn_times.append(now)

            _spawn_times = [t for t in _spawn_times if now - t < BURST_WINDOW]

            if len(_spawn_times) > PROCESS_BURST_THRESHOLD:
                _alert(
                    f"[T1059] Process spawn burst: {len(_spawn_times)} new processes "
                    f"in {BURST_WINDOW}s"
                )
                _spawn_times.clear()

            # ---- Rule 4: High CPU ----
            cpu = proc.cpu_percent(interval=0.05)
            if cpu > CPU_THRESHOLD and pid not in _cpu_alerted:
                _alert(
                    f"[T1486] High CPU usage: {name} (PID={pid}) at {cpu:.1f}% — "
                    f"possible encryption activity"
                )
                _cpu_alerted.add(pid)
            elif cpu <= CPU_THRESHOLD and pid in _cpu_alerted:
                _cpu_alerted.discard(pid)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception as exc:
            logger.debug(f"Process scan error: {exc}")

    return list(_current_alerts)


# ------------------------------------------------------------------ #
# Standalone run                                                       #
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    print("[Process Monitor] Starting — watching for ransomware behaviour…")

    for proc in psutil.process_iter(["pid"]):
        _seen_pids.add(proc.pid)

    while True:
        alerts = detect_ransomware_behavior()
        if alerts:
            for a in alerts:
                print(f" -> {a}")   # ✅ FIXED
        time.sleep(0.5)