"""
monitoring/file_monitor.py
===========================
Real-time file system monitoring using the watchdog library.

Detects ransomware-typical file activity:
  • Mass file modifications (>= FILE_THRESHOLD files in 60s)
  • Known ransomware extensions (.locked, .enc, .crypt, .encrypted)

Writes structured events to logs/file_system.log and exposes
detect_file_anomaly() for the correlation engine to call.
"""

import os
import sys
import time
import logging
from collections import deque
from datetime import datetime
from typing import List

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.security_event import SecurityEvent

# ------------------------------------------------------------------ #
# Configuration                                                        #
# ------------------------------------------------------------------ #
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(PROJECT_ROOT, "..", "logs", "file_system.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

FILE_THRESHOLD = 20          # files/minute to trigger mass-change alert
WINDOW_SECONDS = 60          # sliding window duration

SUSPICIOUS_EXTENSIONS = {".locked", ".enc", ".crypt", ".encrypted", ".ryk", ".ryuk"}

# In-memory sliding window: stores (filepath, timestamp) tuples
_file_activity: deque = deque()

# ------------------------------------------------------------------ #
# Logging                                                              #
# ------------------------------------------------------------------ #
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("file_monitor")


def _log_file_event(event_type: str, path: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} FILE {event_type.upper()} {path}"
    with open(LOG_PATH, "a") as fh:
        fh.write(line + "\n")


# ------------------------------------------------------------------ #
# Detection logic                                                      #
# ------------------------------------------------------------------ #

def record_file_event(filepath: str) -> None:
    """Add a file event to the sliding window."""
    _file_activity.append((filepath, time.time()))


def detect_file_anomaly() -> List[str]:
    """
    Analyse the sliding window for ransomware file patterns.

    Returns a list of alert strings (empty if nothing suspicious).
    """
    alerts: List[str] = []
    now = time.time()

    # Prune events outside the window
    while _file_activity and (now - _file_activity[0][1]) > WINDOW_SECONDS:
        _file_activity.popleft()

    recent = list(_file_activity)

    # Rule 1: Mass file modification
    if len(recent) >= FILE_THRESHOLD:
        msg = (
            f"[T1486] Mass file modification: {len(recent)} file events "
            f"in {WINDOW_SECONDS}s — possible ransomware encryption"
        )
        alerts.append(msg)
        logger.warning(msg)

    # Rule 2: Ransomware extension
    seen_ext_paths = set()
    for filepath, _ in recent:
        _, ext = os.path.splitext(filepath)
        if ext.lower() in SUSPICIOUS_EXTENSIONS and filepath not in seen_ext_paths:
            seen_ext_paths.add(filepath)
            msg = f"[T1486] Ransomware extension detected: {filepath}"
            alerts.append(msg)
            logger.warning(msg)

    return alerts


# ------------------------------------------------------------------ #
# Watchdog event handler                                               #
# ------------------------------------------------------------------ #

class _FileMonitorHandler(FileSystemEventHandler):

    def _handle(self, event_type: str, path: str) -> None:
        if not os.path.isdir(path):
            _log_file_event(event_type, path)
            record_file_event(path)

            alerts = detect_file_anomaly()
            for alert in alerts:
                print(f"[FILE ALERT] {alert}")

    def on_created(self, event):
        self._handle("CREATE", event.src_path)

    def on_modified(self, event):
        self._handle("MODIFY", event.src_path)

    def on_deleted(self, event):
        self._handle("DELETE", event.src_path)


# ------------------------------------------------------------------ #
# Start monitoring                                                     #
# ------------------------------------------------------------------ #

def start_monitor(folder: str = "test_files") -> None:
    """
    Start watchdog observer on the given folder.
    Blocks until KeyboardInterrupt.
    """
    watch_path = os.path.join(PROJECT_ROOT, "..", folder)
    os.makedirs(watch_path, exist_ok=True)

    handler = _FileMonitorHandler()
    observer = Observer()
    observer.schedule(handler, watch_path, recursive=True)
    observer.start()

    print(f"[File Monitor] Watching: {watch_path}")
    logger.info(f"File monitor started on {watch_path}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logger.info("File monitor stopped")

    observer.join()


if __name__ == "__main__":
    start_monitor()