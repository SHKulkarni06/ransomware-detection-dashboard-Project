"""
generate_real_alerts.py
=======================
Injects synthetic log entries to test the dashboard without live capture.

Run this while the dashboard is open at http://127.0.0.1:8050
to see all panels populate with realistic data.
"""

import os
import time
from datetime import datetime

LOG_DIR  = "logs"
FILE_LOG = os.path.join(LOG_DIR, "file_system.log")
SYS_LOG  = os.path.join(LOG_DIR, "system.log")

os.makedirs(LOG_DIR, exist_ok=True)


def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _write(path: str, line: str) -> None:
    with open(path, "a") as fh:
        fh.write(line + "\n")
    print(f"  → {line}")


print("=" * 60)
print("  EDR — Synthetic Alert Generator")
print("=" * 60)

# ---- Scenario 1: Ransomware extensions ----
print("\n[1/4] Injecting ransomware extension events…")
for i in range(8):
    _write(FILE_LOG, f"{_ts()} FILE CREATE C:\\Users\\victim\\docs\\file{i}.locked")
    time.sleep(0.05)

# ---- Scenario 2: Mass file modification ----
print("\n[2/4] Injecting mass file modification…")
for i in range(25):
    _write(FILE_LOG, f"{_ts()} FILE MODIFY C:\\Users\\victim\\work\\report{i}.docx")
    time.sleep(0.02)

# ---- Scenario 3: HIGH alert via system log ----
print("\n[3/4] Injecting HIGH network alert…")
_write(SYS_LOG, (
    f"{_ts()} WARNING [HIGH] | "
    "incident=INC-20240601120000-19216811 | "
    "IP=185.220.101.0 | "
    "score=7.2 | "
    "confidence=85% | "
    "host_risk=21.6 | "
    "reason=Multiple malicious indicators: network + file"
))

# ---- Scenario 4: CRITICAL alert ----
print("\n[4/4] Injecting CRITICAL correlated alert…")
_write(SYS_LOG, (
    f"{_ts()} WARNING [CRITICAL] | "
    "incident=INC-20240601120100-19216811 | "
    "IP=91.215.85.209 | "
    "score=9.0 | "
    "confidence=95% | "
    "host_risk=54.0 | "
    "reason=Confirmed ransomware: all 3 detection layers triggered"
))

print("\n✅ Test data injected. Refresh the dashboard to see results.")
print("   http://127.0.0.1:8050")