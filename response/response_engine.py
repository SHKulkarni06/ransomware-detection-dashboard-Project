"""
response/response_engine.py
============================
Simulated automated response engine.

In a production EDR deployment these functions would call OS APIs,
firewall rules, or SOAR playbooks.  For this system every action is
logged with a clear [RESPONSE] tag so the SOC analyst can audit
every automated decision.

Functions exposed
-----------------
  block_ip(ip)            — simulate network block via iptables / Windows Firewall
  kill_process(pid, name) — simulate terminating a malicious process
  quarantine_file(path)   — simulate moving a file to quarantine
  auto_respond(event)     — decide & apply the right response for a SecurityEvent
"""

import logging
import os
import shutil
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Response log file                                                    #
# ------------------------------------------------------------------ #
RESPONSE_LOG = "logs/response_actions.log"
os.makedirs("logs", exist_ok=True)


def _log_response(action: str, target: str, reason: str) -> None:
    """Write a structured response action entry to the response log."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} [RESPONSE] action={action} | target={target} | reason={reason}"

    with open(RESPONSE_LOG, "a") as fh:
        fh.write(line + "\n")

    logger.warning(line)
    print(line)


# ------------------------------------------------------------------ #
# Response actions                                                     #
# ------------------------------------------------------------------ #

def block_ip(ip: str, reason: str = "Automated threat response") -> bool:
    """
    Simulate blocking an IP address.

    In production: add iptables rule / Windows Firewall rule / push to
    NGFW via API.
    """
    _log_response(
        action="BLOCK_IP",
        target=ip,
        reason=reason,
    )
    # Simulated: would execute OS command here
    # e.g., subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    return True


def kill_process(pid: int, name: str = "UNKNOWN", reason: str = "Suspicious behavior") -> bool:
    """
    Simulate killing a malicious process.

    In production: os.kill(pid, signal.SIGKILL)
    """
    _log_response(
        action="KILL_PROCESS",
        target=f"PID={pid} ({name})",
        reason=reason,
    )
    return True


def quarantine_file(path: str, reason: str = "Suspicious file detected") -> bool:
    """
    Simulate quarantining a file by moving it to a safe folder.

    In production: encrypt + move to isolated quarantine vault.
    """
    quarantine_dir = "quarantine"
    os.makedirs(quarantine_dir, exist_ok=True)

    filename = os.path.basename(path)
    dest = os.path.join(quarantine_dir, f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}")

    _log_response(
        action="QUARANTINE_FILE",
        target=f"{path} → {dest}",
        reason=reason,
    )

    # Actual move (safe to run in test environment)
    try:
        if os.path.exists(path):
            shutil.move(path, dest)
            logger.info(f"File physically moved to quarantine: {dest}")
    except Exception as exc:
        logger.warning(f"Could not physically move file (simulated): {exc}")

    return True


# ------------------------------------------------------------------ #
# Auto-respond based on SecurityEvent severity                         #
# ------------------------------------------------------------------ #

def auto_respond(event, incident_id: str = "N/A") -> None:
    """
    Choose and execute the appropriate response based on the event.

    CRITICAL → block IP + kill any process + quarantine suspicious files
    HIGH     → block IP
    MEDIUM   → log and flag for analyst review
    LOW      → no automated action
    """
    severity = event.severity()
    ip = event.details.get("ip", "UNKNOWN")
    pid = event.details.get("pid")
    filepath = event.details.get("filepath")
    reason = f"Auto-response for {incident_id} [{severity}]"

    if severity == "CRITICAL":
        block_ip(ip, reason)
        if pid:
            kill_process(pid, event.details.get("process_name", "UNKNOWN"), reason)
        if filepath:
            quarantine_file(filepath, reason)

    elif severity == "HIGH":
        block_ip(ip, reason)

    elif severity == "MEDIUM":
        _log_response(
            action="FLAG_FOR_REVIEW",
            target=ip,
            reason=f"Medium severity event — manual review recommended ({incident_id})",
        )

    else:
        # LOW — informational only
        logger.info(f"[RESPONSE] No automated action for LOW severity event on {ip}")