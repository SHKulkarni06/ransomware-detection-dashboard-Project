"""
detection/correlator.py
========================
Multi-signal threat correlation engine.

Aggregates evidence from three detection layers:
  • Network anomaly (weight 3)
  • File anomaly    (weight 4)
  • Process anomaly (weight 5)

Correlation rules
-----------------
  ≥3 signals  → CRITICAL  (Confirmed attack)
   2 signals  → HIGH      (Strong indicators)
   1 signal   → MEDIUM    (Suspicious)
   0 signals  → CLEAN

Bonus features implemented
--------------------------
  • Host risk scoring   — tracks cumulative risk per IP over time
  • Incident grouping   — merges events within a time window
  • Behavior stabilization — decays host risk score when clean
"""

import logging
import sys
import os
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.security_event import SecurityEvent

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Signal weights                                                       #
# ------------------------------------------------------------------ #
NETWORK_WEIGHT = 3
FILE_WEIGHT    = 4
PROCESS_WEIGHT = 5

# ------------------------------------------------------------------ #
# Host risk tracking (bonus feature: host risk scoring)               #
# ------------------------------------------------------------------ #
# Maps IP → { cumulative_score, last_seen, incidents: [] }
_host_risk_table: Dict[str, dict] = defaultdict(lambda: {
    "cumulative_score": 0.0,
    "last_seen": datetime.now(),
    "incidents": [],
    "stable_count": 0,           # consecutive clean cycles
})

DECAY_AFTER_CLEAN_CYCLES = 5    # behaviour stabilization threshold
RISK_DECAY_FACTOR = 0.8         # multiply score by this on clean cycle


# ------------------------------------------------------------------ #
# Incident store (bonus: incident grouping)                            #
# ------------------------------------------------------------------ #
# Maps incident_id → { events, opened_at, severity }
_incidents: Dict[str, dict] = {}
INCIDENT_WINDOW = timedelta(minutes=15)   # group events within this window


def _get_or_create_incident(ip: str, severity: str, reason: str) -> str:
    """
    Return an existing open incident ID for the IP within the time window,
    or create a new incident and return its ID.
    """
    now = datetime.now()

    for inc_id, inc in _incidents.items():
        if inc["ip"] == ip and (now - inc["opened_at"]) < INCIDENT_WINDOW:
            # Merge into existing incident
            inc["events"].append({"time": now, "severity": severity, "reason": reason})
            inc["severity"] = severity  # escalate if higher
            logger.debug(f"Merged event into incident {inc_id}")
            return inc_id

    # Create new incident
    inc_id = f"INC-{now.strftime('%Y%m%d%H%M%S')}-{ip.replace('.', '')}"
    _incidents[inc_id] = {
        "ip": ip,
        "severity": severity,
        "reason": reason,
        "opened_at": now,
        "events": [{"time": now, "severity": severity, "reason": reason}],
    }
    logger.info(f"New incident opened: {inc_id} for IP={ip} [{severity}]")
    return inc_id


# ------------------------------------------------------------------ #
# Behaviour stabilization                                              #
# ------------------------------------------------------------------ #

def _update_host_risk(ip: str, score_delta: float, clean: bool) -> float:
    """
    Update the host risk table.

    On clean cycles, increment stable_count and apply decay if stable
    enough. On dirty cycles, add score_delta and reset stable_count.
    """
    record = _host_risk_table[ip]
    record["last_seen"] = datetime.now()

    if clean:
        record["stable_count"] += 1
        if record["stable_count"] >= DECAY_AFTER_CLEAN_CYCLES:
            before = record["cumulative_score"]
            record["cumulative_score"] *= RISK_DECAY_FACTOR
            logger.debug(
                f"[Stabilization] {ip}: score decayed {before:.1f}→{record['cumulative_score']:.1f}"
            )
    else:
        record["cumulative_score"] += score_delta
        record["stable_count"] = 0

    return round(record["cumulative_score"], 2)


# ------------------------------------------------------------------ #
# Public correlation API                                               #
# ------------------------------------------------------------------ #

def correlate_signals(
    network_event: Optional[SecurityEvent],
    file_alerts: List[str],
    process_alerts: List[str],
    ip: str = "UNKNOWN",
) -> Tuple[str, str, str, float]:
    """
    Combine evidence from all detection layers into a final verdict.

    Parameters
    ----------
    network_event  : SecurityEvent from detector.analyze_behavior()
    file_alerts    : List of file anomaly strings from file_monitor
    process_alerts : List of process anomaly strings from process_monitor
    ip             : Source IP for host risk tracking

    Returns
    -------
    (severity, reason, incident_id, host_cumulative_risk)
    """
    weighted_score = 0
    active_signals = []
    reason_parts = []

    # ---- Network layer ----
    if network_event and network_event.details.get("rule_score", 0) >= 3:
        weighted_score += NETWORK_WEIGHT
        active_signals.append("network")
        reason_parts.append(f"Net({network_event.details.get('rule_score',0)})")

    # ---- File layer ----
    if file_alerts:
        weighted_score += FILE_WEIGHT
        active_signals.append("file")
        reason_parts.append(f"File({len(file_alerts)} alerts)")

    # ---- Process layer ----
    if process_alerts:
        weighted_score += PROCESS_WEIGHT
        active_signals.append("process")
        reason_parts.append(f"Proc({len(process_alerts)} alerts)")

    # ---- Severity decision ----
    num_signals = len(active_signals)

    if num_signals >= 3:
        severity = "CRITICAL"
        reason = "Confirmed ransomware: all 3 detection layers triggered"
    elif num_signals == 2:
        severity = "HIGH"
        reason = f"Multiple malicious indicators: {' + '.join(active_signals)}"
    elif num_signals == 1:
        severity = "MEDIUM"
        reason = f"Suspicious activity — {active_signals[0]} layer only"
    else:
        severity = "CLEAN"
        reason = "No threat indicators detected"

    # ---- Incident grouping ----
    incident_id = "N/A"
    if severity != "CLEAN":
        incident_id = _get_or_create_incident(ip, severity, reason)

    # ---- Host risk scoring ----
    host_risk = _update_host_risk(ip, float(weighted_score), clean=(severity == "CLEAN"))

    detail_str = f"{reason} | signals={'+'.join(reason_parts) or 'none'} | host_risk={host_risk}"
    logger.info(f"[CORRELATOR] {ip} → {severity} | {detail_str}")

    return severity, detail_str, incident_id, host_risk


# ------------------------------------------------------------------ #
# Read-only accessors for dashboard                                    #
# ------------------------------------------------------------------ #

def get_all_incidents() -> List[dict]:
    """Return a list of all tracked incidents (for dashboard)."""
    result = []
    for inc_id, inc in _incidents.items():
        result.append({
            "incident_id": inc_id,
            "ip": inc["ip"],
            "severity": inc["severity"],
            "reason": inc["reason"],
            "opened_at": inc["opened_at"].strftime("%Y-%m-%d %H:%M:%S"),
            "event_count": len(inc["events"]),
        })
    return sorted(result, key=lambda x: x["opened_at"], reverse=True)


def get_host_risk_table() -> List[dict]:
    """Return all host risk scores sorted by risk (for dashboard heatmap)."""
    rows = []
    for ip, rec in _host_risk_table.items():
        rows.append({
            "ip": ip,
            "cumulative_risk": rec["cumulative_score"],
            "last_seen": rec["last_seen"].strftime("%Y-%m-%d %H:%M:%S"),
            "stable_count": rec["stable_count"],
        })
    return sorted(rows, key=lambda x: x["cumulative_risk"], reverse=True)