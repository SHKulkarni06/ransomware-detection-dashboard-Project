"""
detection/detector.py
======================
Rule-based + IOC network behaviour analysis.

Each call to analyze_behavior() returns a SecurityEvent describing
what was observed, its severity, MITRE mapping, and all evidence.

Design goals:
  • Low false-positive rate via allowlist + alert cooldown
  • Explainable detections (every alert has a human-readable reason)
  • Pluggable: ML results are merged in capture_packets.py
"""

import logging
import sys
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

# Allow imports from project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.security_event import SecurityEvent
from threat_intel.ioc_checker import check_ip, get_score_boost

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Thresholds                                                           #
# ------------------------------------------------------------------ #
PACKET_RATE_THRESHOLD = 20        # packets/sec — suspicious burst
AVG_PACKET_SIZE_THRESHOLD = 1000  # bytes — large payload indicator
SUSPICIOUS_PROTOCOLS = {"TLS", "SSL", "QUIC"}

# ------------------------------------------------------------------ #
# Trusted IP prefixes (allowlist)                                      #
# ------------------------------------------------------------------ #
TRUSTED_IP_PREFIXES = [
    "140.82.",   # GitHub
    "151.101.",  # Fastly / GitHub CDN
    "142.250.",  # Google
    "172.217.",  # Google
    "20.",       # Microsoft Azure
    "52.",       # AWS
    "13.",       # AWS
    "34.",       # Google Cloud
]

# ------------------------------------------------------------------ #
# Alert cooldown — prevent alert flooding per IP                       #
# ------------------------------------------------------------------ #
_LAST_ALERT_TIME: Dict[str, datetime] = {}
ALERT_COOLDOWN = timedelta(seconds=60)


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

def _is_trusted(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in TRUSTED_IP_PREFIXES)


def can_raise_alert(ip: str) -> bool:
    """
    Enforce per-IP cooldown to suppress duplicate alerts.
    Returns True if enough time has passed since the last alert.
    """
    now = datetime.now()
    last = _LAST_ALERT_TIME.get(ip)

    if last is None or (now - last) > ALERT_COOLDOWN:
        _LAST_ALERT_TIME[ip] = now
        return True

    return False


def _calculate_confidence(rule_score: int, ioc_hit: bool, trusted: bool) -> float:
    """
    Map rule score to a confidence percentage.

    IOC match boosts confidence significantly.
    Trusted IPs receive a confidence penalty.
    """
    base = min(95.0, rule_score * 12.0)
    if ioc_hit:
        base = min(98.0, base + 25.0)
    if trusted:
        base = max(10.0, base - 20.0)
    return round(base, 1)


# ------------------------------------------------------------------ #
# MITRE ATT&CK mapping                                                 #
# ------------------------------------------------------------------ #
def _map_mitre(alerts: List[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Map detected alert reasons to the most relevant MITRE technique.
    Returns (technique_id, tactic_name).
    """
    lower_alerts = " ".join(alerts).lower()

    if "exfil" in lower_alerts or "large" in lower_alerts:
        return "T1041", "Exfiltration"
    if "encrypted" in lower_alerts or "tls" in lower_alerts:
        return "T1071.001", "Command and Control"
    if "ioc" in lower_alerts or "malicious" in lower_alerts:
        return "T1071", "Command and Control"
    if "rate" in lower_alerts:
        return "T1046", "Discovery"

    return None, None


# ------------------------------------------------------------------ #
# Main analysis function                                               #
# ------------------------------------------------------------------ #

def analyze_behavior(summary: dict) -> SecurityEvent:
    """
    Run rule-based analysis on a traffic summary.

    Parameters
    ----------
    summary : dict from feature_extractor.get_summary()

    Returns
    -------
    SecurityEvent with all findings populated.
    """
    alerts: List[str] = []
    rule_score: int = 0

    ip = summary.get("ip", "UNKNOWN")
    packet_rate = summary.get("packet_rate", 0)
    avg_packet_size = summary.get("avg_packet_size", 0)
    protocols = summary.get("protocols", [])

    trusted = _is_trusted(ip)

    # ---- Rule 1: High packet rate ----
    if packet_rate > PACKET_RATE_THRESHOLD:
        alerts.append(f"High packet rate ({packet_rate:.1f} pkt/s > threshold {PACKET_RATE_THRESHOLD})")
        rule_score += 3

    # ---- Rule 2: Large average packet size ----
    if avg_packet_size > AVG_PACKET_SIZE_THRESHOLD:
        alerts.append(f"Large avg packet size ({avg_packet_size:.0f}B — potential data exfiltration)")
        rule_score += 3

    # ---- Rule 3: Suspicious encrypted protocol ----
    matched_protos = [p for p in protocols if p.upper() in SUSPICIOUS_PROTOCOLS]
    if matched_protos:
        alerts.append(f"Encrypted/suspicious protocol usage: {matched_protos}")
        rule_score += 2

    # ---- Rule 4: IOC threat intelligence hit ----
    ioc_hit, ioc_intel = check_ip(ip)
    if ioc_hit:
        threat_type = ioc_intel.get("threat_type", "Unknown")
        source = ioc_intel.get("source", "Unknown")
        alerts.append(f"IOC match — {threat_type} (source: {source})")
        rule_score += get_score_boost(ip)

    # ---- Context decay: trusted services ----
    if trusted and not ioc_hit:
        alerts.append("IP belongs to known trusted CDN/cloud provider")
        rule_score = max(0, rule_score - 2)

    # ---- Confidence ----
    confidence = _calculate_confidence(rule_score, ioc_hit, trusted)

    # ---- Impact weight: network-layer events ----
    # Network alone = moderate impact; boosted in correlator if multi-signal
    impact = min(10, 3 + (rule_score // 2))

    # ---- MITRE mapping ----
    mitre_technique, tactic = _map_mitre(alerts)

    return SecurityEvent(
        source="network",
        event_type="network_behavior_anomaly",
        host=ip,
        user="SYSTEM",
        mitre_technique=mitre_technique,
        tactic=tactic,
        impact=impact,
        confidence=confidence,
        details={
            "ip": ip,
            "packet_rate": packet_rate,
            "avg_packet_size": avg_packet_size,
            "protocols": protocols,
            "alerts": alerts,
            "rule_score": rule_score,
            "ioc_hit": ioc_hit,
            "trusted": trusted,
        },
    )