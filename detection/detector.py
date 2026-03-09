from datetime import datetime, timedelta
import sys
import os
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.security_event import SecurityEvent

# ===============================
# Alert rate limiting (cooldown)
# ===============================
LAST_ALERT_TIME = {}
ALERT_COOLDOWN = timedelta(seconds=60)


# ===============================
# Trusted IP allowlist
# ===============================
TRUSTED_IP_PREFIXES = [
    "140.82.",   # GitHub
    "151.101.",  # Fastly (GitHub CDN)
    "142.250.",  # Google
    "20.",       # Microsoft Azure
    "52.",       # AWS
]


def is_trusted_ip(ip):
    return any(ip.startswith(prefix) for prefix in TRUSTED_IP_PREFIXES)


def can_raise_alert(ip):
    now = datetime.now()

    if ip not in LAST_ALERT_TIME:
        LAST_ALERT_TIME[ip] = now
        return True

    if now - LAST_ALERT_TIME[ip] > ALERT_COOLDOWN:
        LAST_ALERT_TIME[ip] = now
        return True

    return False


# ===============================
# Detection thresholds
# ===============================
PACKET_RATE_THRESHOLD = 20
AVG_PACKET_SIZE_THRESHOLD = 1000
SUSPICIOUS_PROTOCOLS = {"TLS", "SSL"}


# ===============================
# Confidence calculation
# ===============================
def calculate_confidence(rule_score, trusted=False):
    """
    Convert rule score into confidence percentage.
    """

    confidence = min(95, rule_score * 15)

    if trusted:
        confidence -= 20  # decay confidence for trusted services

    return max(confidence, 10)


# ===============================
# MAIN ANALYSIS FUNCTION
# ===============================
def analyze_behavior(summary):
    """
    Rule-based network behavior analysis.
    Returns a structured SecurityEvent object.
    """

    alerts = []
    rule_score = 0

    ip = summary.get("ip", "UNKNOWN")
    packet_rate = summary.get("packet_rate", 0)
    avg_packet_size = summary.get("avg_packet_size", 0)
    protocols = summary.get("protocols", [])

    trusted = is_trusted_ip(ip)

    # -------------------------------
    # Rule 1: High packet rate
    # -------------------------------
    if packet_rate > PACKET_RATE_THRESHOLD:
        alerts.append("High packet rate in short time")
        rule_score += 3

    # -------------------------------
    # Rule 2: Large packets
    # -------------------------------
    if avg_packet_size > AVG_PACKET_SIZE_THRESHOLD:
        alerts.append("Large average packet size")
        rule_score += 3

    # -------------------------------
    # Rule 3: Encrypted protocols
    # -------------------------------
    if any(p in SUSPICIOUS_PROTOCOLS for p in protocols):
        alerts.append("Encrypted or suspicious protocol usage")
        rule_score += 2

    # -------------------------------
    # Context awareness (allowlist)
    # -------------------------------
    if trusted:
        alerts.append("Known trusted service")
        rule_score -= 2

    # Prevent negative score
    rule_score = max(rule_score, 0)

    # -------------------------------
    # Confidence score
    # -------------------------------
    confidence = calculate_confidence(rule_score, trusted)

    # -------------------------------
    # Impact weighting (network = medium impact)
    # -------------------------------
    impact = 3  # Network-based anomaly base impact

    # -------------------------------
    # MITRE Mapping (basic example)
    # -------------------------------
    mitre_technique = None
    tactic = None

    if rule_score >= 5:
        mitre_technique = "T1041"
        tactic = "Exfiltration"

    # -------------------------------
    # Create structured Security Event
    # -------------------------------
    event = SecurityEvent(
        source="network",
        event_type="network_behavior_anomaly",
        host="LOCAL_HOST",
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
            "rule_score": rule_score
        }
    )

    return event
