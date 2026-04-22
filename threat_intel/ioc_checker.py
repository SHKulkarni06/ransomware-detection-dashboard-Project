"""
threat_intel/ioc_checker.py
============================
Threat Intelligence IOC (Indicator of Compromise) lookup engine.

Maintains an in-memory IOC database (IPs, domains, hashes).
In production, this would pull from MISP, AlienVault OTX, or VirusTotal.
For this EDR system, we seed it with known-bad IPs and provide
a clean API for other modules to query.
"""

import logging
import os
from datetime import datetime
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Seed IOC Database                                                    #
# ------------------------------------------------------------------ #
# Structure: { "ip": { "source": str, "threat_type": str, "added": str } }

KNOWN_MALICIOUS_IPS: Dict[str, dict] = {
    # Known ransomware C2 / exfil servers (sample threat intel)
    "185.220.101.0":  {"source": "ThreatFox", "threat_type": "RansomwareC2",   "added": "2024-01-01"},
    "194.165.16.11":  {"source": "AbuseIPDB", "threat_type": "Botnet",         "added": "2024-02-15"},
    "45.142.212.100": {"source": "AlienVault","threat_type": "CryptoMiner",    "added": "2024-03-01"},
    "91.215.85.209":  {"source": "ThreatFox", "threat_type": "TrojanC2",       "added": "2024-04-10"},
    "5.188.206.14":   {"source": "SpamHaus",  "threat_type": "Phishing",       "added": "2024-05-01"},
    "193.32.162.157": {"source": "ThreatFox", "threat_type": "RansomwareC2",   "added": "2024-06-20"},
    "10.0.0.66":      {"source": "Internal",  "threat_type": "TestMaliciousIP","added": "2024-01-01"},
}

# Risk score boost when an IOC match is found
IOC_SCORE_BOOST = 8


# ------------------------------------------------------------------ #
# Public API                                                           #
# ------------------------------------------------------------------ #

def check_ip(ip: str) -> Tuple[bool, Optional[dict]]:
    """
    Look up an IP in the IOC database.

    Returns
    -------
    (True, intel_dict)  if the IP is malicious
    (False, None)       if the IP is clean
    """
    intel = KNOWN_MALICIOUS_IPS.get(ip)
    if intel:
        logger.warning(f"IOC HIT: {ip} matched as {intel['threat_type']} (src={intel['source']})")
        return True, intel
    return False, None


def get_score_boost(ip: str) -> int:
    """
    Returns additional risk score to add if IP matches an IOC.
    Returns 0 if no match.
    """
    matched, _ = check_ip(ip)
    return IOC_SCORE_BOOST if matched else 0


def add_ioc(ip: str, source: str, threat_type: str) -> None:
    """
    Dynamically add a new IOC at runtime (e.g. from live threat feed).
    """
    KNOWN_MALICIOUS_IPS[ip] = {
        "source": source,
        "threat_type": threat_type,
        "added": datetime.now().strftime("%Y-%m-%d")
    }
    logger.info(f"New IOC added: {ip} ({threat_type}) from {source}")


def list_iocs() -> Dict[str, dict]:
    """Return the full IOC table (for dashboard display)."""
    return dict(KNOWN_MALICIOUS_IPS)