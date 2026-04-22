"""
core/security_event.py
======================
Central data model for all security events in the EDR system.
Every detection pipeline returns a SecurityEvent object — this ensures
consistent structure across network, file, and process detections.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import json
import socket


def _get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "UNKNOWN_HOST"


@dataclass
class SecurityEvent:
    """
    Structured representation of a security detection event.

    Fields
    ------
    source        : Origin of the detection (network / file / process)
    event_type    : Specific type of event (e.g. 'high_packet_rate')
    host          : Hostname where the event occurred
    user          : OS user associated with the event
    mitre_technique : MITRE ATT&CK technique ID (e.g. T1041)
    tactic        : MITRE ATT&CK tactic (e.g. Exfiltration)
    impact        : Raw impact weight (1–10)
    confidence    : Confidence percentage (0–100)
    details       : Arbitrary dict with raw evidence
    timestamp     : Auto-set to creation time
    """

    source: str
    event_type: str
    host: str
    user: str
    mitre_technique: Optional[str]
    tactic: Optional[str]
    impact: int                         # 1–10
    confidence: float                   # 0–100
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

    # ------------------------------------------------------------------ #
    # Computed properties                                                  #
    # ------------------------------------------------------------------ #

    def risk_score(self) -> float:
        """Composite risk = impact × (confidence / 10)"""
        return round(self.impact * (self.confidence / 10), 2)

    def severity(self) -> str:
        """Map risk score to human-readable severity band."""
        score = self.risk_score()
        if score >= 25:
            return "CRITICAL"
        elif score >= 15:
            return "HIGH"
        elif score >= 7:
            return "MEDIUM"
        else:
            return "LOW"

    def to_dict(self) -> dict:
        """Serialize event to plain dictionary (JSON-safe)."""
        return {
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "source": self.source,
            "event_type": self.event_type,
            "host": self.host,
            "user": self.user,
            "mitre_technique": self.mitre_technique,
            "tactic": self.tactic,
            "impact": self.impact,
            "confidence": self.confidence,
            "risk_score": self.risk_score(),
            "severity": self.severity(),
            "details": self.details,
        }

    def to_log_line(self) -> str:
        """Format a single-line log entry for structured log files."""
        return (
            f"[{self.severity()}] | "
            f"src={self.source} | "
            f"type={self.event_type} | "
            f"host={self.host} | "
            f"score={self.risk_score()} | "
            f"confidence={self.confidence:.0f}% | "
            f"mitre={self.mitre_technique or 'N/A'} | "
            f"tactic={self.tactic or 'N/A'} | "
            f"details={json.dumps(self.details, default=str)}"
        )