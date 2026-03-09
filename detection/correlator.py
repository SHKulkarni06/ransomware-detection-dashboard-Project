import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.security_event import SecurityEvent

def correlate_signals(network_alerts, file_alerts, process_alerts):
    signals = 0

    if network_alerts:
        signals += 1
    if file_alerts:
        signals += 1
    if process_alerts:
        signals += 1

    if signals >= 3:
        return "CRITICAL", "Confirmed ransomware activity"
    elif signals == 2:
        return "HIGH", "Multiple malicious indicators"
    elif signals == 1:
        return "LOW", "Suspicious but unconfirmed"
    else:
        return "CLEAN", "No threat detected"
