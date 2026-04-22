"""
capture/capture_packets.py
===========================
Main packet capture loop — the heart of the EDR's network layer.
"""

# ------------------------------------------------------------------ #
# FIX: PROJECT ROOT IMPORT PATH                                       #
# ------------------------------------------------------------------ #
import sys
import os

# Add project root (CN/) to Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ------------------------------------------------------------------ #
# IMPORTS                                                             #
# ------------------------------------------------------------------ #
import asyncio
import logging

import pyshark

from features.feature_extractor import extract_features, get_summary, save_features_to_csv
from detection.detector import analyze_behavior, can_raise_alert
from detection.correlator import correlate_signals
from monitoring.file_monitor import detect_file_anomaly
from monitoring.process_monitor import detect_ransomware_behavior
from ml.anomaly_model import train_model, detect_anomaly, is_trained, load_model_from_disk
from response.response_engine import auto_respond

# ------------------------------------------------------------------ #
# Logging setup                                                        #
# ------------------------------------------------------------------ #
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/system.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

logging.getLogger("pyshark").setLevel(logging.CRITICAL)
logger = logging.getLogger("capture")

# ------------------------------------------------------------------ #
# Configuration                                                        #
# ------------------------------------------------------------------ #
INTERFACE = r"\Device\NPF_{F87EC896-7754-4080-8242-80A038E1F76C}"
ML_MIN_SAMPLES = 20

# ------------------------------------------------------------------ #
# Asyncio fix for Windows                                              #
# ------------------------------------------------------------------ #
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

# ------------------------------------------------------------------ #
# Entry point                                                          #
# ------------------------------------------------------------------ #
def main():
    print("\n" + "=" * 60)
    print("  EDR — Network Capture Engine")
    print("  Press CTRL+C to stop")
    print("=" * 60 + "\n")

    # Load saved ML model if exists
    load_model_from_disk()

    capture = pyshark.LiveCapture(interface=INTERFACE, eventloop=loop)

    try:
        for packet in capture.sniff_continuously():
            _process_packet(packet)

    except KeyboardInterrupt:
        print("\n[Capture] Stopped by user")
        logger.info("Packet capture stopped by user")

    finally:
        try:
            capture.close()
        except Exception:
            pass

        save_features_to_csv()
        print("[Capture] Features saved. Shutdown complete.")

# ------------------------------------------------------------------ #
# Per-packet logic                                                     #
# ------------------------------------------------------------------ #
def _process_packet(packet):
    try:
        if not hasattr(packet, "ip"):
            return

        # ----------------------------
        # STEP 1: Feature Extraction
        # ----------------------------
        extract_features(packet)
        summary_list = get_summary()

        # ----------------------------
        # STEP 2: Train ML Model
        # ----------------------------
        if not is_trained() and len(summary_list) >= ML_MIN_SAMPLES:
            train_model(summary_list)

        # ----------------------------
        # STEP 3: Analyze Recent Data
        # ----------------------------
        for summary in summary_list[-3:]:

            ip = summary.get("ip", "UNKNOWN")

            # ---- Rule-based detection ----
            net_event = analyze_behavior(summary)

            # ---- ML anomaly detection ----
            if is_trained() and detect_anomaly(summary):
                net_event.details["alerts"].append(
                    "ML Isolation Forest: behavioural anomaly"
                )
                net_event.impact = min(10, net_event.impact + 2)

            # ---- Skip low-risk events ----
            if net_event.risk_score() < 5:
                continue

            if not can_raise_alert(ip):
                continue

            # ----------------------------
            # STEP 4: Context Monitoring
            # ----------------------------
            file_alerts = detect_file_anomaly()
            process_alerts = detect_ransomware_behavior()

            # ----------------------------
            # STEP 5: Correlation Engine
            # ----------------------------
            severity, reason, incident_id, host_risk = correlate_signals(
                network_event=net_event,
                file_alerts=file_alerts,
                process_alerts=process_alerts,
                ip=ip,
            )

            if severity == "CLEAN":
                continue

            # ----------------------------
            # STEP 6: Logging
            # ----------------------------
            net_event.details["incident_id"] = incident_id
            net_event.details["host_cumulative_risk"] = host_risk
            net_event.details["severity_override"] = severity

            log_line = (
                f"[{severity}] | "
                f"incident={incident_id} | "
                f"IP={ip} | "
                f"score={net_event.risk_score()} | "
                f"confidence={net_event.confidence:.0f}% | "
                f"host_risk={host_risk} | "
                f"reason={reason}"
            )

            print(log_line)
            logger.warning(log_line)

            # ----------------------------
            # STEP 7: Auto Response
            # ----------------------------
            auto_respond(net_event, incident_id)

    except Exception as e:
        logger.debug(f"Packet processing error: {e}")

# ------------------------------------------------------------------ #
# RUN                                                                  #
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    main()