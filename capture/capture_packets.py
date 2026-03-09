import pyshark
import logging
import os
import asyncio
import sys


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.security_event import SecurityEvent

from ml.anomaly_model import train_model, detect_anomaly
from detection.detector import analyze_behavior, can_raise_alert
from detection.correlator import correlate_signals
from monitoring.file_monitor import detect_file_anomaly
from monitoring.process_monitor import detect_ransomware_behavior
from features.feature_extractor import (
    extract_features,
    get_summary,
    save_features_to_csv
)

# =====================================
# Fix asyncio for Windows + PyShark
# =====================================
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

# =====================================
# Logging setup
# =====================================
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/system.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logging.getLogger("pyshark").setLevel(logging.CRITICAL)
logger = logging.getLogger(__name__)

print("Starting packet capture... Press CTRL+C to stop")

# =====================================
# Network interface
# =====================================
INTERFACE = r"\Device\NPF_{F87EC896-7754-4080-8242-80A038E1F76C}"

capture = pyshark.LiveCapture(
    interface=INTERFACE,
    eventloop=loop
)

ml_trained = False

# =====================================
# MAIN LOOP
# =====================================
try:
    for packet in capture.sniff_continuously():
        try:
            if not hasattr(packet, "ip"):
                continue

            protocol = packet.highest_layer
            length = int(packet.length)
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            msg = f"Protocol={protocol}, Size={length}, Src={src_ip}, Dst={dst_ip}"
            print(msg)
            logger.info(msg)

            # 1️⃣ Feature extraction
            extract_features(packet)
            summary = get_summary()

            # 2️⃣ Train ML once (baseline learning)
            if not ml_trained and len(summary) >= 20:
                train_model(summary)
                ml_trained = True
                print("[ML] Model trained on normal traffic")
                logger.info("ML model trained on normal traffic")

            # 3️⃣ Network detection
            for s in summary[-3:]:
                result = analyze_behavior(s)

                if ml_trained and detect_anomaly(s):
                    result["alerts"].append("ML anomaly detected")
                    result["risk_score"] += 3

                # Only proceed if network is suspicious
                if result["risk_score"] >= 5 and can_raise_alert(result["ip"]):

                    # 4️⃣ Contextual monitoring
                    file_alerts = detect_file_anomaly()
                    process_alerts = detect_process_anomaly()

                    # 5️⃣ Correlation
                    severity, reason = correlate_signals(
                        network_alerts=result["alerts"],
                        file_alerts=file_alerts,
                        process_alerts=process_alerts
                    )

                    alert_msg = (
                        f"[{severity}] | IP={result['ip']} | "
                        f"Risk={result['status']} | "
                        f"Score={result['risk_score']} | "
                        f"Confidence={result['confidence']}% | "
                        f"Reason={reason}"
                    )

                    print(alert_msg)
                    logger.warning(alert_msg)

        except Exception:
            pass

except KeyboardInterrupt:
    print("\nPacket capture stopped by user")
    logger.info("Packet capture stopped by user")

finally:
    try:
        capture.close()
    except Exception:
        pass

    save_features_to_csv()
    print("Features saved. Shutdown complete.")
