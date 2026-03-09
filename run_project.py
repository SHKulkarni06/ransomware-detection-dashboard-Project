import threading
import subprocess
import sys

PYTHON = sys.executable


def run_service(name, path):

    try:
        print(f"[STARTING] {name} -> {path}")

        process = subprocess.Popen(
            [PYTHON, path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        # Print live output
        for line in process.stdout:
            print(f"[{name}] {line.strip()}")

    except Exception as e:
        print(f"[ERROR] {name} -> {e}")


def file_monitor():
    run_service("File Monitor", "monitoring/file_monitor.py")


def process_monitor():
    run_service("Process Monitor", "monitoring/process_monitor.py")


def network_capture():
    run_service("Network Capture", "capture/capture_packets.py")


def network_feature():
    run_service("Feature Extractor", "features/feature_extractor.py")


def rule_engine():
    run_service("Rule Detection Engine", "detection/detector.py")


def ml_engine():
    run_service("ML Engine", "ml/anomaly_model.py")


def correlator():
    run_service("Threat Correlator", "detection/correlator.py")


def dashboard():
    run_service("SOC Dashboard", "dash_ui.py",)


if __name__ == "__main__":

    print("\n==============================")
    print("   SOC RANSOMWARE DETECTION")
    print("==============================\n")

    services = [

        threading.Thread(target=file_monitor),
        threading.Thread(target=process_monitor),
        threading.Thread(target=network_capture),
        threading.Thread(target=network_feature),
        threading.Thread(target=rule_engine),
        threading.Thread(target=ml_engine),
        threading.Thread(target=correlator),
        threading.Thread(target=dashboard)

    ]

    for s in services:
        s.start()

    for s in services:
        s.join()