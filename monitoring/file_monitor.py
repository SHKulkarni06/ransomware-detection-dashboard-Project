import os
import time
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(PROJECT_ROOT, "logs", "file_system.log")

os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

FILE_ACTIVITY = []
SUSPICIOUS_EXTENSIONS = {".locked", ".enc", ".crypt", ".encrypted"}

FILE_THRESHOLD = 20   # files per minute


# --------------------------------
# Logging
# --------------------------------
def log_event(source_ip, event_type, details):

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"{timestamp} {source_ip} {event_type} {details}"

    with open(LOG_PATH, "a") as f:
        f.write(log_line + "\n")

    print(log_line)


# --------------------------------
# Detection Logic
# --------------------------------
def record_file_event(filepath):

    FILE_ACTIVITY.append((filepath, time.time()))


def detect_file_anomaly():

    alerts = []
    now = time.time()

    recent = [f for f, t in FILE_ACTIVITY if now - t < 60]

    # MASS FILE CHANGE
    if len(recent) >= FILE_THRESHOLD:
        alerts.append(f"Mass file modification detected ({len(recent)} files in 60s)")

    # SUSPICIOUS EXTENSION
    for f in recent:
        _, ext = os.path.splitext(f)
        if ext.lower() in SUSPICIOUS_EXTENSIONS:
            alerts.append(f"Possible ransomware extension detected: {f}")

    return list(set(alerts))


# --------------------------------
# File Event Handler
# --------------------------------
class FileMonitorHandler(FileSystemEventHandler):

    def on_created(self, event):

        if not event.is_directory:

            log_event("127.0.0.1", "create", event.src_path)
            record_file_event(event.src_path)

            alerts = detect_file_anomaly()

            for a in alerts:
                log_event("127.0.0.1", "ALERT", a)


    def on_modified(self, event):

        if not event.is_directory:

            log_event("127.0.0.1", "modify", event.src_path)
            record_file_event(event.src_path)

            alerts = detect_file_anomaly()

            for a in alerts:
                log_event("127.0.0.1", "ALERT", a)


    def on_deleted(self, event):

        if not event.is_directory:

            log_event("127.0.0.1", "delete", event.src_path)
            record_file_event(event.src_path)

            alerts = detect_file_anomaly()

            for a in alerts:
                log_event("127.0.0.1", "ALERT", a)


# --------------------------------
# Start Monitoring
# --------------------------------
def start_monitor(folder="test_files"):

    path = os.path.join(PROJECT_ROOT, folder)

    os.makedirs(path, exist_ok=True)

    event_handler = FileMonitorHandler()

    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)

    observer.start()

    print(f"Monitoring folder: {path}")

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        observer.stop()

    observer.join()


if __name__ == "__main__":

    start_monitor()