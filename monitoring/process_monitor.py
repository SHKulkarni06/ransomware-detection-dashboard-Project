import psutil
import os
import logging
import time

# -----------------------------
# Detection Thresholds
# -----------------------------
CPU_THRESHOLD = 40
PROCESS_BURST_THRESHOLD = 6
PROCESS_BURST_WINDOW = 5

# -----------------------------
# Ransomware Command Patterns
# -----------------------------
SUSPICIOUS_COMMANDS = [
    "vssadmin",
    "shadowcopy",
    "bcdedit",
    "wbadmin",
    "cipher",
    "powershell",
    "-enc",
    "encodedcommand"
]

# -----------------------------
# Suspicious Script Hosts
# -----------------------------
SCRIPT_HOSTS = [
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "python.exe"
]

# -----------------------------
# Trusted Processes
# -----------------------------
TRUSTED_PROCESSES = [
    "system",
    "system idle process",
    "explorer.exe",
    "svchost.exe",
    "chrome.exe",
    "msedge.exe",
    "zoom.exe",
    "teams.exe",
    "code.exe",
    "dwm.exe",
    "wmiprvse.exe"
]

# -----------------------------
# Suspicious Locations
# -----------------------------
TEMP_PATH = os.environ.get("TEMP", "").lower()
APPDATA_PATH = os.environ.get("APPDATA", "").lower()
DOWNLOAD_PATH = os.path.join(os.path.expanduser("~"), "downloads").lower()

# -----------------------------
# Logging Setup
# -----------------------------
LOG_FILE = "monitoring/logs/process_system.log"

os.makedirs("monitoring/logs", exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s"
)

# -----------------------------
# Runtime Tracking
# -----------------------------
seen_processes = set()
spawn_times = []
cpu_alerted = set()

# -----------------------------
# Alert Function
# -----------------------------
def alert(msg):
    logging.warning(msg)
    print(f"[ALERT] {msg}")

# -----------------------------
# Detection Engine
# -----------------------------
def detect_ransomware_behavior():

    global spawn_times
    current_time = time.time()

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid']):

        try:

            pid = proc.info['pid']
            name = proc.info['name']

            if not name:
                continue

            name = name.lower()

            # Skip trusted processes
            if name in TRUSTED_PROCESSES:
                continue

            exe = proc.info.get('exe')
            cmdline = proc.info.get('cmdline')
            cmd = " ".join(cmdline).lower() if cmdline else ""

            # --------------------------------
            # Log monitored process
            # --------------------------------
            logging.info(f"Monitoring process: {name} | PID={pid}")

            # --------------------------------
            # Detect suspicious commands
            # --------------------------------
            for keyword in SUSPICIOUS_COMMANDS:
                if keyword in cmd:
                    alert(f"Possible ransomware command detected: {name} -> {cmd}")
                    break

            # --------------------------------
            # Suspicious execution location
            # --------------------------------
            if exe:

                path = exe.lower()

                if name in SCRIPT_HOSTS:

                    if TEMP_PATH in path or APPDATA_PATH in path or DOWNLOAD_PATH in path:
                        alert(f"Script host running from suspicious location: {exe}")

            # --------------------------------
            # Process burst detection
            # --------------------------------
            if pid not in seen_processes:

                seen_processes.add(pid)
                spawn_times.append(current_time)

            spawn_times = [t for t in spawn_times if current_time - t < PROCESS_BURST_WINDOW]

            if len(spawn_times) > PROCESS_BURST_THRESHOLD:

                alert(f"Process burst detected: {len(spawn_times)} processes in {PROCESS_BURST_WINDOW}s")

                spawn_times.clear()

            # --------------------------------
            # High CPU usage detection
            # --------------------------------
            cpu = proc.cpu_percent(interval=0.1)

            if cpu > CPU_THRESHOLD and pid not in cpu_alerted:

                alert(f"High CPU usage suspicious process: {name} using {cpu:.1f}% CPU")

                cpu_alerted.add(pid)

            if cpu <= CPU_THRESHOLD and pid in cpu_alerted:

                cpu_alerted.remove(pid)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):

            continue


# -----------------------------
# Monitoring Loop
# -----------------------------
if __name__ == "__main__":

    print("Enterprise Ransomware Behavior Monitor Started")

    # preload running processes
    for proc in psutil.process_iter(['pid']):
        seen_processes.add(proc.pid)

    while True:

        detect_ransomware_behavior()

        time.sleep(0.5)