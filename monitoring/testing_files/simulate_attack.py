import subprocess
import time
import os
import base64

print("Starting safe ransomware behavior demo...")

# ------------------------------------------------
# 1. Process Burst Simulation
# ------------------------------------------------
print("Simulating process burst...")

burst_procs = []

for i in range(6):
    p = subprocess.Popen("notepad.exe")
    burst_procs.append(p)
    time.sleep(0.5)


# ------------------------------------------------
# 2. High CPU Usage Simulation
# ------------------------------------------------
print("Simulating high CPU usage...")

cpu_proc = subprocess.Popen([
    "python",
    "-c",
    "import time; [sum([i*i for i in range(10000000)]) for _ in range(20)]; time.sleep(5)"
])


# ------------------------------------------------
# 3. Encoded PowerShell (Ransomware-like)
# ------------------------------------------------
print("Simulating encoded PowerShell...")

command = "Write-Host 'Suspicious activity simulation'"

encoded = base64.b64encode(command.encode("utf-16le")).decode()

powershell_proc = subprocess.Popen([
    "powershell",
    "-EncodedCommand",
    encoded
])


# ------------------------------------------------
# 4. Suspicious Execution Location
# ------------------------------------------------
print("Simulating execution from AppData...")

appdata = os.environ.get("APPDATA")

test_script = os.path.join(appdata, "fake_payload.py")

with open(test_script, "w") as f:
    f.write("""
import time
while True:
    x = sum([i*i for i in range(100000)])
""")

location_proc = subprocess.Popen(["python", test_script])


# ------------------------------------------------
# Wait for monitor detection
# ------------------------------------------------
print("Waiting for monitor alerts...")
time.sleep(15)


# ------------------------------------------------
# Cleanup
# ------------------------------------------------
print("Cleaning demo processes...")

for p in burst_procs + [cpu_proc, powershell_proc, location_proc]:
    try:
        p.terminate()
    except:
        pass

if os.path.exists(test_script):
    os.remove(test_script)

print("Demo finished safely.")