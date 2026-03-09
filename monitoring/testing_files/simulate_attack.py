import subprocess
import time
import os

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
    "import time; [sum([i*i for i in range(10000000)]) for _ in range(15)]; time.sleep(5)"
])

# ------------------------------------------------
# 3. Suspicious PowerShell Behavior
# ------------------------------------------------
print("Simulating suspicious PowerShell command...")

powershell_proc = subprocess.Popen([
    "powershell",
    "-Command",
    "Write-Host 'Simulating suspicious activity'"
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
    time.sleep(1)
""")

location_proc = subprocess.Popen(["python", test_script])

# ------------------------------------------------
# Wait so monitor detects everything
# ------------------------------------------------
print("Waiting for monitor alerts...")
time.sleep(12)

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