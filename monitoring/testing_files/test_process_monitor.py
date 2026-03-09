import subprocess
import time

print("Starting safe burst test...")

for i in range(10):
    subprocess.Popen("notepad.exe")  # process stays alive
    time.sleep(0.6)  # slightly slower than monitoring loop (0.5s)