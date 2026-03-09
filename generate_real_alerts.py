# save as generate_real_alerts.py
import os
import time
from datetime import datetime

LOG_DIR = "E:/Desktop/CN/monitoring/logs"
FILE_LOG = os.path.join(LOG_DIR, "file_system.log")

def write_to_log(message):
    """Write directly to log file"""
    with open(FILE_LOG, 'a') as f:
        f.write(message + "\n")
    print(f"✅ Written to log: {message}")

print("="*50)
print("GENERATING REAL TEST ALERTS")
print("="*50)

# Test 1: Create .locked files (Should trigger CRITICAL alert)
print("\n1️⃣ Creating .locked file entries...")
for i in range(5):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    write_to_log(f"{timestamp} FILE CREATE C:\\Users\\test\\file{i}.locked")

time.sleep(2)

# Test 2: Create mass file modifications (Should trigger HIGH alert)
print("\n2️⃣ Creating mass file modifications...")
for i in range(100):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    write_to_log(f"{timestamp} FILE MODIFY C:\\Users\\test\\doc{i}.txt")

print("\n✅ Test complete! Now run the dashboard and watch for NEW alerts.")
print("The old alerts should be gone and only new ones will appear.")