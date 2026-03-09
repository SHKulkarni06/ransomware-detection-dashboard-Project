# save as clear_logs.py
import os

log_files = [
    "E:/Desktop/CN/monitoring/logs/file_system.log",
    "E:/Desktop/CN/monitoring/logs/process_system.log",
    "E:/Desktop/CN/monitoring/logs/system.log"
]

for log_file in log_files:
    if os.path.exists(log_file):
        # Create backup
        backup = log_file + ".backup"
        if os.path.exists(backup):
            os.remove(backup)
        os.rename(log_file, backup)
        print(f"✅ Backed up: {log_file} -> {backup}")
        
        # Create empty log file
        with open(log_file, 'w') as f:
            f.write("# New log file created\n")
        print(f"✅ Created fresh: {log_file}")

print("\n✅ Logs cleared! Now run the dashboard and create test files.")