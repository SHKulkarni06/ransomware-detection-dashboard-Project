# test_file_activity.py
import os

os.makedirs("test_files", exist_ok=True)

for i in range(30):
    with open(f"test_files/test_{i}.txt", "w") as f:
        f.write("test")
