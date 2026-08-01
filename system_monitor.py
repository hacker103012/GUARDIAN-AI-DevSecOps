import os
import platform
import shutil
print(f"--- system monitor report ({platform.system()} OS) ---")
total,used,free = shutil.disk_usage("/")
total_gb = total / (1024 ** 3)
used_gb = used / (1024 ** 3)
free_gb = free / (1024 ** 3)
used_percent = (used / total) * 100
print(f"total disk space: {total_gb:.2f} GB")
print(f"used disk space: {used_gb:.2f} GB ({used_percent:.1f}%)")
print(f"free disk space: {free_gb:.2f} GB")
if used_percent > 80.0:
 print("[ALERT] WARNING: disk space usage is over 80%!")
 print("Action Required: clean up old files immediately")
else:
 print("[STATUS] healthy: you have plenty of storage space left")

