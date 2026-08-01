import hashlib
import os
known_hash = ("--------")
with open("important_data.py", "r") as file:
 data = file.read()
 calculated_hash = hashlib.sha256(data.encode()).hexdigest()
if calculated_hash == known_hash:
 print("ok,file is safe")
else:
 print("warning!,file is  changed")



