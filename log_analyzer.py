print("--- starting security log analysis ---")
with open("server.log","r") as file:
 lines = file.readlines()
fail_count = 0
for line in lines:
 if "fail" in line:
  fail_count += 1
  print(f"[ALERT] failed  login detected: {line.strip()}")
print("-------------------------------------------------")
print(f"scan complete. total failed login attempts found: {fail_count}")
if fail_count >= 3:
 print("[CRITICAL] warning: possible brute-force attack detected!")

