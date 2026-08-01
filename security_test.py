import socket
import sys
target_host = "scanme.nmap.org"
ports_to_scan = [22,80,443]
print(f"--- starting security scan on {target_host} ---")
for port in ports_to_scan:
 s= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
 s.settimeout(1.0)
 result = s.connect_ex((target_host,port))
 if result == 0:
  print(f"[+] Port {port}: OPEN")
 else:
  print(f"[-] Port {port}: Closed/Filtered")
 s.close()
print("--- Scan Complete ---")


