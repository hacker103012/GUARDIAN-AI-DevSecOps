import socket
target_host = "scanme.nmap.org"
port = 22
print(f"--- grabbing banner from {target_host} on Port {port} ---")
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.settimeout(2.0)
try:
 s.connect((target_host,port))
 banner = s.recv(1024)
 print(f"[+] successfully connected!")
 print(f"[+] service banner: {banner.decode().strip()}")
except Exception as e:
 print(f"[-] could not get banner: {e}")
s.close()


