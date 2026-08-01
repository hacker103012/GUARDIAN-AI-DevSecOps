import socket
target_host = "127.0.0.1"
ports_to_scan = [21,22,80,443]
print(f"Scanning target:{target_host}...")
for port in ports_to_scan:
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(1.0)
    result = s.connect_ex((target_host,port))
    if result == 0:
        print(f"[*] Port {port} is OPEN")
    else:
        print(f"[] Port {port} is closed")
    s.close()    