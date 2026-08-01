import hashlib
print("---[ cybersecurity crypto testing] ---")
user_host = input("enter a password to hash:")
sha256_hash = hashlib.sha256(user_host.encode())
hex_fingerprint = sha256_hash.hexdigest()
print("\n--- hash output generated ---")
print(f"original text:{user_host}")
print(f"sha-256 hash : {hex_fingerprint}")

