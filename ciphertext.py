def caesar_cipher(text,shift,mode='encrypt'):
    result = ""
    if mode == 'decrypt':
         shift = -shift
    for char in text:
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char)+ shift -97) % 26 + 97)
        else:
            result += char
    return result
secret_message = "cybersecurity is fun!"
key = 4
encrypted = caesar_cipher(secret_message,key,mode='encrypt')
print(f"Encrypted: {encrypted}")
decrypted = caesar_cipher(encrypted,key,mode='decrypt')
print(f"Decrypted:{decrypted}")
