user_mode = input("encrypt" or "decrypt")
user_secret = input("enter secret message string")
secret_number = int(input("enter secret key number"))
processed_message = ("------------------------")
for letter in user_secret:
 if letter.isalpha():
  letter_code = ord(letter)
  if user_mode == "encrypt":
   new_code = letter_code + key
  elif user_mode == "decrypt":
   new_code = letter_code - key
  processed_message += chr(new_code)
 else:
  processed_message += letter
print(f"\nyour {mode}ed message is: {processed_message}")




