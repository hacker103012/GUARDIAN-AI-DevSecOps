import random
secret_number = random.randint(1,20)
guessed_correctly = False
while guessed_correctly == False:
 guess = int(input("guess the number"))
 if guess < secret_number:
  print("Too low! Try again")
 elif guess > secret_number:
  print("Too high! Try again")
 else:
  print("You Won! You guessed the secret number!")
  guessed_correctly = True


