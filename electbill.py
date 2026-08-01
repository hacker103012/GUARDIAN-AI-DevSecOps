units = float(input("enter the total electricity units consumed:"))
if units < 0:
 print("error:units consumed cannot be negative")
else:
 bill = 0.0
 if units <= 100:
   bill = units*2
 elif units <= 200:
   bill = (100*2)+((units - 100) * 3)
 else:
   bill = (100*2)+(100*3)+((units - 200)*5)
 print(f"total electricity bill: Rs. {bill:.2f}")
print("error: please enter a valid numerical value for units")

