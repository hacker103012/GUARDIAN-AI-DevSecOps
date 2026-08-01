import urllib.request
web_address = "https://www.google.com"
try:
 response = urllib.request.urlopen(web_address)
 status_code = response.getcode()
 if status_code == 200:
  print("ONLINE,Website is up!")
except:
 print("DOWN,Website might be crashing!")


