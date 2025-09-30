import hashlib

username = str(input("> "))
user_hash = hashlib.sha256(username.encode()).hexdigest
print(user_hash)
