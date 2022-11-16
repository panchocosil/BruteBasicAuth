#Brute force HTTP authentication#

HTTP Basic Authentication is a known weak authentication system and isn’t often used in web apps anymore. However it is used quite frequently in locale network devices like routers and webcams. To complicate matters, these devices don’t have any lockout mechanisms in place to prevent password guessing attacks like dictionary or brute-force attacks.

```Usage: python3 brutebasic.py -url-file URL_FILE -users-file USERS_FILE -pass-file PASS_FILE -timeout TIMEOUT -threads THREADS -out OUTPUT --sslinsecure```


Important note: Only use this tool in your own network or where you are authorized to carry out tests of this type.
