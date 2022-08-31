#!/bin/env python

import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

time.sleep(5)

# Load bob public key 
with open("bob_public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Save key contents as bytes in message variable
f = open('key.key', 'rb')
message = f.read()
f.close()

# open('key.encrypted', "wb").close() # clear file
# Encrypt key
encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# write encryption to key.encrypted
f = open('key.encrypted', 'wb')
f.write(encrypted)
f.close()

# with open('key.encrypted', "ab") as f: f.write(encrypted)

print("[*] Session key encrypted with bob public key")

# file = open('key.key', 'rb') # opening for [r]eading as [b]inary
# data = file.read()
#
# open('key.encrypted', "wb").close() # clear file
# for encode in data:
#     encrypted = public_key.encrypt(
#         encode,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     
#     with open('key.encrypted', "ab") as f: f.write(encrypted)

