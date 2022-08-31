#!/bin/env python

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Load bob public key 
with open("bob_public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

print("[*] Loaded {bob_public_key.pem}")

# Save key contents as bytes in message variable
f = open('key.key', 'rb')
message = f.read()
f.close()

print("[*] Loaded {key.key} to be later encrypted")

# Encrypt key
open('key.encrypted', "wb").close() # clear file
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

print("[*] {key.key} encrypted with {bob_public_key} as {key.encrypted}")
