#!/bin/env python

import tftpy
import os.path
import time

import base64 # for base64 encoding
def utf8(s: bytes):
    return str(s, 'utf-8')

FILE = input("Enter file to encrypt: ")

##################### alice generates public key

# Generating alice key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
    )
public_key = private_key.public_key()

# Storing alice's keys
from cryptography.hazmat.primitives import serialization
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
    )
with open('alice_private_key.pem', 'wb') as f:
    f.write(private_pem)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
with open('alice_public_key.pem', 'wb') as f:
    f.write(public_pem)

print("[*] Private and public keys generated and stored.")

####################### alice generates a random session key
from cryptography.fernet import Fernet

# Generate skc key and save into file
key = Fernet.generate_key()
with open("key.key", "wb") as key_file:
    key_file.write(key)

print("[*] Random session key generated and stored")

#3#################### alice generates hash from file
from hashlib import blake2b

# divide files in chunks, to not use a lot of ram for big files
# BUF_SIZE is totally arbitrary, change for your app!
BUF_SIZE = 65536 # lets read stuff in 64kb chunks!

blake2 = blake2b()

with open(FILE, 'rb') as f:
    while True:
        data = f.read(BUF_SIZE)
        if not data:
            break
        blake2.update(data)

HASH = "{0}".format(blake2.hexdigest())

# write hash to file
hash_file = open(FILE + ".blake2b", "w")
n = hash_file.write(HASH)
hash_file.close()

print("[*] Hash generated from file")

########################## alice encrypts hash w/ alice private key (signs file)

# Load alice private key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
with open("alice_private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Load the contents of the file to be signed.
with open(FILE + '.blake2b', 'rb') as f:
    payload = f.read()

# Sign the payload file.
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

signature = base64.b64encode(
    private_key.sign(
        payload,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
)
with open(FILE + '.sig', 'wb') as f:
    f.write(signature)

print("[*] Hash encrypted with private key (file signed)")

########################## alice encrypts file w/ session key

# Given a filename (str) and key (bites), it encrypts the file and write it
f = Fernet(key)
with open(FILE, "rb") as file:
    # read all file data
    file_data = file.read()
# encrypt data
encrypted_data = f.encrypt(file_data)
# write the encrypted file
with open(FILE + ".encrypted", "wb") as file:
    file.write(encrypted_data)

print("[*] File encrypted with session key")

####################### alice establishes a connection with bob

# device's IP address
SERVER_HOST = "0.0.0.0" #means all ipv4 addresses that are on the local machine
SERVER_PORT = 5001

print("[*] Creating tftp server")
# create the server tftpy
server = tftpy.TftpServer('.')

print("Listening")
server.listen(SERVER_HOST, SERVER_PORT,.4)

# here alice sends alice public key, encrypted hash and file

print("Stop listening")
# ?????

########################## alice encrypts session key w/ bob public key

# Load bob public key 
with open("bob_public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Encrypt key
data = key
open('key.encrypted', "wb").close() # clear file
for encode in data:
    encrypted = public_key.encrypt(
        encode,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    with open('key.encrypted', "ab") as f: f.write(encrypted)

print("[*] Session key encrypted with bob public key")

######################### alice sends encrypted session key to bob
print("Start listening again")
server.listen(SERVER_HOST, SERVER_PORT)

print("Stop listening")
# ???

print("Close server")
server.stop()
