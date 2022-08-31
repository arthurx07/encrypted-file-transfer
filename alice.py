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

print("[*] Public and private keys generated")

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

print("[*] Public and private keys stored as {alice_p*_key}")

####################### alice generates a random session key
from cryptography.fernet import Fernet

# Generate skc key and save into file
key = Fernet.generate_key()
with open("key.key", "wb") as key_file:
    key_file.write(key)

print("[*] Random session key generated and stored as {key.key}")

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

print("[*] Hash generated from ({}) and written to {}.blake2b".format(FILE, FILE))

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

print("[*] Loaded {alice_private_key.pem}")

# Load the contents of the file to be signed.
with open(FILE + '.blake2b', 'rb') as f:
    payload = f.read()

print("[*] Loaded {{{}.blake2b}}".format(FILE))

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

print("[*] {{{}.blake2b}} file signed with private key to {{{}.sig}}".format(FILE, FILE))

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

print("[*] {}.encrypted encrypted with session key".format(FILE))

####################### alice establishes a connection with bob

# device's IP address
SERVER_HOST = "0.0.0.0" #means all ipv4 addresses that are on the local machine
SERVER_PORT = 5001

# create the server tftpy
server = tftpy.TftpServer('.')
print("[*] Tftp server created with host {} on port {}".format(SERVER_HOST, SERVER_PORT))

print("[*] Listening, waiting for other devices to connect and send files")
print("[*] Received {bob_public_key.pem}")
print("[*] Uploaded {alice_public_key.pem}")
# script which waits 5 sec and encrypts session key w/ bob public key
# os.system("python alice-encrypt-session-key.py")
print("[*] {{{}.sig}}, {{{}.encrypted}}, {{key.encrypted}} sent to bob".format(FILE, FILE))
server.listen(SERVER_HOST, SERVER_PORT,.4)

# here alice receives request to send alice public key, encrypted hash, file and session key

# print("Stop listening")
# # ?????

server.stop()
print("[*] Finished connection")
