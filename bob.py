#!/bin/env python

import tftpy
import time

import base64 # for base64 encoding
def utf8(s: bytes):
    return str(s, 'utf-8')

################### Generating bob's key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
    )
public_key = private_key.public_key()

# Storing bob's keys
from cryptography.hazmat.primitives import serialization
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
    )
with open('bob_private_key.pem', 'wb') as f:
    f.write(private_pem)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
with open('bob_public_key.pem', 'wb') as f:
    f.write(public_pem)

print("[*] Private and public keys generated and stored.")


################ bob establishes a connection with alice

# the ip address or hostname of the server, the receiver
HOST = "192.168.1.144"
# the port, let's use 5001
PORT = 5001

################### bob sends his public key to alice

client = tftpy.TftpClient(HOST, PORT)

print("[*] Connected to alice")

# initiates a tftp upload to the configured remote host, uploading the filename passed. 
client.upload("bob_public_key.pem", "bob_public_key.pem")

print("[*] Uploaded public key to alice")

################### bob receives alice's public key

# initiates a tftp download from the configured remote host, requesting the filename passed
client.download("alice_public_key.pem", "alice_public_key.pem")

print("[*] Downloaded alice's public key")


################## bob receives alice's hash, file, session key
FILE = "ip-ampolla.txt"

for name in (FILE + ".sig", FILE + ".encrypted"):
    client.download(name, name)

print("[*] Downloaded encrypted file, hash")

time.sleep(20)

client.download("key.encrypted", "key.encrypted")

print("[*] Downloaded encrypted session key")

################## bob decrypts session key w/ bob private key
# Load bob private key

with open("bob_private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

print("[*] Loaded bob private key")

# Decrypt file
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
with open("key.encrypted", "rb") as f:
    for encrypted in f:
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open('key.key', "ab") as f: f.write(decrypted)

print("[*] Decrypted private key and written into file key.key")

###### bob decrypts file w/ session key
# Loads the key from the current directory named `key.key`
def load_key():
    return open("key.key", "rb").read()
key = load_key()

print("[*] Loaded session key from file key.key")

# Given a filename (str) and key (bytes), it decripts the file and write it
from cryptography.fernet import Fernet

f = Fernet(key)
with open(FILE + ".encrypted", "rb") as file:
    # read the encrypted data
    encrypted_data = file.read()
# decrypt data
decrypted_data = f.decrypt(encrypted_data)
# write the original file
FILE = FILE.removesuffix('.encrypted')    # Returns original FILE name
with open(FILE, "wb") as file:
    file.write(decrypted_data)

print("[*] File decrypted with session key")

##### bob generates blake2b hash from file
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


###### bob verificates file (decrypts hash, generates hash from file, compares)
import cryptography.exceptions
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Load the public key.
with open('alice_public_key.pem', 'rb') as f:
    public_key = load_pem_public_key(f.read(), default_backend())

print("[*] Loaded alice public key")

# Load the payload contents and the signature.
with open(FILE + ".blake2b", 'rb') as f:
    payload_contents = f.read()
with open(FILE + ".sig", 'rb') as f:
    signature = base64.b64decode(f.read())

# Perform the verification.
try:
    public_key.verify(
        signature,
        payload_contents,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    print("[*] File verification succeeded")
except cryptography.exceptions.InvalidSignature as e:
    print('ERROR: Payload and/or signature files failed verification!')

