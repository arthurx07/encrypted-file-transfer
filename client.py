#!/bin/env python

import socket
import tqdm # for progress bar
import os

import base64 # for base64 encoding
def utf8(s: bytes):
    return str(s, 'utf-8')

SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 4096 # send 4096 bytes each time step

# the ip address or hostname of the server, the receiver
host = input("Enter server ip: ")
# the port, let's use 5001
port = 5001
# the name of file we want to send, make sure it exists
filename = input("Enter filename: ")
# get the file size
filesize = os.path.getsize(filename)

# create the client socket
s = socket.socket()

print(f"[+] Connecting to {host}:{port} ... ")
s.connect((host, port))
print("[+] Connected.")

# Generating a key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
    )
public_key = private_key.public_key()

# Storing the keys
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

bob_public_keyfile = "bob_public_key.pem"
bob_public_filesize = os.path.getsize(bob_public_filename)

# send bob public key filename and size
s.send(f"{bob_public_keyfile}{SEPARATOR}{filesize}".encode())

# start sendig bob public key
progress = tqdm.tqdm(range(bob_public_filesize), f"Sending {bob_public_keyfile}", unit="B", unit_scale=True, unit_divisor=1024)
with open(bob_public_keyfile, "rb") as f:
    while True:
        # read the bytes from the file
        bytes_read = f.read(BUFFER_SIZE)
        if not bytes_read:
            # file transmitting is done
            break
        # we use sendall to assure transimission in 
        # busy networks
        s.sendall(bytes_read)
        # update the progress bar
        progress.update(len(bytes_read))

# # send the filename and filesize
# s.send(f"{filename}{SEPARATOR}{filesize}".encode())
# #encode() function encodes the string we passed to 'utf-8' encoding (that's necessary).
#
# # start sending the file
# progress = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
# with open(filename, "rb") as f:
#     while True:
#         # read the bytes from the file
#         bytes_read = f.read(BUFFER_SIZE)
#         if not bytes_read:
#             # file transmitting is done
#             break
#         # we use sendall to assure transimission in 
#         # busy networks
#         s.sendall(bytes_read)
#         # update the progress bar
#         progress.update(len(bytes_read))
# close the socket
s.close()
