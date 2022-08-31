#!/bin/env python

import socket
import tqdm # for progress bar
import os
import time

import base64 # for base64 encoding
def utf8(s: bytes):
    return str(s, 'utf-8')

# send/receive 4096 bytes each time
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"
FILE = input("Enter file to encrypt: ")

###################### alice receives bob public key

# device's IP address
SERVER_HOST = "0.0.0.0" #means all ipv4 addresses that are on the local machine
SERVER_PORT = 5001

# create the server socket
# TCP socket
s = socket.socket()

# bind the socket to our local address
s.bind((SERVER_HOST, SERVER_PORT))

# enabling our server to accept connections
# 1 here is the number of accepted connections that
# the system will allow before refusing new connections
s.listen(1)
print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")

# accept connection if there is any
client_socket, address = s.accept() 
# if below code is executed, that means the sender is connected
print(f"[+] {address} is connected.")

# receive bob key file infos
# receive using client socket, not server socket
received = client_socket.recv(BUFFER_SIZE).decode()
bob_public_key_filename, bob_public_key_filesize = received.split(SEPARATOR)
# remove absolute path if there is
bob_public_key_filename = os.path.basename(bob_public_key_filename)
# convert to integer
bob_public_key_filesize, sep, tail = bob_public_key_filesize.partition('-')
bob_public_key_filesize = int(bob_public_key_filesize)

# start receiving bob key file from the socket
# and writing to the file stream
progress = tqdm.tqdm(range(bob_public_key_filesize), f"Receiving {bob_public_key_filename}", unit="B", unit_scale=True, unit_divisor=1024)
with open(bob_public_key_filename, "wb") as f:
    while True:
        # read 1024 bytes from the socket (receive)
        bytes_read = client_socket.recv(BUFFER_SIZE)
        if not bytes_read:
            # nothing is received
            # file transmitting is done
            break
        # write to bob key file the bytes we just received
        f.write(bytes_read)
        # update the progress bar
        progress.update(len(bytes_read))
f.close()

# close the client socket
client_socket.close()
# close the server socket
s.close()
print("test1")

########## alice establishes a connection with bob as the sender

# the ip address or hostname of the server, the receiver
host = "192.168.1.177"
# the port, let's use 5001
port = 5001
# the name of file we want to send, make sure it exists
#filename = input("Enter filename: ")
# get the file size
#filesize = os.path.getsize(filename)

# create the client socket
s = socket.socket()

# connect to receiver
print(f"[+] Connecting to {host}:{port} ... ")
s.connect((host, port))
print("[+] Connected.")

#### alice sends her public key to bob

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

# get alice public key filename and size
alice_public_key_filename = "alice_public_key.pem"
alice_public_key_filesize = os.path.getsize(alice_public_key_filename)

# send alice public key filename and size
s.send(f"{alice_public_key_filename}{SEPARATOR}{alice_public_key_filesize}".encode())

# start sending alice public key
progress = tqdm.tqdm(range(alice_public_key_filesize), f"Sending {alice_public_key_filename}", unit="B", unit_scale=True, unit_divisor=1024)
with open(alice_public_key_filename, "rb") as f:
    while True:
        # read the bytes from alice's key
        bytes_read = f.read(BUFFER_SIZE)
        if not bytes_read:
            # alice key's transmitting is done
            break
        # we use sendall to assure transimission in
        # busy networks
        s.sendall(bytes_read)
        # update the progress bar
        progress.update(len(bytes_read))
f.close()

# close the socket
s.close()
print("test")

############ alice generates a random session key
from cryptography.fernet import Fernet

# Generate skc key and save into file
key = Fernet.generate_key()
with open("key.key", "wb") as key_file:
    key_file.write(key)

### alice generates hash from file
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

##### alice encrypts hash w/ alice private key (signs file)

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

##### alice encrypts file w/ session key

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

##### alice encrypts session key w/ bob public key

# Load bob public key 
while True:
    if bob_public_key_filesize != os.path.getsize(bob_public_key_filename):
        time.sleep(0.5)
    else:
        break

with open("bob_public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Encrypt file
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

##### alice sends encrypted hash, file, session key to bob
 
##############
