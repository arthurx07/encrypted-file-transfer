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

################ bob sends alice his session key

# the ip address or hostname of the server, the receiver
host = "192.168.1.144"
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

# Generating bob's key
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

# get bob public key filename and size
bob_public_key_filename = "bob_public_key.pem"
bob_public_key_filesize = os.path.getsize(bob_public_key_filename)

# send bob public key filename and size
s.send(f"{bob_public_key_filename}{SEPARATOR}{bob_public_key_filesize}".encode())

# start sending bob public key
progress = tqdm.tqdm(range(bob_public_key_filesize), f"Sending {bob_public_key_filename}", unit="B", unit_scale=True, unit_divisor=1024)
with open(bob_public_key_filename, "rb") as f:
    while True:
        # read the bytes from bob's public key 
        bytes_read = f.read(BUFFER_SIZE)
        if not bytes_read:
            # bob's public key file transmitting is done
            break
        # we use sendall to assure transimission in 
        # busy networks
        s.sendall(bytes_read)
        # update the progress bar
        progress.update(len(bytes_read))

time.sleep(5)

# close the socket
s.close()

###### bob establishes a connection with alice as a receiver

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

##### bob receives alice's public key

# receive alice key file infos
# receive using client socket, not server socket
received = client_socket.recv(BUFFER_SIZE).decode()
alice_public_key_filename, alice_public_key_filesize = received.split(SEPARATOR)
# remove absolute path if there is
alice_public_key_filename = os.path.basename(alice_public_key_filename)
# convert to integer
alice_public_key_filesize, sep, tail = alice_public_key_filesize.partition('-')
alice_public_key_filesize = int(alice_public_key_filesize)

# start receiving alice key file from the socket
# and writing to the file stream
progress = tqdm.tqdm(range(alice_public_key_filesize), f"Receiving {alice_public_key_filename}", unit="B", unit_scale=True, unit_divisor=1024)
with open(alice_public_key_filename, "wb") as f:
    while True:
        # read 1024 bytes from the socket (receive)
        bytes_read = client_socket.recv(BUFFER_SIZE)
        if not bytes_read:
            # nothing is received
            # alice's key file transmitting is done
            break
        # write to alice key file the bytes we just received
        f.write(bytes_read)
        # update the progress bar
        progress.update(len(bytes_read))

# close the client socket
client_socket.close()
# close the server socket
s.close()

################## bob receives alice's hash, file, session key

###### bob decrypts session key w/ bob private key
# Load bob private key
with open("bob_private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Decrypt file
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


###### bob decrypts file w/ session key
# Loads the key from the current directory named `key.key`
def load_key():
    return open("key.key", "rb").read()
key = load_key()

# Given a filename (str) and key (bytes), it decripts the file and write it
f = Fernet(key)
    with open(FILE, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    decrypted_data = f.decrypt(encrypted_data)
    # write the original file
    FILE = FILE.removesuffix('.encrypted')    # Returns original FILE name
    with open(FILE, "wb") as file:
        file.write(decrypted_data)

###### bob verificates file (decrypts hash, generates hash from file, compares)
import cryptography.exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Load the public key.
with open('alice_public_key.pem', 'rb') as f:
    public_key = load_pem_public_key(f.read(), default_backend())

# Load the payload contents and the signature.
with open(FILE, 'rb') as f:
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
except cryptography.exceptions.InvalidSignature as e:
    print('ERROR: Payload and/or signature files failed verification!')

##################
