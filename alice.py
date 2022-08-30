#!/bin/env python

import socket
import tqdm # for progress bar
import os

import base64 # for base64 encoding
def utf8(s: bytes):
    return str(s, 'utf-8')

# send/receive 4096 bytes each time
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"

####################################################################################
# reciever

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
print(bob_public_key_filesize)
print(bob_public_key_filename)
head, sep, tail = bob_public_key_filesize.partition('-')
print(bob_public_key_filesize)
bob_public_key_filesize = int(bob_public_key_filesize)
print(bob_public_key_filesize)

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

# close the client socket
client_socket.close()
# close the server socket
s.close()

##################################################################################
# sender

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
       
# close the socket
s.close()
