#!/bin/env python

from sys import argv
from hashlib import blake2b

file = argv[1]

# divide files in chunks, to not use a lot of ram for big files
# BUF_SIZE is totally arbitrary, change for your app!
BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

blake2 = blake2b()

#usage: ./hash_blake2.py file ///change sys.argv[1] if wanted
with open(file, 'rb') as f:
    while True:
        data = f.read(BUF_SIZE)
        if not data:
            break
        blake2.update(data)

print("BLAKE2: {0}".format(blake2.hexdigest()))
