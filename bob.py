#!/bin/env python

def genPkcKey(): # Generating bob's key
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
        )
    public_key = private_key.public_key()

    print("[*] Public and private keys generated")

    # Storing bob's keys
    from cryptography.hazmat.primitives import serialization
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
        )
    with open(TMPDIR + 'bob_private_key.pem', 'wb') as f:
        f.write(private_pem)

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(TMPDIR + 'bob_public_key.pem', 'wb') as f:
        f.write(public_pem)

    print("[*] Public and private keys stored as {bob_p*_key}")

class Server:
    global FILE
    def establishConnection(self): # bob establishes a connection with alice
        # device's IP address
        SERVER_HOST = "0.0.0.0" #means all ipv4 addresses that are on the local machine
        SERVER_PORT = 5001

        # create the server tftpy
        self.server = tftpy.TftpServer('.')
        print("[*] Tftp server created with host {} on port {}".format(SERVER_HOST, SERVER_PORT))

        print("[*] Listening, waiting for other devices to connect and send files")
        Thread(target = s.connection).start()
        self.server.listen(SERVER_HOST, SERVER_PORT) # todo: stop server after sending all files

    def connection(self):
        while True:
            if file_exists(TMPDIR + "file_name") == True:
                time.sleep(.1)
                with open(TMPDIR + 'file_name', 'r') as file:
                    FILE = file.read().rstrip()
                break
        while True:
            if file_exists(TMPDIR + "alice_public_key.pem") == True and file_exists(TMPDIR + FILE + ".sig") == True and file_exists(TMPDIR + FILE + ".encrypted") == True and file_exists(TMPDIR + "key.encrypted") == True:
                file = open(TMPDIR + "files_received", "w")
                file.write("this file will be deleted")
                file.close()
                print("[*] Connection successful. {{{}}} received, starting decryption.".format(FILE))
                break
        return FILE

    def connectionSuccessful(self):
        print(FILE)
        while True: 
            if file_exists(FILE) == True:
                file = open(TMPDIR + "file_decrypted", "w")
                file.write("this file will be deleted")
                file.close()
        print("[*] Finished connection")
        self.server.stop()

def loadBobPrivateKey(): # Loads bob private key
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    # Load bob private key

    with open(TMPDIR + "bob_private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    return private_key
    print("[*] Loaded {bob_private_key.pem}")

def decryptSkcKey(): # Decrypt session key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    private_key = loadBobPrivateKey()
    with open(TMPDIR + 'key.encrypted', "rb") as f:
        for encrypted in f:
            decrypted = private_key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
    with open(TMPDIR + 'key.key', "wb") as f: f.write(decrypted)

    print("[*] Decrypted {key.encrypted} and written into {key.key}")

def loadSkcKey():# Loads the key from the current directory named `key.key`
    global key
    key = open(TMPDIR + "key.key", "rb").read()

    print("[*] Loaded {key.key}")

def decryptFile(): # bob decrypts file w/ session key
    # Given a filename (str) and key (bytes), it decripts the file and write it
    from cryptography.fernet import Fernet

    global key
    global FILE
    f = Fernet(key)
    with open(TMPDIR + FILE + ".encrypted", "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()

    print("[*] Loaded {{{}.encrypted}}".format(FILE))

    # decrypt data
    decrypted_data = f.decrypt(encrypted_data)
    # write the original file
    FILE = FILE.removesuffix('.encrypted')    # Returns original FILE name
    with open(FILE, "wb") as file:
        file.write(decrypted_data)

    print("[*] {} decrypted and stored".format(FILE))

def genHash(): # bob generates blake2b hash from file
    global FILE
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
    hash_file = open(TMPDIR + FILE + ".blake2b", "w")
    n = hash_file.write(HASH)
    hash_file.close()

    print("[*] Hash generated from ({}) and writtento {}.blake2b".format(FILE, FILE))

class Verify: # bob verifies file (decrypts hash, generates hash from file, compares)
    global FILE
    def __init__(self):
        self.public_key = None
        self.payload_contents = None
        self.signature = None

    def loadAlPublicKey(self):
        import cryptography.exceptions
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.backends import default_backend

        # Load the public key.
        with open(TMPDIR + 'alice_public_key.pem', 'rb') as f:
            self.public_key = load_pem_public_key(f.read(), default_backend())

        print("[*] Loaded {alice_public_key.pem}")

    def loadHashSig(self):
        # Load the payload contents and the signature.
        with open(TMPDIR + FILE + ".blake2b", 'rb') as f:
            self.payload_contents = f.read()
        with open(TMPDIR + FILE + ".sig", 'rb') as f:
            self.signature = base64.b64decode(f.read())

        print("[*] Loaded {{{}.blake2b}} and {{{}.sig}}".format(FILE, FILE))

    def verification(self):
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        # Perform the verification.
        try:
            self.public_key.verify(
                self.signature,
                self.payload_contents,
                padding.PSS(
                    mgf = padding.MGF1(hashes.SHA256()),
                    salt_length = padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            print("[*] {{{}}} verification succeeded".format(FILE))
        except cryptography.exceptions.InvalidSignature as e:
            print('[X] ERROR: Payload and/or signature files failed verification!')

def mkdir():
    if os.path.isdir(TMPDIR) == False:
        os.mkdir(TMPDIR)
        # print("tmp/ directory created")
    # else:
        # print("tmp/ directory already exists")

def rmfiles():
    RMFILES = input("Would you like to remove temporary files? [Yes/No] ")
    if RMFILES == "Yes" or RMFILES == "y":
        os.rmdir(TMPDIR)
        print("Temporary files removed")
    else:
        print("Temporary files not removed")
    raise SystemExit


if __name__ == '__main__':
    import tftpy
    import time
    import base64 # for base64 encoding 
    from threading import Thread
    from os.path import exists as file_exists
    import os

    TMPDIR = "tmp/"

    mkdir()
    genPkcKey()
    loadBobPrivateKey()
    s = Server()
    Thread(target = s.establishConnection).start()
    while True: 
        if file_exists("key.encrypted") == True:
            decryptSkcKey()
            loadSkcKey()
            decryptFile()
            genHash()
            v = Verify()
            v.loadAlPublicKey()
            v.loadHashSig()
            v.verification()
            s.connectionSuccessful()
            rmfiles()
        else:
            pass


