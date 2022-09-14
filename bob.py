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

    logging.info("Public and private keys generated")

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

    logging.info("Public and private keys stored as {bob_public/private_key}")

class Server:
    def establishConnection(self): # bob establishes a connection with alice
        # device's IP address
        SERVER_HOST = "0.0.0.0" # means all ipv4 addresses that are on the local machine
        # SERVER_PORT defined before

        import socket
        LOCAL_IP = (([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0]
        # code from https://stackoverflow.com/a/1267524

        # from requests import get
        # PUBLIC_IP = get('https://api.ipify.org').content.decode('utf8')        

        # create the tftpy server
        self.server = tftpy.TftpServer('.')
        logging.warning("Tftp server created with host {} on port {}".format(LOCAL_IP, SERVER_PORT))

        logging.info("Listening, waiting for other devices to connect and send files")
        Thread(target = s.connection).start()
        self.server.listen(SERVER_HOST, SERVER_PORT) # todo: stop server after sending all files

    def connection(self):
        global FILE
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
                logging.info("Connection successful. {{{}}} received, starting decryption.".format(FILE))
                break

    def connectionSuccessful(self):
        while True: 
            if file_exists(FILE) == True:
                file = open(TMPDIR + "file_decrypted", "w")
                file.write("this file will be deleted")
                file.close()
                break
            logging.info("{{{}}} received successfully".format(FILE))
        logging.info("Finished connection")
        self.server.stop()

def loadBobPrivateKey(): # Loads bob private key
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    # Load bob private key

    global private_key
    with open(TMPDIR + "bob_private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    logging.info("Loaded {bob_private_key.pem}")

def decryptSkcKey(): # Decrypt session key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    global private_key
    # if doesn't work add time.sleep(1) to wait receiving all file contents or use if len(encrypted) == "256":
    while True: # else file has not been completely sent //error: Ciphertext length must be equal to key size //
        with open(TMPDIR + 'key.encrypted', "rb") as f:
            encrypted = f.read()
        if len(encrypted) == "256":
            print("ok")
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        break
    with open(TMPDIR + 'key.key', "wb") as f: f.write(decrypted)

    logging.info("Decrypted {key.encrypted} and written into {key.key}")

def loadSkcKey(): # Loads the key from the current directory named `key.key`
    global key
    key = open(TMPDIR + "key.key", "rb").read()

    logging.info("Loaded {key.key}")

def decryptFile(): # bob decrypts file w/ session key
    # Given a filename (str) and key (bytes), it decripts the file and write it
    from cryptography.fernet import Fernet

    global key
    global FILE

    f = Fernet(key)
    with open(TMPDIR + FILE + ".encrypted", "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()

    logging.info("Loaded {{{}.encrypted}}".format(FILE))

    # decrypt data
    decrypted_data = f.decrypt(encrypted_data)
    # write the original file
    FILE = FILE.removesuffix('.encrypted')    # Returns original FILE name
    with open(FILE, "wb") as file:
        file.write(decrypted_data)

    logging.info("{{{}}} decrypted and stored".format(FILE))

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

    logging.info("Hash generated from {{{}}} and written to {{{}.blake2b}}".format(FILE, FILE))

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

        logging.info("Loaded {alice_public_key.pem}")

    def loadHashSig(self):
        # Load the payload contents and the signature.
        with open(TMPDIR + FILE + ".blake2b", 'rb') as f:
            self.payload_contents = f.read()
        with open(TMPDIR + FILE + ".sig", 'rb') as f:
            self.signature = base64.b64decode(f.read())

        loggin.info("Loaded {{{}.blake2b}} and {{{}.sig}}".format(FILE, FILE))

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
            logging.info("{{{}}} verification succeeded".format(FILE))
        except cryptography.exceptions.InvalidSignature as e:
            logging.error('Payload and/or signature files failed verification!')

def mkdir():
    if os.path.isdir(TMPDIR) == False:
        os.mkdir(TMPDIR)

def rmfiles():
    from shutil import rmtree
    RMFILES = input("[*] Would you like to remove temporary files? [Yes/No] ")
    if RMFILES == "Yes" or RMFILES == "y" or RMFILES == "":
        rmtree(TMPDIR)
        logging.info("Temporary files removed")
    else:
        logging.info("Temporary files not removed")
    raise SystemExit


if __name__ == '__main__':
    import os
    import sys
    import time
    import tftpy
    import logging
    import argparse
    from threading import Thread
    from os.path import exists as file_exists

    parser = argparse.ArgumentParser(description="Encrypted File Receiver")
    parser.add_argument("-p", "--port", help="Port to use, default is 5001", default=5001)
    parser.add_argument("-d", "--dir", help="Directory to store temporary files, default is tmp/", default="tmp/")
    parser.add_argument("-l", "--log", help="Enable debugging", action='store_true')
    args = parser.parse_args()

    TMPDIR = args.dir
    SERVER_PORT = args.port
    LOG = args.log


    # Logger
    if LOG == True:
        logging.root.handlers = []
        logging.basicConfig(format='%(asctime)s [%(threadName)-10.10s] [%(levelname)-4.4s]  %(message)s', level=logging.INFO , filename = '%slog' % __file__[:-2])

        # set up logging to console
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)
        # set a format which is simpler for console use
        formatter = logging.Formatter('%(asctime)s [%(levelname)-4.4s]  %(message)s')
        ch.setFormatter(formatter)
        logging.getLogger('').addHandler(ch)
    elif LOG == False:
        logging.basicConfig(level = logging.WARNING, format = '[*] %(message)s')


    mkdir()
    genPkcKey()
    loadBobPrivateKey()
    s = Server()
    Thread(target = s.establishConnection).start()
    while True: 
        if file_exists(TMPDIR + "key.encrypted") == True:
            time.sleep(.1)
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
