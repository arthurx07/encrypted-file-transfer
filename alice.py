#!/bin/env python

def genPkcKey(): 
    # Generating alice's key
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
        )
    public_key = private_key.public_key()

    logging.info("Public and private keys generated")

    # Storing alice's keys
    from cryptography.hazmat.primitives import serialization
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
        )
    with open(TMPDIR + '/alice_private_key.pem', 'wb') as f:
        f.write(private_pem)

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(TMPDIR + 'alice_public_key.pem', 'wb') as f:
        f.write(public_pem)

    logging.info("Public and private keys stored as {alice_public/private_key}")

class Fernet: # Alice generates a random session key
    def __init__(self, Fernet):
        self.Fernet = Fernet

    def genSkcKey(self):
        # Generate skc key and save into file
        from cryptography.fernet import Fernet
        self.key = Fernet.generate_key()
        with open(TMPDIR + "key.key", "wb") as key_file:
            key_file.write(self.key)

        logging.info("Random session key generated and stored as {key.key}")

    def encryptFile(self): # Alice encrypts file with session key
        from cryptography.fernet import Fernet
        # Given a filename (str) and key (bites), it encrypts the file and write it
        f = Fernet(self.key)
        with open(FILE, "rb") as file:
            # Read all file data
            file_data = file.read()
        # Encrypt data
        encrypted_data = f.encrypt(file_data)
        # Write the encrypted file
        with open(TMPDIR + FILE + ".encrypted", "wb") as file:
            file.write(encrypted_data)

        logging.info("{{{}.encrypted}} encrypted with session key".format(FILE))

def genHash(): # Alice generates hash from file
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

    # Write hash to file.blake2b
    hash_file = open(TMPDIR + FILE + ".blake2b", "w")
    n = hash_file.write(HASH)
    hash_file.close()

    logging.info("Hash generated from {{{}}} and written to {{{}.blake2b}}".format(FILE, FILE))

class EncryptHash: # alice encrypts hash w/ alice private key (signs file)
    def loadAlPrivateKey(self): # Load alice private key
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        with open(TMPDIR + "alice_private_key.pem", "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
                )

        logging.info("Loaded {alice_private_key.pem}")

    def signHash(self): # Sign hash 
        # Load the contents of the file to be signed.
        with open(TMPDIR + FILE + '.blake2b', 'rb') as f:
            payload = f.read()

        logging.info("Loaded {{{}.blake2b}}".format(FILE))

        # Sign the payload file.
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        signature = base64.b64encode(
            self.private_key.sign(
                payload,
                padding.PSS(
                    mgf = padding.MGF1(hashes.SHA256()),
                    salt_length = padding.PSS.MAX_LENGTH,
                    ),
                hashes.SHA256(),
                )
            )
        with open(TMPDIR + FILE + '.sig', 'wb') as f:
            f.write(signature)

        logging.info("{{{}.blake2b}} file signed with private key to {{{}.sig}}".format(FILE, FILE))


def loadBobPublicKey(): # Load bob public key 
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization

    with open(TMPDIR + "bob_public_key.pem", "rb") as key_file:
        global public_key
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    logging.info("Loaded {bob_public_key.pem}")

def encryptSkcKey(): # encrypt key.key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    loadBobPublicKey()
    # Save key contents as bytes in message variable
    f = open(TMPDIR + 'key.key', 'rb')
    message = f.read()
    f.close()

    logging.info("Loaded {key.key} to be later encrypted")

    # Encrypt key
    open(TMPDIR + 'key.encrypted', "wb").close() # clear file
    global public_key
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )

    # Write encryption to key.encrypted
    f = open(TMPDIR + 'key.encrypted', 'wb')
    f.write(encrypted)
    f.close()

    logging.info("{key.key} encrypted with {bob_public_key} as {key.encrypted}")

def establishConnection(): # create tftpy client
    global client
    client = tftpy.TftpClient(HOST, PORT)
    logging.info("Connection succeeded with {} on port {}".format(HOST, PORT))
    return client

def connection(): # upload files, download bob_public_key
    global client
    while file_exists(TMPDIR + "key.encrypted") == False:
        # download bob's public key
        # initiates a tftp download from the configured remote host, requesting the filename passed
        client.download(TMPDIR + "bob_public_key.pem", TMPDIR + "bob_public_key.pem")
        if file_exists(TMPDIR + "bob_public_key.pem") == True:
            logging.info("Received {bob_public_key.pem}")
            Thread(target = encryptSkcKey).start()
            break

    while file_exists(TMPDIR + "files_received") == False:
        # open file_name
        file = open(TMPDIR + "file_name" , "w")
        # write FILE name to file_name
        file.write(FILE + "\n")   
        #close file_name
        file.close()

        # upload alice's public key, file, hash, session key
        # initiates a tftp upload to the configured remote host, uploading the filename passed.
        for name in (TMPDIR + "file_name", TMPDIR + "alice_public_key.pem", TMPDIR + FILE + ".sig", TMPDIR + FILE + ".encrypted", TMPDIR + "key.encrypted"):
            client.upload(name, name)

        time.sleep(.1)
        client.download(TMPDIR + "files_received", TMPDIR + "files_received")
        if file_exists(TMPDIR + "files_received") == True:
            logging.info("Uploaded {alice_public_key.pem}")
            logging.info("Uploaded {{{}.sig}}, {{{}.encrypted}}, {{key.encrypted}}".format(FILE, FILE))
            logging.info("Bob received files")
            break
        else:
            time.sleep(.5)

def connectionSuccessful():
    logging.info("Finished connection")

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
        logging.warning("[*] Temporary files not removed")
    raise SystemExit

if __name__ == '__main__':
    import os
    import time
    import tftpy
    import logging
    import argparse
    from threading import Thread
    from os.path import exists as file_exists

    parser = argparse.ArgumentParser(description="Encrypted File Sender")
    parser.add_argument("file", help="File name to send")
    parser.add_argument("host", help="The host/IP address of the receiver")
    parser.add_argument("-p", "--port", help="Port to use, default is 5001", default=5001)
    parser.add_argument("-d", "--directory", help="Directory to store temporary files, default is tmp/", default="tmp/")
    parser.add_argument("-l", "--log", help="Enable debugging", action='store_true')
    args = parser.parse_args()

    FILE = args.file
    HOST = args.host
    PORT = args.port
    TMPDIR = args.directory
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
    f = Fernet(Fernet)
    f.genSkcKey()
    genHash()
    f.encryptFile()
    e = EncryptHash()
    e.loadAlPrivateKey()
    e.signHash()
    establishConnection()
    connection()
    connectionSuccessful()
    rmfiles()
