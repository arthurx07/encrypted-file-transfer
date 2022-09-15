#!/bin/env python

def genPkcKey(): 
    # Generate alice's key
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
        )
    public_key = private_key.public_key()

    logging.info(f"Public and private keys generated")

    # Store alice's keys
    from cryptography.hazmat.primitives import serialization
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
        )
    with open(f'{TMPDIR}/alice_private_key.pem', 'wb') as f:
        f.write(private_pem)

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(f'{TMPDIR}/alice_public_key.pem', 'wb') as f:
        f.write(public_pem)

    logging.info(f"Public and private keys stored as [alice_public/private_key]")

class Fernet:
    def __init__(self, Fernet):
        self.Fernet = Fernet

    def genSkcKey(self):
        # Generate skc key and save
        from cryptography.fernet import Fernet
        self.key = Fernet.generate_key()
        with open(f'{TMPDIR}/key.key', 'wb') as key_file:
            key_file.write(self.key)

        logging.info(f"Random session key generated and stored as [key.key]")

    def encryptFile(self): # Encrypte file with session key
        from cryptography.fernet import Fernet
        # Given a filename (str) and key (bites), it encrypts the file and writes it
        f = Fernet(self.key)
        with open(FILE, 'rb') as file:
            # Read all file data
            file_data = file.read()
            # Encrypt data
            encrypted_data = f.encrypt(file_data)
            # Write the encrypted file
            with open(f'{TMPDIR}/{FILE}.encrypted', 'wb') as file:
                file.write(encrypted_data)

        logging.info(f"[{FILE}.encrypted] encrypted with session key")

def genHash(): # Generate hash from file
    from hashlib import blake2b
    # Divide files in chunks, to not use a lot of ram for big files
    BUF_SIZE = 65536 # Read in 64kb chunks // BUF_SIZE is totally arbitrary

    blake2 = blake2b()

    with open(FILE, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            blake2.update(data)

    hash_data = '{0}'.format(blake2.hexdigest())

    # Write hash to file.blake2b
    with open(f'{TMPDIR}/{FILE}.blake2b', 'w') as hash_file:
        hash_file.write(hash_data)

    logging.info(f"Hash generated from [{FILE}] and written to [{FILE}.blake2b]")

class EncryptHash: # Encrypt hash w/ alice private key (signs file)
    def loadAlPrivateKey(self): # Load alice private key
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        with open(f'{TMPDIR}/alice_private_key.pem', 'rb') as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
                )

        logging.info("Loaded [alice_private_key.pem]")

    def signHash(self): # Sign hash 
        # Load contents of file.blake2b
        with open(f'{TMPDIR}/{FILE}.blake2b', 'rb') as f:
            payload = f.read()
        
        logging.info(f"Loaded [{FILE}.blake2b]")

        # Sign the payload file to file.sig
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        import base64 # For base64 encoding
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
        with open(f'{TMPDIR}/{FILE}.sig', 'wb') as f:
            f.write(signature)

        logging.info(f"[{FILE}.blake2b] file signed with private key to [{FILE}.sig]")


def loadBobPublicKey(): # Load bob public key 
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization

    global public_key
    with open(f'{TMPDIR}/bob_public_key.pem', 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    logging.info("Loaded [bob_public_key.pem]")

def encryptSkcKey(): # Encrypt key.key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    loadBobPublicKey()

    # Save key contents as bytes in message variable
    with open(f'{TMPDIR}/key.key', 'rb') as f:
        message = f.read()

    logging.info("Loaded [key.key] to be later encrypted")

    # Encrypt key
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
    with open(f'{TMPDIR}/key.encrypted', 'wb') as f:
        f.write(encrypted)

    logging.info("[key.key] encrypted with [bob_public_key] as [key.encrypted]")

def establishConnection(): # Create tftpy client
    import tftpy
    global client
    client = tftpy.TftpClient(HOST, PORT)
    logging.info(f"Started connnection with [{HOST}] on port [{PORT}]")
    return client

def connection(): # Upload files, download bob_public_key
    global client
    while os.path.exists(f'{TMPDIR}/key.encrypted') == False:
        # Download bob's public key
        # Initiates a tftp download from the configured remote host, requesting the filename passed
        client.download(f'{TMPDIR}/bob_public_key.pem', f'{TMPDIR}/bob_public_key.pem')
        if os.path.exists(f'{TMPDIR}/bob_public_key.pem') == True:
            logging.info(f"Connection succeeded with [{HOST}] on port [{PORT}]")
            logging.info("Received [bob_public_key.pem]")
            Thread(target = encryptSkcKey).start()
            break

    while os.path.exists(f'{TMPDIR}/files_received') == False:
        # Write FILE name to file_name
        with open(f'{TMPDIR}/file_name', 'w') as file:
            file.write(f'{FILE}\n')   

        # Upload alice's public key, file, hash, session key
        # Initiates a tftp upload to the configured remote host, uploading the filename passed.
        for name in (f'{TMPDIR}/file_name', f'{TMPDIR}/alice_public_key.pem', f'{TMPDIR}/{FILE}.sig', f'{TMPDIR}/{FILE}.encrypted', f'{TMPDIR}/key.encrypted'):
            client.upload(name, name)

        sleep(.1)
        # Request confirmation Bob received files
        files_rcv = f'{TMPDIR}/files_received'
        client.download(files_rcv, files_rcv)
        if os.path.exists(files_rcv) == True:
            logging.info("Uploaded [alice_public_key.pem]")
            logging.info(f"Uploaded [{FILE}.sig], [{FILE}.encrypted], [key.encrypted]")
            logging.info("Bob received files")
            break
        else:
            sleep(.5)

def connectionSuccessful():
    logging.info("Finished connection")

def mkdir():
    # Create tmpdir
    if os.path.isdir(TMPDIR) == False:
        os.mkdir(TMPDIR)

def rmfiles():
    # Remove rmdir recursively, with temporary files inside
    from shutil import rmtree
    RMFILES = input("[*] Would you like to remove temporary files? [Yes/No] ")
    if RMFILES == "Yes" or RMFILES == "y" or RMFILES == "":
        rmtree(TMPDIR)
        logging.info("Temporary files removed")
    else:
        logging.info("Temporary files not removed")
    raise SystemExit

def logger():
    # Logger
    if LOG == True:
        logging.root.handlers = []
        logging.basicConfig(format='%(asctime)s [%(threadName)-10.10s] [%(levelname)-4.4s]  %(message)s', level=logging.INFO , filename = '%slog' % __file__[:-2])

        # Set up logging to console
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)
        # Set a format which is simpler for console use
        formatter = logging.Formatter('%(asctime)s [%(levelname)-4.4s]  %(message)s')
        ch.setFormatter(formatter)
        logging.getLogger('').addHandler(ch)
    elif LOG == False:
        logging.basicConfig(level = logging.WARNING, format = '[*] %(message)s')

def progress():
    import sys
    print("Loading:")


# animation = ["10%", "20%", "30%", "40%", "50%", "60%", "70%", "80%", "90%", "100%"]
    animation = ["[■□□□□□□□□□]","[■■□□□□□□□□]", "[■■■□□□□□□□]", "[■■■■□□□□□□]", "[■■■■■□□□□□]", "[■■■■■■□□□□]", "[■■■■■■■□□□]", "[■■■■■■■■□□]", "[■■■■■■■■■□]", "[■■■■■■■■■■]"]

    for i in range(len(animation)):
        sleep(0.2)
        sys.stdout.write("\r" + animation[i % len(animation)])
        sys.stdout.flush()

    print("\n")


if __name__ == '__main__':
    # Imports
    import os
    import logging
    import argparse
    from time import sleep
    from threading import Thread

    # Define argument parser for easier utilization
    parser = argparse.ArgumentParser(description="Encrypted File Sender")
    parser.add_argument("file", help="File name to send")
    parser.add_argument("host", help="The host/IP address of the receiver")
    parser.add_argument("-p", "--port", help="Port to use, default is 5001", default=5001)
    parser.add_argument("-d", "--directory", help="Directory to store temporary files, default is tmp/", default="tmp/")
    parser.add_argument("-l", "--log", help="Enable debugging", action='store_true')
    args = parser.parse_args()

    # Define global variables
    FILE = args.file
    HOST = args.host
    PORT = args.port
    TMPDIR = args.directory
    LOG = args.log

    Thread(target = progress).start()

    logger()

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
