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

    print("[*] Public and private keys generated")

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

    print("[*] Public and private keys stored as {alice_p*_key}")

####################### alice generates a random session key
class Fernet:
    def __init__(self, Fernet):
        self.Fernet = Fernet
    def genSkcKey(self):
        from cryptography.fernet import Fernet
        # Generate skc key and save into file
        self.key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(self.key)

        print("[*] Random session key generated and stored as {key.key}")

    ########################## alice encrypts file w/ session key
    def encryptFile(self):
        from cryptography.fernet import Fernet
        # Given a filename (str) and key (bites), it encrypts the file and write it
        f = Fernet(self.key)
        with open(FILE, "rb") as file:
            # read all file data
            file_data = file.read()
        # encrypt data
        encrypted_data = f.encrypt(file_data)
        # write the encrypted file
        with open(FILE + ".encrypted", "wb") as file:
            file.write(encrypted_data)

        print("[*] {}.encrypted encrypted with session key".format(FILE))

def genHash():
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

    print("[*] Hash generated from ({}) and written to {}.blake2b".format(FILE, FILE))

class EncryptHash: # alice encrypts hash w/ alice private key (signs file)
    def loadAlPrivateKey(self):
        # Load alice private key
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        with open("alice_private_key.pem", "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
                )

        print("[*] Loaded {alice_private_key.pem}")

    def signHash(self):
        # Load the contents of the file to be signed.
        with open(FILE + '.blake2b', 'rb') as f:
            payload = f.read()

        print("[*] Loaded {{{}.blake2b}}".format(FILE))

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
        with open(FILE + '.sig', 'wb') as f:
            f.write(signature)

        print("[*] {{{}.blake2b}} file signed with private key to {{{}.sig}}".format(FILE, FILE))


def loadBobPublicKey():
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    # Load bob public key 
    with open("bob_public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    print("[*] Loaded {bob_public_key.pem}")

def encryptSkcKey():
    loadBobPublicKey()
    # Save key contents as bytes in message variable
    f = open('key.key', 'rb')
    message = f.read()
    f.close()

    print("[*] Loaded {key.key} to be later encrypted")

    # Encrypt key
    open('key.encrypted', "wb").close() # clear file
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )

    # Write encryption to key.encrypted
    f = open('key.encrypted', 'wb')
    f.write(encrypted)
    f.close()

    print("[*] {key.key} encrypted with {bob_public_key} as {key.encrypted}")
def establishConnection():
    global client
    client = tftpy.TftpClient(HOST, PORT)
    print("[*] Connection succeeded with {} on port {}".format(HOST, PORT))
    return client

def connection():
    from threading import Thread
    global client
    while file_exists("bob_public_key.pem") == False:
        # download bob's public key
        # initiates a tftp download from the configured remote host, requesting the filename passed
        client.download("bob_public_key.pem", "bob_public_key.pem")
        if file_exists("bob_public_key.pem") == True:
            print("[*] Received {bob_public_key.pem}")
            Thread(target = encryptSkcKey).start()
            break

    while file_exists("files_received") == False:
        #open file_name
        file = open("file_name" , "w")
        # write FILE name to file_name
        file.write(FILE + "\n")   
        #close file_name
        file.close()

        # upload alice's public key, file, hash, session key
        # initiates a tftp upload to the configured remote host, uploading the filename passed.
        for name in ("file_name", "alice_public_key.pem", FILE + ".sig", FILE + ".encrypted", "key.encrypted"):
            client.upload(name, name)

        client.download("files_received", "files_received")
        time.sleep(.5)
        if file_exists("files_received") == True:
            print("[*] Uploaded {alice_public_key.pem}")
            print("[*] Uploaded {{{}.sig}}, {{{}.encrypted}}, {{key.encrypted}}".format(FILE, FILE))
            print("[*] Bob received files")
            break
        else:
            time.sleep(.5)

def connectionSuccessful():
    global client
    while file_exists("file_decrypted") == False:
        time.sleep(.5)
        client.download("files.decrypted", "files.decrypted")
        if file_exists("files_decrypted") == True:
            print("[*] Bob decrypted files successfully")
            print("[*] Finished connection")
            raise SystemExit

if __name__ == '__main__':
    import tftpy
    import base64 # for base64 encoding
    import time

    HOST = input("Enter receiver ip: ")
    PORT = int(input("Enter port: "))
    FILE = input("Enter file to send to {}: ".format(HOST))

    genPkcKey()
    f = Fernet(Fernet)
    f.genSkcKey()
    genHash()
    f.encryptFile()
    e = EncryptHash()
    e.loadAlPrivateKey()
    e.signHash()
    establishConnection()
    from os.path import exists as file_exists
    connection()
    connectionSuccessful()
