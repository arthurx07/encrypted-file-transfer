#!/bin/env python


def gen_pkc_key():
    # Generate bob's key
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    logging.info("Public and private keys generated")

    # Store bob's keys
    from cryptography.hazmat.primitives import serialization

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(f"{TMPDIR}/bob_private_key.pem", "wb") as f:
        f.write(private_pem)

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(f"{TMPDIR}/bob_public_key.pem", "wb") as f:
        f.write(public_pem)

    logging.info("Public and private keys stored as [bob_public/private_key]")


class Server:
    def establish_connection(self):  # Bob establishes a connection with alice
        import tftpy

        # Device's IP address
        server_host = (
            "0.0.0.0"  # means all ipv4 addresses that are on the local machine
        )
        # SERVER_PORT (defined as global variable)

        # Get local and public ip
        import socket

        local_ip = (
            (
                [
                    ip
                    for ip in socket.gethostbyname_ex(socket.gethostname())[2]
                    if not ip.startswith("127.")
                ]
                or [
                    [
                        (s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close())
                        for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]
                    ][0][1]
                ]
            )
            + ["no IP found"]
        )[
            0
        ]  # Code from https://stackoverflow.com/a/1267524

        # From requests import get
        # PUBLIC_IP = get('https://api.ipify.org').content.decode('utf8')

        # Create tftpy server
        self.server = tftpy.TftpServer(".")
        logging.warning(
            f"Creat servidor tftp amb host a {local_ip} i el port a {SERVER_PORT}"
        )

        # Server waiting for receiving files
        logging.info("Listening, waiting for other devices to connect and send files")
        Thread(target=s.connection).start()
        self.server.listen(server_host, SERVER_PORT)

    def connection(self):
        global FILE
        # Define FILE variable from file_name contents
        while True:
            if os.path.exists(f"{TMPDIR}/file_name") is True:
                sleep(0.1)
                with open(f"{TMPDIR}/file_name", "r") as file:
                    FILE = file.read().rstrip()
                break
        # Check if received all files and send confirmation to Bob
        while True:
            if (
                os.path.exists(f"{TMPDIR}/alice_public_key.pem") is True
                and os.path.exists(f"{TMPDIR}/{FILE}.sig") is True
                and os.path.exists(f"{TMPDIR}/{FILE}.encrypted") is True
                and os.path.exists(f"{TMPDIR}/key.encrypted") is True
            ):
                with open(f"{TMPDIR}/files_received", "w") as file:
                    file.write("temporary file")
                logging.info(
                    f"Connection successful. [{FILE}] received, starting decryption."
                )
                break

    def connection_successful(self):
        if os.path.exists(FILE) is True:
            logging.info(f"[{FILE}] received successfully")
        logging.info("Finished connection")
        self.server.stop()


def load_bob_private_key():  # Loads bob private key
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    # Load bob private key
    global private_key
    with open(f"{TMPDIR}/bob_private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )

    logging.info("Loaded [bob_private_key.pem]")


def decrypt_skc_key():  # Decrypt session key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    global private_key
    # If doesn't work add time.sleep(1) to wait receiving all file contents or use if len(encrypted) == "256":
    while (
        True
    ):  # Else file has not been completely sent // error: Ciphertext length must be equal to key size //
        with open(f"{TMPDIR}/key.encrypted", "rb") as f:
            encrypted = f.read()
        # if len(encrypted) == "256": # Won't print, if statement not working
        #     logging.debug("Fully received {key.encrypted}")
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        break
    with open(f"{TMPDIR}/key.key", "wb") as f:
        f.write(decrypted)

    logging.info("Decrypted [key.encrypted] and written into [key.key]")


def load_skc_key():  # Loads the key from the current directory named `key.key`
    global key
    with open(f"{TMPDIR}/key.key", "rb") as f:
        key = f.read()

    logging.info("Loaded [key.key]")


def decrypt_file():  # Bob decrypts file w/ session key
    # Given a filename (str) and key (bytes), it decripts the file and write it
    from cryptography.fernet import Fernet

    global key
    global FILE

    f = Fernet(key)
    with open(f"{TMPDIR}/{FILE}.encrypted", "rb") as file:
        # Read the encrypted data
        encrypted_data = file.read()

    logging.info(f"Loaded [{FILE}.encrypted]")

    # Decrypt data
    decrypted_data = f.decrypt(encrypted_data)

    # Write the original file
    with open(FILE, "wb") as file:
        file.write(decrypted_data)

    logging.info(f"[{FILE}] decrypted and stored")


def gen_hash():  # Bob generates blake2b hash from blake2b.encrypted
    global FILE
    from hashlib import blake2b

    # Divide files in chunks, to not use a lot of ram for big files
    buf_size = 65536  # Read in 64kb chunks // buf_size is totally arbitrary

    blake2 = blake2b()

    with open(FILE, "rb") as f:
        while True:
            data = f.read(buf_size)
            if not data:
                break
            blake2.update(data)

    hash_blake2 = "{0}".format(blake2.hexdigest())

    # Write hash to file
    with open(f"{TMPDIR}/{FILE}.blake2b", "w") as hash_file:
        hash_file.write(hash_blake2)

    logging.info(f"Hash generated from [{FILE}] and written to [{FILE}.blake2b]")


class Verify:  # Bob verifies file (decrypts hash, generates hash from file (before), compares)
    global FILE

    def __init__(self):
        self.public_key = None
        self.payload_contents = None
        self.signature = None

    def load_al_public_key(self):
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.backends import default_backend

        # Load the public key.
        with open(f"{TMPDIR}/alice_public_key.pem", "rb") as f:
            self.public_key = load_pem_public_key(f.read(), default_backend())

        logging.info("Loaded [alice_public_key.pem]")

    def load_hash_sig(self):
        import base64  # for base64 decoding

        # Load the payload contents and the signature.
        with open(f"{TMPDIR}/{FILE}.blake2b", "rb") as f:
            self.payload_contents = f.read()
        with open(f"{TMPDIR}/{FILE}.sig", "rb") as f:
            self.signature = base64.b64decode(f.read())

        logging.info(f"Loaded [{FILE}.blake2b] and [{FILE}.sig]")

    def verification(self):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes

        # Perform the verification.
        try:
            self.public_key.verify(
                self.signature,
                self.payload_contents,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            logging.info(f"[{FILE}] verification succeeded")
        except InvalidSignature:
            logging.error("Payload and/or signature files failed verification!")


def mkdir():
    # Create tmpdir
    if os.path.isdir(TMPDIR) is False:
        os.mkdir(TMPDIR)


def rmfiles():
    from shutil import rmtree

    # Remove rmdir recursively, with temporary files inside
    if SAVE_FILES is False:
        rmtree(TMPDIR)
        logging.info("Temporary files removed")
    else:
        logging.info("Temporary files not removed")


def logger():
    # Logger
    if LOG is True:
        logging.root.handlers = []
        logging.basicConfig(
            format="%(asctime)s [%(threadName)-10.10s] [%(levelname)-4.4s]  %(message)s",
            level=logging.INFO,
            filename="%slog" % __file__[:-2],
        )

        # Set up logging to console
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)
        # Set a format which is simpler for console use
        formatter = logging.Formatter("%(asctime)s [%(levelname)-4.4s]  %(message)s")
        ch.setFormatter(formatter)
        logging.getLogger("").addHandler(ch)
    elif LOG is False:
        logging.basicConfig(level=logging.WARNING, format="[*] %(message)s")


class Loader:  # Small loading dots animation
    def __init__(self, desc="Loading...", end="Done!", timeout=0.1):
        """
        A loader-like context manager

        Args:
            desc (str, optional): The loader's description. Defaults to "Loading...".
            end (str, optional): Final print. Defaults to "Done!".
            timeout (float, optional): Sleep time between prints. Defaults to 0.1.
        """
        self.desc = desc
        self.end = end
        self.timeout = timeout

        self._thread = Thread(target=self._animate, daemon=True)
        self.steps = ["⢿", "⣻", "⣽", "⣾", "⣷", "⣯", "⣟", "⡿"]
        self.done = False

    def start(self):
        self._thread.start()
        return self

    def _animate(self):
        for c in cycle(self.steps):
            if self.done:
                break
            print(f"\r{self.desc} {c}", flush=True, end="")
            sleep(self.timeout)

    def __enter__(self):
        self.start()

    def stop(self):
        self.done = True
        cols = get_terminal_size((80, 20)).columns
        print("\r" + " " * cols, end="", flush=True)
        print(f"\r{self.end}", flush=True)

    def __exit__(self, exc_type, exc_value, tb):
        # handle exceptions with those variables ^
        self.stop()


if __name__ == "__main__":
    # Imports
    import os
    import logging
    import argparse
    from tqdm import tqdm
    from time import sleep
    from itertools import cycle
    from threading import Thread
    from shutil import get_terminal_size

    # Define argument parser for easier utilization
    parser = argparse.ArgumentParser(description="Encrypted File Receiver")
    parser.add_argument(
        "-p", "--port", help="Port to use, default is 5001", default=5001
    )
    parser.add_argument(
        "-d",
        "--dir",
        help="Directory to store temporary files, default is tmp/",
        default="tmp/",
    )
    parser.add_argument("-l", "--log", help="Enable debugging", action="store_true")
    parser.add_argument(
        "-s", "--save", help="Save temporary files", action="store_true"
    )
    args = parser.parse_args()

    # Define global variables
    TMPDIR = args.dir
    SERVER_PORT = args.port
    LOG = args.log
    SAVE_FILES = args.save

    logger()

    mkdir()
    gen_pkc_key()
    load_bob_private_key()
    s = Server()
    Thread(target=s.establish_connection).start()
    sleep(0.1)
    loader = Loader("[*] Establint connexió...", "").start()
    while True:
        if os.path.exists(f"{TMPDIR}key.encrypted") is True:
            loader.stop()
            # loader = Loader("[*] Decrypting file...", "").start()
            logging.warning("Desxifrant arxiu...")

            sleep(0.1)
            v = Verify()
            myfunctions = [
                decrypt_skc_key,
                load_skc_key,
                decrypt_file,
                gen_hash,
                v.load_al_public_key,
                v.load_hash_sig,
                v.verification,
                s.connection_successful,
                rmfiles,
            ]

            for i in tqdm(myfunctions):
                i()
                sleep(0.1)
            break
        else:
            pass
    raise SystemExit
