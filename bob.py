#!/bin/env python


def gen_pkc_key():
    # Generar claus públiques i privades de Bob
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    logging.info("Public and private keys generated")

    # Emmagatzemar les claus de Bob
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

    logging.info(
        "Claus públiques i privades emmagatzemades com a [bob_public/private_key]"
    )


class Server:
    def establish_connection(self):  # Bob estableix una connexió amb Alice
        import tftpy

        # Adreça IP del dispositiu
        server_host = "0.0.0.0"  # 0.0.0.0 vol dir totes les adresses ipv4 que están al dispositiu local
        # SERVER_PORT (definit com a variable global)

        # Obtenir l'adreça ip pública i local
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
        ]  # Code de https://stackoverflow.com/a/1267524

        # From requests import get
        # PUBLIC_IP = get('https://api.ipify.org').content.decode('utf8')

        # Crear servidor tftpy
        self.server = tftpy.TftpServer(".")
        logging.warning(
            f"Creat servidor tftp amb host a {local_ip} i el port a {SERVER_PORT}"
        )

        # Server waiting for receiving files
        logging.info(
            "Escoltant, esperant que altres dispositius es connectin i enviïn fitxers"
        )
        Thread(target=s.connection).start()
        self.server.listen(server_host, SERVER_PORT)

    def connection(self):
        global FILE
        # Definir la variable FILE a prtir dels continguts de l'arxiu file_name
        while True:
            if os.path.exists(f"{TMPDIR}/file_name") is True:
                sleep(0.1)
                with open(f"{TMPDIR}/file_name", "r") as file:
                    FILE = file.read().rstrip()
                break
        # Comprovar si s'han rebut tots els arxius, enviar confirmació a Alicde
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
                    f"Connexió exitosa. [{FILE}] rebut, començant el desxifrat."
                )
                break

    def connection_successful(self):
        if os.path.exists(FILE) is True:
            logging.info(f"[{FILE}] rebut satisfactòriament")
        logging.info("Connexió finalitzada")
        self.server.stop()


def load_bob_private_key():  # Càrrega de la clau privada de Bob
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    # Carregar bob_private_key
    global private_key
    with open(f"{TMPDIR}/bob_private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )

    logging.info("Loaded [bob_private_key.pem]")


def decrypt_skc_key():  # Desxifrar la clau de sessió
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
        #     logging.debug("Rebut {key.encrypted} íntegrament")
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

    logging.info("Desxifrat [key.encrypted] i emmagatzemat com a [key.key]")


def load_skc_key():  # Càrrega el fitxer del directori anomenat `key.key`
    global key
    with open(f"{TMPDIR}/key.key", "rb") as f:
        key = f.read()

    logging.info("Carregat [key.key]")


def decrypt_file():  # Bob desxifra el fitxer amb la clau de sessió (skc)
    # Given a filename (str) and key (bytes), it decripts the file and write it
    from cryptography.fernet import Fernet

    global key
    global FILE

    f = Fernet(key)
    with open(f"{TMPDIR}/{FILE}.encrypted", "rb") as file:
        # Llegir les dades encriptades
        encrypted_data = file.read()

    logging.info(f"Carregat [{FILE}.encrypted]")

    # Desxifrar les dades
    decrypted_data = f.decrypt(encrypted_data)

    # Emmagatzemar l'arxiu original
    with open(FILE, "wb") as file:
        file.write(decrypted_data)

    logging.info(f"[{FILE}] desxifrat i emmagatzemat")


def gen_hash():  # Bob genera un blake2b hash de l'arxiu un cop desxifrat
    global FILE
    from hashlib import blake2b

    # Dividiu els fitxers en parts, per no utilitzar molta memòria RAM en fitxers grans
    buf_size = 65536  # Llegir en trossos de 64 kb // buf_size és totalment arbitrària

    blake2 = blake2b()

    with open(FILE, "rb") as f:
        while True:
            data = f.read(buf_size)
            if not data:
                break
            blake2.update(data)

    hash_blake2 = "{0}".format(blake2.hexdigest())

    # Emmagatzemar el hash a un arxiu
    with open(f"{TMPDIR}/{FILE}.blake2b", "w") as hash_file:
        hash_file.write(hash_blake2)

    logging.info(f"Hash generat de [{FILE}] i emmagatzemat com a [{FILE}.blake2b]")


class Verify:  # Bob verifica l'arxiu (desxifra el hash, genera un hash de l'arxiu (ja realitzat), els compara)
    global FILE

    def __init__(self):
        self.public_key = None
        self.payload_contents = None
        self.signature = None

    def load_al_public_key(self):
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.backends import default_backend

        # Càrrega de la clau pública d'Alice
        with open(f"{TMPDIR}/alice_public_key.pem", "rb") as f:
            self.public_key = load_pem_public_key(f.read(), default_backend())

        logging.info("Loaded [alice_public_key.pem]")

    def load_hash_sig(self):
        import base64  # Per a la decodificació de base64

        # Carregar els continguts del fitxer i la signatura
        with open(f"{TMPDIR}/{FILE}.blake2b", "rb") as f:
            self.payload_contents = f.read()
        with open(f"{TMPDIR}/{FILE}.sig", "rb") as f:
            self.signature = base64.b64decode(f.read())

        logging.info(f"Carregat [{FILE}.blake2b] i [{FILE}.sig]")

    def verification(self):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes

        # Duur a terme la verificació
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
    # Creació del directori temporal (tmpdir)
    if os.path.isdir(TMPDIR) is False:
        os.mkdir(TMPDIR)


def rmfiles():
    # Eliminar rmdir de forma recursiva, incloent els fitxers temporals de l'interior
    from shutil import rmtree

    if SAVE_FILES is False:
        rmtree(TMPDIR)
        logging.info("Fitxers temporals suprimits")
    else:
        logging.info("Fitxers temporals no suprimits")


def logger():
    # Enregistrador
    if LOG is True:
        logging.root.handlers = []
        logging.basicConfig(
            format="%(asctime)s [%(threadName)-10.10s] [%(levelname)-4.4s]  %(message)s",
            level=logging.INFO,
            filename="%slog" % __file__[:-2],
        )

        # Configura el registre a la consola
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)
        # Estableix un format que sigui més senzill per a la visualització a la consola
        formatter = logging.Formatter("%(asctime)s [%(levelname)-4.4s]  %(message)s")
        ch.setFormatter(formatter)
        logging.getLogger("").addHandler(ch)
    elif LOG is False:
        logging.basicConfig(level=logging.WARNING, format="[*] %(message)s")


class Loader:  # Petita animació de càrrega
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

    # Definir un analitzador d'arguments per a una utilització més fàcil del programari
    parser = argparse.ArgumentParser(description="Encrypted File Receiver")
    parser.add_argument(
        "-p", "--port", help="Port to use, default is 5001", default=5001
    )
    parser.add_argument(
        "-d",
        "--dir",
        help="Directory to store temporary files, default is $XDG_CACHE_HOME/encrypted-file-transfer/bob",
        default="/home/kumao/.cache/encrypted-file-transfer-bob/",
    )
    parser.add_argument("-l", "--log", help="Enable debugging", action="store_true")
    parser.add_argument(
        "-s", "--save", help="Save temporary files", action="store_true"
    )
    args = parser.parse_args()

    # Definir les variables globals (constants)
    TMPDIR = args.dir
    SERVER_PORT = args.port
    LOG = args.log
    SAVE_FILES = args.save

    logger()

    # Cridar les functions
    mkdir()
    gen_pkc_key()
    load_bob_private_key()
    s = Server()
    Thread(target=s.establish_connection).start()
    sleep(0.1)
    loader = Loader("[*] Establint connexió...", "").start()  # Animació de càrrega
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

            # Configuració de la barra de progrés
            for i in tqdm(myfunctions):
                i()
                sleep(0.1)
            break
        else:
            pass
    raise SystemExit
