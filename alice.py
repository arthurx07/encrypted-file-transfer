#!/bin/env python


def gen_pkc_key():
    # Generate alice's key
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    al_public_key = private_key.public_key()

    logging.info("S'han generat les claus públiques i privades")

    # Emmagatzemar les claus
    from cryptography.hazmat.primitives import serialization

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(f"{TMPDIR}/alice_private_key.pem", "wb") as file:
        file.write(private_pem)

    public_pem = al_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(f"{TMPDIR}/alice_public_key.pem", "wb") as file:
        file.write(public_pem)

    logging.info(
        "Claus públiques i privades emmagatzemades com a [alice_public/private_key]"
    )


class Fernet:
    def __init__(self, fernet):
        self.Fernet = fernet

    def gen_skc_key(self):
        # Generar una clau skc i emmagatzemar-la
        from cryptography.fernet import Fernet

        self.key = Fernet.generate_key()
        with open(f"{TMPDIR}/key.key", "wb") as key_file:
            key_file.write(self.key)

        logging.info(
            "Clau de sessió aleatòria (skc) generada i emmagatzemada com a [key.key]"
        )

    def encrypt_file(self):  # Encriptació de l'arxiu amb la clau skc
        from cryptography.fernet import Fernet

        # Given a filename (str) and key (bites), it encrypts the file and writes it
        f_encrypt = Fernet(self.key)
        with open(FILE, "rb") as file:
            # Llegir les dades de l'arxiu
            file_data = file.read()
            # Xifrar les dades
            encrypted_data = f_encrypt.encrypt(file_data)
            # Emmagatzemar l'arxiu encriptat
            with open(f"{TMPDIR}/{FILE_CLEAN}.encrypted", "wb") as file_encrypted:
                file_encrypted.write(encrypted_data)

        logging.info(f"[{FILE_CLEAN}.encrypted] xifrat amb la clau de sessió")


def gen_hash():  # Generar hash de l'arxiu
    from hashlib import blake2b

    # Dividiu els fitxers en parts, per no utilitzar molta memòria RAM en fitxers grans
    buf_size = 65536  # Llegir en trossos de 64 kb // buf_size és totalment arbitrària

    blake2 = blake2b()

    with open(FILE, "rb") as file:
        while True:
            data = file.read(buf_size)
            if not data:
                break
            blake2.update(data)

    hash_data = "{0}".format(blake2.hexdigest())

    # Write hash to file.blake2b
    with open(f"{TMPDIR}/{FILE_CLEAN}.blake2b", "w") as hash_file:
        hash_file.write(hash_data)

    logging.info(
        f"Hash generat de l'arxiu [{FILE_CLEAN}] i emmagatzemat com a [{FILE_CLEAN}.blake2b]"
    )


class EncryptHash:  # Xifrar hash amb la clau privada d'Alice (signar-lo)
    def load_al_private_key(self):  # Carregar la clau privada d'Alice
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization

        with open(f"{TMPDIR}/alice_private_key.pem", "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )

        logging.info("Fitxer [alice_private_key.pem] carregat")

    def sign_hash(self):  # Signar hash
        # Càrrega dels continguts de file.blake2b
        with open(f"{TMPDIR}/{FILE_CLEAN}.blake2b", "rb") as file:
            payload = file.read()

        logging.info(f"Arxiu [{FILE_CLEAN}.blake2b] carregat")

        # Signar l'arxiu file.blakeb a file.sig
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        import base64  # Per a la codificació a base64

        signature = base64.b64encode(
            self.private_key.sign(
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        )
        with open(f"{TMPDIR}/{FILE_CLEAN}.sig", "wb") as file:
            file.write(signature)

        logging.info(
            f"Arxiu [{FILE_CLEAN}.blake2b] signat amb la clau privada com a [{FILE_CLEAN}.sig]"
        )


def load_bob_public_key():  # Càrrega de bob public key
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization

    global bob_public_key
    with open(f"{TMPDIR}/bob_public_key.pem", "rb") as key_file:
        bob_public_key = serialization.load_pem_public_key(
            key_file.read(), backend=default_backend()
        )

    logging.info("Fitxer [bob_public_key.pem] carregat")


def encrypt_skc_key():  # Encriptar key.key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    load_bob_public_key()

    # Desar el contingut de la clau com a bytes a la variable message
    with open(f"{TMPDIR}/key.key", "rb") as file:
        message = file.read()

    logging.info("Carregat l'arxiu [key.key] per a la seva encriptació")

    # Xifrar la clau
    global bob_public_key
    encrypted = bob_public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Emmagatzemar key.key xifrat com a key.encrypted
    with open(f"{TMPDIR}/key.encrypted", "wb") as file:
        file.write(encrypted)

    logging.info("Arxiu [key.key] xifrat amb [bob_public_key] com a [key.encrypted]")


def establish_connection():  # Crear un client tftpy
    import tftpy

    global client
    client = tftpy.TftpClient(HOST, PORT)
    logging.info(f"Iniciada la connexió amb [{HOST}] al port [{PORT}]")
    return client


def connection():  # Pujar arxius, descarregar bob_public_key
    global client
    while os.path.exists(f"{TMPDIR}/key.encrypted") is False:
        # Descarregar bob public key
        # Initiates a tftp download from the configured remote host, requesting the filename passed
        client.download(f"{TMPDIR}/bob_public_key.pem", f"{TMPDIR}/bob_public_key.pem")
        if os.path.exists(f"{TMPDIR}/bob_public_key.pem") is True:
            logging.info(f"Connexió amb éxit amb [{HOST}] al port [{PORT}]")
            logging.info("[bob_public_key.pem] rebut")
            Thread(target=encrypt_skc_key).start()
            break

    while os.path.exists(f"{TMPDIR}/files_received") is False:
        # Escriure el nom de l'arxiu al fitxer file_name
        with open(f"{TMPDIR}/file_name", "w") as file:
            file.write(f"{FILE_CLEAN}\n")

        # Pujar alice_public_key, l'arxiu encriptat, el hash signat i la clau de sessió xifrada
        # Initiates a tftp upload to the configured remote host, uploading the filename passed.
        for name in (
            f"{TMPDIR}/file_name",
            f"{TMPDIR}/alice_public_key.pem",
            f"{TMPDIR}/{FILE_CLEAN}.sig",
            f"{TMPDIR}/{FILE_CLEAN}.encrypted",
            f"{TMPDIR}/key.encrypted",
        ):
            client.upload(name, name)

        sleep(0.1)
        # Sol·licitar la confirmació que Bob ha rebut els fitxers
        files_rcv = f"{TMPDIR}/files_received"
        client.download(files_rcv, files_rcv)
        if os.path.exists(files_rcv) is True:
            logging.info("Pujat [alice_public_key.pem]")
            logging.info(
                f"Pujat [{FILE_CLEAN}.sig], [{FILE_CLEAN}.encrypted], [key.encrypted]"
            )
            logging.info("Bob ha rebut els fitxers")
            break
        else:
            sleep(0.5)


def connection_successful():
    logging.info("Connexió finalitzada")


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


if __name__ == "__main__":
    # Importacions
    import os
    import logging
    import argparse
    from tqdm import tqdm
    from time import sleep
    from threading import Thread

    # Definir un analitzador d'arguments per a una utilització més fàcil del programari
    parser = argparse.ArgumentParser(description="Encrypted File Sender")
    parser.add_argument("file", help="File name to send")
    parser.add_argument("host", help="The host/IP address of the receiver")
    parser.add_argument(
        "-p", "--port", help="Port to use, default is 5001", default=5001
    )
    parser.add_argument(
        "-d",
        "--dir",
        help="Directory to store temporary files, default is $XDG_CACHE_HOME/encrypted-file-transfer/alice",
        default=os.path.expanduser('~') + "/.cache/encrypted-file-transfer-alice/",
    )
    parser.add_argument("-l", "--log", help="Enable debugging", action="store_true")
    parser.add_argument(
        "-s", "--save", help="Save temporary files", action="store_true"
    )
    args = parser.parse_args()

    # Definir les variables globals (constants)
    FILE = args.file
    d, FILE_CLEAN = os.path.split(f"{FILE}")
    HOST = args.host
    PORT = args.port
    TMPDIR = args.directory
    LOG = args.log
    SAVE_FILES = args.save

    logger()

    f = Fernet(Fernet)
    e = EncryptHash()

    # Cridar les functions
    myfunctions = [
        mkdir,
        gen_pkc_key,
        f.gen_skc_key,
        gen_hash,
        f.encrypt_file,
        e.load_al_private_key,
        e.sign_hash,
        establish_connection,
        connection,
        connection_successful,
        rmfiles,
    ]

    # Configuració de la barra de progrés
    for i in tqdm(myfunctions):
        i()
        sleep(0.1)
        if i == "rmfiles":
            raise SystemExit
