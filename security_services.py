import os
from cryptography.fernet import Fernet

KEY_FILE = "secret.key"


def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()

    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key


def get_cipher():
    return Fernet(load_or_create_key())
