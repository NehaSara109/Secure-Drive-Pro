import os
import uuid

ENCRYPTED_DIR = "encrypted_files"


def ensure_storage_dir():
    os.makedirs(ENCRYPTED_DIR, exist_ok=True)


def encrypt_and_store_file(file_storage, cipher):
    ensure_storage_dir()
    file_id = str(uuid.uuid4())
    data = file_storage.read()
    size_bytes = len(data)
    encrypted_data = cipher.encrypt(data)
    encrypted_path = os.path.join(ENCRYPTED_DIR, f"{file_id}.enc")

    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)

    return file_id, size_bytes


def load_and_decrypt_file(file_id, cipher):
    encrypted_path = os.path.join(ENCRYPTED_DIR, f"{file_id}.enc")
    with open(encrypted_path, "rb") as f:
        encrypted_data = f.read()
    return cipher.decrypt(encrypted_data)


def delete_encrypted_file(file_id):
    encrypted_path = os.path.join(ENCRYPTED_DIR, f"{file_id}.enc")
    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)
