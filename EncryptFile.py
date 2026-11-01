from pathlib import Path
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from Generate_Encryption_Key import get_key

MAGIC = b"PWENC1"
SALT_SIZE = 16
NONCE_SIZE = 12

def encrypt_file(file_path : str, master_password: str):
    # Encrypts a file using the file_path : str specified by the user and the master password : str for later decryption
    
    # For a fully specified file path
    # source = Path(file_path)
    
    # For relative file paths
    source = Path(__file__).resolve().parent / file_path

    # Raise an error alerting the user if the file can not be found
    if not source.is_file():
        raise FileNotFoundError("File specified by user does not exist.")

    # Read the original file contents
    plaintext = source.read_bytes()

    # Generate our random salt and nonce
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)

    # Generate our encryption key
    key = get_key(master_password, salt)

    # Encrypt the file contents
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, MAGIC)

    # Build the encrypted file contents
    encrypted_data = MAGIC + salt + nonce + ciphertext

    # Write to a seperate file - only for the time being to make sure file contents are not lost
    output = Path(str(source) + ".enc")
    output.write_bytes(encrypted_data)

    return output