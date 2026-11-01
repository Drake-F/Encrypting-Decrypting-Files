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
    
    source = Path(file_path)
    # Check if we have an absolute or relative file path
    if not source.is_absolute():
        source = Path(__file__).resolve().parent / source

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

def decrypt_file(file_path : str, master_password : str):
    # Decrypt a given file specified by the user with file_path : str with password, master_password : str
    source = Path(file_path)

    # Check if we have an absolute or relative file path
    if not source.is_absolute():
        source = Path(__file__).resolve().parent / source

    # If file does not exist we raise an error
    if not source.is_file():
        raise FileNotFoundError("Encrypted file specified by user does not exist.")

    # Gather the encrypted data
    encrypted_data = source.read_bytes()

    # Validate file format
    if not encrypted_data.startswith(MAGIC):
        raise ValueError("Invalid encrypted file format.")

    # Extract the salt number
    offset = len(MAGIC)
    salt = encrypted_data[offset:offset + SALT_SIZE]
    offset += SALT_SIZE

    # Extract the nonce
    nonce = encrypted_data[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE

    # The remaining data now is all of our encrypted data along with our authentication tag
    ciphertext = encrypted_data[offset:]

    # Derive the original encryption key
    key = get_key(master_password, salt)

    # Decrypt and authenticate the data
    try: 
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
    except InvalidTag:
        raise ValueError("Incorrect password or corrupted encrypted file.")

    # Create the decrypted output
    output = source.with_name(source.stem + "_decrypted.txt")

    with output.open("xb") as file:
        file.write(plaintext)

    return output