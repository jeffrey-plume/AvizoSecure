from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import serialization
import sqlite3


import os
import secrets

def generate_and_store_master_key(file_path):
    master_key = secrets.token_bytes(32)  # Generate a 256-bit (32-byte) master key
    with open(file_path, 'wb') as key_file:
        key_file.write(master_key)
    print(f"Master key has been generated and stored in {file_path}")

# Specify the file path where the master key will be stored
master_key_file = 'masterKey.bin'

# Generate and store the master key
generate_and_store_master_key(master_key_file)


conn = sqlite3.connect('user_credentials.db')
    
# Create a cursor object using the cursor() method
cursor = conn.cursor()

# Create the users table
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT NOT NULL UNIQUE,
password_hash TEXT NOT NULL,
salt TEXT NOT NULL,
encrypted_private_key TEXT NOT NULL,
public_key TEXT NOT NULL
)
''')

def encrypt_private_key(private_key_pem, master_key):
    # Derive an encryption key and IV (initialization vector) from the master key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'8848',  # Use a secure and random salt in production
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(master_key)
    iv = secrets.token_bytes(16)  # Generate a random 16-byte IV for AES

    # Encrypt the private key using AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Add padding to the private key
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_private_key = padder.update(private_key_pem) + padder.finalize()

    encrypted_private_key = encryptor.update(padded_private_key) + encryptor.finalize()
    
    # Store the IV with the encrypted private key
    return b64encode(iv + encrypted_private_key).decode('utf-8')


def decrypt_private_key(encrypted_private_key_b64, master_key):
    # Decode the base64-encoded encrypted private key
    encrypted_data = b64decode(encrypted_private_key_b64)
    
    # Extract the IV and the actual encrypted private key
    iv = encrypted_data[:16]
    encrypted_private_key = encrypted_data[16:]

    # Derive the encryption key from the master key using the same KDF and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=self.get_salt(username),  # Use the same salt
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(master_key)

    # Decrypt the private key using AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_private_key = decryptor.update(encrypted_private_key) + decryptor.finalize()

    # Remove padding
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    private_key_pem = unpadder.update(padded_private_key) + unpadder.finalize()

    # Load the private key object from the PEM data
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    return private_key
