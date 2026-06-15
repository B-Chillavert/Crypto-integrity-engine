#!/usr/bin/env python3
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class CryptoEngine:
    def __init__(self):
        self.key_size = 32 # 32 bytes = 256 bits

    def generate_key(self, key_path="secret.key"):
        """Generates a secure 256-bit key and saves it locally."""
        try:
            if os.path.exists(key_path):
                return self.load_key(key_path)
            key = os.urandom(self.key_size)
            with open(key_path, "wb") as key_file:
                key_file.write(key)
            print(f"[+] Success: New 256-bit key generated and saved to '{key_path}'")
            return key
        except Exception as e:
            print(f"[-] Error generating key: {e}")
            return None

    def load_key(self, key_path="secret.key"):
        """Loads an existing key from disk."""
        try:
            with open(key_path, "rb") as key_file:
                return key_file.read()
        except FileNotFoundError:
            print(f"[-] Error: Key file '{key_path}' not found.")
            return None

    def encrypt_file(self, target_file, key_path="secret.key"):
        """Encrypts a file using AES-256 CBC mode."""
        key = self.load_key(key_path)
        if not key:
            return False

        try:
            with open(target_file, "rb") as f:
                plaintext = f.read()

            cipher = AES.new(key, AES.MODE_CBC)
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

            output_file = target_file + ".enc"
            with open(output_file, "wb") as f:
                f.write(cipher.iv)
                f.write(ciphertext)

            print(f"[+] Success: '{target_file}' encrypted securely -> '{output_file}'")
            return True
        except Exception as e:
            print(f"[-] Encryption failed: {e}")
            return False

    def generate_file_hash(self, target_file):
        """Generates a SHA-256 cryptographic hash of a file for integrity verification."""
        try:
            sha256_hash = hashlib.sha256()
            with open(target_file, "rb") as f:
                # Read file in chunks to efficiently handle large files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()
            print(f"[+] SHA-256 Integrity Hash for '{target_file}':\n    {file_hash}")
            return file_hash
        except FileNotFoundError:
            print(f"[-] Error: '{target_file}' not found for hashing.")
            return None

if __name__ == "__main__":
    engine = CryptoEngine()
    print("[*] Initializing Cryptographic Integrity Engine...")
    
    # 1. Ensure key exists
    engine.generate_key()
    
    # 2. Encrypt sample target file
    print("[*] Running encryption check...")
    engine.encrypt_file("sample_cardholder_data.txt")
    
    # 3. Generate integrity hash of the original file
    print("[*] Running file integrity baseline hash...")
    engine.generate_file_hash("sample_cardholder_data.txt")
