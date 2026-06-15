#!/usr/bin/env python3
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class CryptoEngine:
    def __init__(self):
        self.key_size = 32 # 32 bytes = 256 bits

    def generate_key(self, key_path="secret.key"):
        """Generates a secure 256-bit key and saves it locally."""
        try:
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
            print(f"[-] Error: Key file '{key_path}' not found. Generate one first.")
            return None

    def encrypt_file(self, target_file, key_path="secret.key"):
        """Encrypts a file using AES-256 CBC mode."""
        key = self.load_key(key_path)
        if not key:
            return False

        try:
            # Read original sensitive data
            with open(target_file, "rb") as f:
                plaintext = f.read()

            # Initialize AES Cipher in CBC mode with a random IV
            cipher = AES.new(key, AES.MODE_CBC)
            
            # AES requires data to be in 16-byte blocks. pad() fixes this.
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

            # Write the IV + the ciphertext to a new protected file
            output_file = target_file + ".enc"
            with open(output_file, "wb") as f:
                f.write(cipher.iv)
                f.write(ciphertext)

            print(f"[+] Success: '{target_file}' encrypted securely -> '{output_file}'")
            return True
        except Exception as e:
            print(f"[-] Encryption failed: {e}")
            return False

# Quick operational test
if __name__ == "__main__":
    engine = CryptoEngine()
    print("[*] Initializing Cryptographic Integrity Engine...")

    # 1. Generate the key (if it doesn't exist)
    engine.generate_key()

    # 2. Encrypt our sensitive sample file
    print("[*] Attempting secure file encryption...")
    engine.encrypt_file("sample_cardholder_data.txt")
