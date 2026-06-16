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

    def decrypt_file(self, encrypted_file, key_path="secret.key"):
        """Decrypts an AES-256 CBC encrypted file and strips padding."""
        key = self.load_key(key_path)
        if not key:
            return False

        try:
            with open(encrypted_file, "rb") as f:
                # Read the first 16 bytes to extract the Initialization Vector (IV)
                iv = f.read(16)
                # Read the rest of the file to get the actual ciphertext
                ciphertext = f.read()

            cipher = AES.new(key, AES.MODE_CBC, iv)
            # Decrypt and strip the cryptographic padding blocks cleanly
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

            # Strip the '.enc' extension to restore the original file name format
            output_file = encrypted_file.replace(".enc", ".decrypted")
            with open(output_file, "wb") as f:
                f.write(plaintext)

            print(f"[+] Success: '{encrypted_file}' decrypted cleanly -> '{output_file}'")
            return True
        except Exception as e:
            print(f"[-] Decryption failed: {e}. Check key integrity or file corruption.")
            return False

    def generate_file_hash(self, target_file):
        """Generates a SHA-256 cryptographic hash of a file for integrity verification."""
        try:
            sha256_hash = hashlib.sha256()
            with open(target_file, "rb") as f:
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
    
    # Target file containing simulated cardholder records
    test_file = "sample_cardholder_data.txt"
    
    # 1. Ensure key exists
    engine.generate_key()
    
    # 2. Run encryption check
    print("\n[*] Step 1: Encrypting sensitive data baseline...")
    if engine.encrypt_file(test_file):
        
        # 3. Generate integrity hash of the encrypted file to record the secure baseline
        print("\n[*] Step 2: Recording file integrity hash...")
        engine.generate_file_hash(test_file + ".enc")
        
        # 4. Run decryption check to simulate authorized data access
        print("\n[*] Step 3: Decrypting asset for authorized system use...")
        engine.decrypt_file(test_file + ".enc")
