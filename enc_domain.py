#!/usr/bin/env python3
"""
Helper script to encrypt domains for the ELF loader.
Uses the same AES key and IV as the Rust program.
"""

import base64
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt_domain(domain):
    # Same key and IV as in the Rust code
    key = b'e6dc2260348e75ez'  # 16 bytes AES-128 key
    iv = b'4d09018a9772dfbb'   # 16 bytes IV
    
    # Encrypt the domain
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(domain.encode(), 16))
    encrypted_b64 = base64.b64encode(encrypted).decode()
    
    return encrypted_b64

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 encrypt_domain.py <domain>")
        print("Example: python3 encrypt_domain.py example.com")
        sys.exit(1)
    
    domain = sys.argv[1]
    encrypted = encrypt_domain(domain)
    
    print(f"Original domain: {domain}")
    print(f"Encrypted (base64): {encrypted}")
    print(f"\nTo use with the loader:")
    print(f"./target/release/loaderV2 '{encrypted}'")
