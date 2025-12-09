#!/usr/bin/env python3
"""Padding Oracle Attack Challenge"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

KEY = os.urandom(16)
IV = os.urandom(16)

def encrypt(plaintext):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded = pad(plaintext.encode(), 16)
    return IV + cipher.encrypt(padded)

def decrypt_and_check(ciphertext):
    """Returns True if padding is valid, False otherwise"""
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    try:
        plaintext = cipher.decrypt(ct)
        unpad(plaintext, 16)
        return True  # Padding valid
    except:
        return False  # Padding invalid - ORACLE LEAK!

# The flag is encrypted
FLAG = "WOW{p4dd1ng_0r4cl3_4tt4ck}"
encrypted_flag = encrypt(FLAG)
print(f"Encrypted flag (hex): {encrypted_flag.hex()}")

# Your task: Use the padding oracle to decrypt byte by byte
# Tool: https://github.com/AonCyberLabs/PadBuster
