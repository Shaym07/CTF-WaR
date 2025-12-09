#!/usr/bin/env python3
"""XOR Encryption Challenge"""

# Encrypted flag (XORed with key 0x42)
encrypted = bytes.fromhex('150d1a130600171f0b0d0a04170e171b1d0c')

# Your task: XOR with key to decrypt
key = 0x42

# Solution:
# decrypted = bytes(b ^ key for b in encrypted)
# print(decrypted.decode())
