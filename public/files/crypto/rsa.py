#!/usr/bin/env python3
"""RSA Basics Challenge"""

# Given values
n = 3233  # n = p * q
e = 17    # public exponent
c = 2201  # ciphertext

# Your task:
# 1. Factor n to find p and q
# 2. Calculate phi(n) = (p-1)(q-1)
# 3. Find d = e^(-1) mod phi(n)
# 4. Decrypt: m = c^d mod n

# Hint: n = 61 * 53

def solve():
    p, q = 61, 53
    phi_n = (p - 1) * (q - 1)

    # Extended Euclidean Algorithm to find d
    def modinv(a, m):
        g, x, _ = extended_gcd(a, m)
        if g != 1:
            raise Exception('No modular inverse')
        return x % m

    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        return gcd, y1 - (b // a) * x1, x1

    d = modinv(e, phi_n)
    m = pow(c, d, n)
    print(f"Decrypted message: {m}")
    print(f"As ASCII: {chr(m)}")

if __name__ == "__main__":
    solve()
