import os
import random
import math
import json
import base64
from sympy import isprime

def GeneratePrime(bits: int) -> int:
    while True:
        candidate = random.getrandbits(bits)

        candidate |= (1 << bits - 1) | 1
        if isprime(candidate):
            return candidate
    
def GenerateKeys(bits: int = 1024):
    p = GeneratePrime(bits)
    q = GeneratePrime(bits)

    n = p * q

    phi = (p-1) * (q-1)
    
    e = 65537
    if math.gcd(e, phi) != 1:
        for i in range(3, 1000, 2):
            if math.gcd(i, phi) == 1:
                e=i
                break
    
    d = pow(e, -1, phi)

    public_key = (e,n)
    private_key = (d,n)

    return public_key, private_key

def Encrypt(plaintext:str, public_key):
    e, n = public_key

    m = int.from_bytes(plaintext.encode("utf-8"), "big")

    if m >= n:
        raise ValueError("Message too long")
    
    c = pow(m, e, n)
    return c

def Decrypt(cipher_int: int, private_key):
    d, n = private_key

    m = pow(cipher_int, d, n)

    length = (m.bit_length() + 7) // 8
    plaintext = m.to_bytes(length, "big").decode("utf-8")

    return plaintext