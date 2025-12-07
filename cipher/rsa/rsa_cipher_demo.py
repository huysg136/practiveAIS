import math
class RSADemo:
    def __init__(self):
        pass
    
    @staticmethod
    def CheckPrime(n:int) -> bool:
        if n<2:
            return False
        for i in range (2, int(n**0.5) + 1):
            if n%i == 0:
                return False
        return True

    def GenerateKeys(p:int, q:int):
        if not RSADemo.CheckPrime(p) or not RSADemo.CheckPrime(q):
            raise ValueError("p and q must be prime number.")
        if p==q:
            raise ValueError("p and q must not be equal")
        
        n = p*q
        phi = (p-1)*(q-1)

        e = 65537
        for candidate in range(3, phi):
            if math.gcd(candidate, phi) == 1:
                e = candidate
                break
        
        d = pow(e, -1, phi)

        public_key = (e,n)
        private_key = (d,n)

        return public_key, private_key, p, q, phi

    def Encrypt(plaintext:str, public_key):
        e, n = public_key
        cipher_block = []

        for ch in plaintext:
            m = ord(ch)
            if m>=n:
                raise ValueError(f"Character '{ch}' has code {m}, which is >= n={n}. Choose larger primes.")
            c = pow(m, e, n)
            cipher_block.append(c)
        return cipher_block

    def Decrypt(cipher_block, private_key):
        d, n = private_key
        plaintext_char = []

        for c in cipher_block:
            m = pow(c, d, n)
            plaintext_char.append(chr(m))
        
        return "".join(plaintext_char)