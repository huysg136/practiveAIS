import base64
from cipher.des.des_cipher import DESDemo

class TripleDESDemo:
    def __init__(self):
        pass

    def Encrypt(self, plaintext: str, key1: bytes, key2: bytes, key3: bytes) -> str:
        """
        Triple DES EDE: Encrypt -> Decrypt -> Encrypt
        """
        data = plaintext.encode('utf-8')
        data = DESDemo._pad(data)

        keys1 = DESDemo._generate_keys(key1)
        keys2 = DESDemo._generate_keys(key2)
        keys3 = DESDemo._generate_keys(key3)

        result = b''
        for i in range(0, len(data), 8):
            block = data[i:i+8]
            if len(block) < 8:
                block += b'\x00' * (8 - len(block))

            block = DESDemo._des_process(block, keys1, True)   
            block = DESDemo._des_process(block, keys2, False)  
            block = DESDemo._des_process(block, keys3, True)  
            result += block

        return base64.b64encode(result).decode('utf-8')

    def Decrypt(self, ciphertext: str, key1: bytes, key2: bytes, key3: bytes) -> str:
        """
        Triple DES EDE: Decrypt -> Encrypt -> Decrypt
        """
        data = base64.b64decode(ciphertext.encode('utf-8'))

        keys1 = DESDemo._generate_keys(key1)
        keys2 = DESDemo._generate_keys(key2)
        keys3 = DESDemo._generate_keys(key3)

        result = b''
        for i in range(0, len(data), 8):
            block = data[i:i+8]

            # DED
            block = DESDemo._des_process(block, keys3, False)  
            block = DESDemo._des_process(block, keys2, True)   
            block = DESDemo._des_process(block, keys1, False)  
            result += block

        result = DESDemo._unpad(result)
        return result.decode('utf-8')
