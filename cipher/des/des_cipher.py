"""
Triển khai thuật toán DES (Data Encryption Standard) - Phiên bản đơn giản
Không sử dụng thư viện bên thứ ba
"""
import base64
import os

class DESDemo:
    def __init__(self):
        pass
    
    # Các bảng permutation và S-box (chuẩn DES)
    IP = [58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
          62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
          57,49,41,33,25,17,9,1, 59,51,43,35,27,19,11,3,
          61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7]
    
    FP = [40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
          38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
          36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
          34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25]
    
    E = [32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13,
         12,13,14,15,16,17, 16,17,18,19,20,21, 20,21,22,23,24,25,
         24,25,26,27,28,29, 28,29,30,31,32,1]
    
    P = [16,7,20,21, 29,12,28,17, 1,15,23,26, 5,18,31,10,
         2,8,24,14, 32,27,3,9, 19,13,30,6, 22,11,4,25]
    
    PC1 = [57,49,41,33,25,17,9, 1,58,50,42,34,26,18,
           10,2,59,51,43,35,27, 19,11,3,60,52,44,36,
           63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
           14,6,61,53,45,37,29, 21,13,5,28,20,12,4]
    
    PC2 = [14,17,11,24,1,5, 3,28,15,6,21,10, 23,19,12,4,26,8,
           16,7,27,20,13,2, 41,52,31,37,47,55, 30,40,51,45,33,48,
           44,49,39,56,34,53, 46,42,50,36,29,32]
    
    SHIFT = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
    
    # S-boxes (8 boxes, mỗi box 4x16)
    S = [
        [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
         [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
         [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
         [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
        [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
         [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
         [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
         [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
        [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
         [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
         [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
         [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
        [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
         [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
         [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
         [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
        [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
         [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
         [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
         [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
        [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
         [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
         [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
         [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
        [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
         [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
         [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
         [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
        [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
         [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
         [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
         [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
    ]
    
    @staticmethod
    def _bytes_to_bits(data):
        """Chuyển bytes thành list bits"""
        bits = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits
    
    @staticmethod
    def _bits_to_bytes(bits):
        """Chuyển list bits thành bytes"""
        result = []
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(bits):
                    byte = (byte << 1) | bits[i + j]
            result.append(byte)
        return bytes(result)
    
    @staticmethod
    def _permute(bits, table):
        """Permutation theo bảng"""
        return [bits[x-1] for x in table]
    
    @staticmethod
    def _left_shift(bits, n):
        """Dịch trái"""
        return bits[n:] + bits[:n]
    
    @staticmethod
    def _generate_keys(key):
        """Tạo 16 subkeys"""
        # Key -> bits
        key_bits = DESDemo._bytes_to_bits(key)
        
        # PC1: 64 -> 56 bits
        key_56 = DESDemo._permute(key_bits, DESDemo.PC1)
        
        # Chia C0, D0
        C = key_56[:28]
        D = key_56[28:]
        
        keys = []
        for i in range(16):
            # Shift
            C = DESDemo._left_shift(C, DESDemo.SHIFT[i])
            D = DESDemo._left_shift(D, DESDemo.SHIFT[i])
            
            # PC2: 56 -> 48 bits
            key_48 = DESDemo._permute(C + D, DESDemo.PC2)
            keys.append(key_48)
        
        return keys
    
    @staticmethod
    def _sbox(bits):
        """S-box substitution"""
        result = []
        for i in range(8):
            block = bits[i*6:(i+1)*6]
            row = (block[0] << 1) | block[5]
            col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
            value = DESDemo.S[i][row][col]
            for j in range(3, -1, -1):
                result.append((value >> j) & 1)
        return result
    
    @staticmethod
    def _f_function(right, key):
        """Hàm F trong Feistel"""
        # E: 32 -> 48 bits
        expanded = DESDemo._permute(right, DESDemo.E)
        
        # XOR với key
        xor = [expanded[i] ^ key[i] for i in range(48)]
        
        # S-box: 48 -> 32 bits
        s_out = DESDemo._sbox(xor)
        
        # P: 32 bits
        return DESDemo._permute(s_out, DESDemo.P)
    
    @staticmethod
    def _des_process(block, keys, encrypt):
        """Xử lý 1 block 8 bytes"""
        # Block -> bits
        bits = DESDemo._bytes_to_bits(block)
        
        # IP
        bits = DESDemo._permute(bits, DESDemo.IP)
        
        # Chia L0, R0
        L = bits[:32]
        R = bits[32:]
        
        # 16 rounds
        for i in range(16):
            L_old = L
            key_idx = i if encrypt else 15 - i
            f = DESDemo._f_function(R, keys[key_idx])
            L = R
            R = [L_old[j] ^ f[j] for j in range(32)]
        
        # Kết hợp (swap cuối)
        combined = R + L
        
        # FP
        result = DESDemo._permute(combined, DESDemo.FP)
        
        return DESDemo._bits_to_bytes(result)
    
    @staticmethod
    def _pad(data):
        """PKCS7 padding"""
        pad_len = 8 - (len(data) % 8)
        return data + bytes([pad_len] * pad_len)
    
    @staticmethod
    def _unpad(data):
        """PKCS7 unpadding"""
        pad_len = data[-1]
        return data[:-pad_len]
    
    @staticmethod
    def GenerateKey():
        """Tạo khóa 8 bytes"""
        return os.urandom(8)
    
    @staticmethod
    def ValidateKey(key):
        """Kiểm tra key 8 bytes"""
        if isinstance(key, str):
            key = key.encode('utf-8')
        if len(key) != 8:
            raise ValueError("DES key must be 8 bytes")
        return key
    
    @staticmethod
    def Encrypt(plaintext, key):
        """Mã hóa"""
        key = DESDemo.ValidateKey(key)
        data = plaintext.encode('utf-8')
        data = DESDemo._pad(data)
        
        keys = DESDemo._generate_keys(key)
        result = b''
        
        for i in range(0, len(data), 8):
            block = data[i:i+8]
            if len(block) < 8:
                block = block + b'\x00' * (8 - len(block))
            result += DESDemo._des_process(block, keys, True)
        
        return base64.b64encode(result).decode('utf-8')
    
    @staticmethod
    def Decrypt(ciphertext, key):
        """Giải mã"""
        key = DESDemo.ValidateKey(key)
        data = base64.b64decode(ciphertext.encode('utf-8'))
        
        keys = DESDemo._generate_keys(key)
        result = b''
        
        for i in range(0, len(data), 8):
            block = data[i:i+8]
            result += DESDemo._des_process(block, keys, False)
        
        result = DESDemo._unpad(result)
        return result.decode('utf-8')
