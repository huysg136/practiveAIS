from aes.aes_cipher import AESCipher

aes = AESCipher("mysecretkey12345")  # key 16 byte

plaintext = b"Hello AES Testing!!!"

cipher = aes.encrypt(plaintext)
print("Ciphertext:", cipher)

decrypted = aes.decrypt(cipher)
print("Decrypted:", decrypted)

if decrypted == plaintext:
    print("AES hoạt động đúng!")
else:
    print("AES lỗi!")
