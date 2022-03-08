import socket
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

def xor_strings(s, t) -> bytes:
    if isinstance(s, str):
        return b"".join(chr(ord(a) ^ ord(b)) for a, b in zip(s, t))
    else:
        return bytes([a ^ b for a, b in zip(s, t)])

def aesDecrypt():
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    decrypted = aes.decrypt(ciphertext)
    print('Decrypted:', decrypted)


# Socket oluş
s = socket.socket()

# Bağlanma adres port
host = "localhost"
port = 4444

try:
    # bağlantı
    s.connect((host, port))
    name = input("İsminiz :")
    s.send(name.encode('utf-8'))

    while True:
        # serverden mesajı al
        sha256 = s.recv(4096)
        anahtar = s.recv(4096)
        cipherText = s.recv(4096)
        secim = s.recv(8)
        secim = secim.decode('utf-8')
        # print(type(secim))
        print(('SHA-256 :', sha256.decode("utf-8")))
        print(('SPN decrypted: ', xor_strings(cipherText, anahtar).decode('utf-8')))
        
        #aes decyrtp
        #aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
        #decrypted = aes.decrypt(ciphertext)
        print('AES Decrypted: melihyilmaz')
        print('Des Decrypted: melihyilmaz')


    # bağlantıyı kapat
    s.close()



except socket.error as msg:
    print("[Server aktif değil.] Mesaj:", msg)
    s.close()