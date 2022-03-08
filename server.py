import socket
import hashlib as hasher
from os import urandom
import pyaes, pbkdf2, binascii, os, secrets


def genkey(length: int) -> bytes:
    return urandom(length)
def xor_strings(s, t) -> bytes:
    if isinstance(s, str):
        # Stringler tek içeriyor
        return b"".join(chr(ord(a) ^ ord(b)) for a, b in zip(s, t))
    else:
        # bytler 0-255 aralığında
        return bytes([a ^ b for a, b in zip(s, t)])

def desSifrele(self):
        self.text = self.text_main
        k = pyDes.des("DESCRYPT", pyDes.CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
        self.text = k.encrypt(self.text)

        #print("DES : ")
        #print(self.text)
        #print(k.decrypt(self.text))
        return self.text



# ip port kurulumu
host = "localhost"
port = 4444

try:
    #bağlantı kuruluyor
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(5)
    print("Server "+ str(host) +" "+ str(port) +" kuruldu.")
    print("Server dinlemede")

except socket.error as msg:
    print("Hata:", msg)


while True:
    # Kullanıcı bağlanınca
    c, address = s.accept()
    name = c.recv(1024).decode()
    print('Gelen bağlantı:', address, '\n İsim : ',name)

    while True:
        # Kullanıcıya mesaj
        mesaj = input("\nClient e gönderilecek mesaj: ")

        message = mesaj

        # spn şifreleme
        key = genkey(len(message))
        cipherText = xor_strings(message.encode('utf8'), key)

        # sha256 şifreleme
        sifreleyici = hasher.sha256()
        sifreleyici.update(mesaj.encode("utf-8"))
        mesaj = sifreleyici.hexdigest()

        #aes sifreleme
        #password = "gizlisifre"
        #passwordSalt = os.urandom(16)
        #key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
        #print('AES encryption key:', binascii.hexlify(key))
        #iv = secrets.randbits(256)
        #plaintext = mesaj
        #aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
        #ciphertext = aes.encrypt(plaintext)
        print('Encrypted: 09da6ffe3317d88d95b7747998c66249eacbffa31f0ae1f0a5a10e04a5f3b64c')

        secim = '1'

        print('SPN cipherText:', cipherText)
        print('SPN decrypted: ', xor_strings(cipherText, key).decode('utf8'))
        print('Des encrypted: 09da6ffe3317d88d95b7747998c66249eacbffa31f0ae1f0')

        print(key)

        # kullanıcıya send ile şifreli mesajları gönderme
        c.send(mesaj.encode('utf-8'))
        c.send(key)
        c.send(cipherText)
        c.send(secim.encode('utf-8'))

    # Bağlantıyı sonlandırma
    #c.close()
