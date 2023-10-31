from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class Encryptor:
    key = b''
    
    def __init(self):
        self.key = get_random_bytes(16)
        
        
    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_EAX)
        cipher_text, tag = cipher.encrypt_and_digest(data)
    
    
    def write(self, binfile):
        [ binfile.write(x) for x in (self.cipher.none, self.tag, self.cipher_text) ]
        binfile.close()