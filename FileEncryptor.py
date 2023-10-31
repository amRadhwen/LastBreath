import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

class FileEncryptor:
    def __init__(self, password, salt=b''):
        self.password = password
        if not salt:
            self.salt = get_random_bytes(16)
        else:
            self.salt = salt

    def encrypt_file(self, input_file, output_file):
        key = PBKDF2(self.password, self.salt, dkLen=32, count=1000000)
        cipher = AES.new(key, AES.MODE_EAX)
        with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
            data = infile.read()
            ciphertext, tag = cipher.encrypt_and_digest(data)
            outfile.write(cipher.nonce)
            outfile.write(tag)
            outfile.write(ciphertext)

    def decrypt_file(self, input_file, output_file):
        key = PBKDF2(self.password, self.salt, dkLen=32, count=1000000)
        with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
            nonce = infile.read(16)
            tag = infile.read(16)
            ciphertext = infile.read()
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            outfile.write(data)

    def encrypt_folder(self, folder_path):
        for root, dirs, files in os.walk(folder_path):
            for filename in files:
                input_file = os.path.join(root, filename)
                output_file = os.path.join(root, filename + '.enc')
                self.encrypt_file(input_file, output_file)
                os.remove(input_file)

    def decrypt_folder(self, folder_path):
        for root, dirs, files in os.walk(folder_path):
            for filename in files:
                if filename.endswith('.enc'):
                    input_file = os.path.join(root, filename)
                    output_file = os.path.join(root, filename[:-4])
                    self.decrypt_file(input_file, output_file)
                    os.remove(input_file)