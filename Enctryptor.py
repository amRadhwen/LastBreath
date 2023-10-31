import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

class Encryptor:
    def __init__(self, public_key_path, private_key_path):
        self.public_key_path = public_key_path
        self.private_key_path = private_key_path
        self.public_key = self.load_public_key(public_key_path)
        self.private_key = self.load_private_key(private_key_path)
        self.symmetric_key = None

    def generate_public_key(self, key_size=2048):
        key = RSA.generate(key_size)
        with open(self.public_key_path, 'wb') as f:
            f.write(key.publickey().export_key())

    def generate_private_key(self, key_size=2048):
        key = RSA.generate(key_size)
        with open(self.private_key_path, 'wb') as f:
            f.write(key.export_key())

    def load_public_key(self, public_key_path):
        if os.path.exists(public_key_path):
            with open(public_key_path, 'rb') as f:
                return RSA.import_key(f.read())
        else:
            print(f"Public key file not found at {public_key_path}. Generating a new one...")
            self.generate_public_key()
            return self.load_public_key(public_key_path)

    def load_private_key(self, private_key_path):
        if os.path.exists(private_key_path):
            with open(private_key_path, 'rb') as f:
                return RSA.import_key(f.read())
        else:
            print(f"Private key file not found at {private_key_path}. Generating a new one...")
            self.generate_private_key()
            return self.load_private_key(private_key_path)

    def generate_symmetric_key(self):
        self.symmetric_key = get_random_bytes(32)

    def encrypt_file(self, input_file):
        with open(input_file, 'rb') as f:
            data = f.read()
        
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        self.generate_symmetric_key()
        enc_symmetric_key = cipher_rsa.encrypt(self.symmetric_key)
        cipher_aes = AES.new(self.symmetric_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        # Change the file extension to .xvxv
        output_file = os.path.splitext(input_file)[0] + '.xvxv'

        with open(output_file, 'wb') as f:
            for x in (enc_symmetric_key, cipher_aes.nonce, tag, ciphertext):
                f.write(x)

    def decrypt_file(self, input_file):
        with open(input_file, 'rb') as f:
            enc_symmetric_key, nonce, tag, ciphertext = [f.read(x) for x in (self.public_key.size_in_bytes(), 16, 16, -1)]
        
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        symmetric_key = cipher_rsa.decrypt(enc_symmetric_key)
        cipher_aes = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)

        # Change the file extension to the original extension
        input_filename, _ = os.path.splitext(input_file)
        output_file = input_filename + '.original'

        with open(output_file, 'wb') as f:
            f.write(data)

    def encrypt_folder(self, input_folder):
        for root, dirs, files in os.walk(input_folder):
            for file in files:
                input_file_path = os.path.join(root, file)
                self.encrypt_file(input_file_path)
                os.remove(input_file_path)  # Remove the original file

    def decrypt_folder(self, input_folder):
        for root, dirs, files in os.walk(input_folder):
            for file in files:
                input_file_path = os.path.join(root, file)
                self.decrypt_file(input_file_path)
                os.remove(input_file_path)  # Remove the encrypted file

# Example usage:
public_key_path = 'public_key.pem'
private_key_path = 'private_key.pem'

encryptor = Encryptor(public_key_path, private_key_path)
encryptor.encrypt_folder('input_folder')
encryptor.decrypt_folder('input_folder')
