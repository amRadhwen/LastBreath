from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import os

class Encryptor:
    def __init__(self, keys_dir="keys"):
        self.keys_dir = keys_dir
        self.private_key_path = os.path.join(keys_dir, "private_key.pem")
        self.public_key_path = os.path.join(keys_dir, "public_key.pem")

    def generate_key_pair(self):
        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)
        
        if not os.path.exists(self.private_key_path) or not os.path.exists(self.public_key_path):
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()
            
            if not os.path.exists(self.private_key_path):
                with open(self.private_key_path, "wb") as private_key_file:
                    private_key_file.write(private_key)
                
            if not os.path.exists(self.public_key_path):
                with open(self.public_key_path, "wb") as public_key_file:
                    public_key_file.write(public_key)

    def encrypt_file(self, input_file):
        filename, ext = os.path.splitext(os.path.basename(input_file))
        encrypted_file_name = f"{filename}{ext}.xv"

        # Generate a random AES encryption key
        aes_key = os.urandom(32)
        aes_cipher = AES.new(aes_key, AES.MODE_EAX)

        with open(input_file, "rb") as file:
            plaintext = file.read()

        ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext)

        # Encrypt the AES key with the recipient's public key (asymmetric encryption)
        with open(self.public_key_path, "rb") as public_key_file:
            recipient_key = RSA.import_key(public_key_file.read())
            rsa_cipher = PKCS1_OAEP.new(recipient_key)
            encrypted_aes_key = rsa_cipher.encrypt(aes_key)

        output_dir = os.path.dirname(input_file)
        encrypted_file_path = os.path.join(output_dir, encrypted_file_name)

        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_aes_key)
            encrypted_file.write(aes_cipher.nonce)
            encrypted_file.write(ciphertext)
            encrypted_file.write(tag)

        os.remove(input_file)

    def encrypt_files_in_folder(self, folder_path):
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                self.encrypt_file(file_path)
