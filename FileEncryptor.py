import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

class FileEncryptor:
    def __init__(self, recipient_public_key_file, sender_private_key_file, output_dir):
        self.recipient_public_key_file = recipient_public_key_file
        self.sender_private_key_file = sender_private_key_file
        self.output_dir = output_dir

    def generate_aes_key(self):
        return get_random_bytes(32)  # 256-bit key

    def encrypt_file(self, input_file, aes_key):
        # Generate an AES cipher with the key
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)

        # Encrypt the file using AES
        with open(input_file, 'rb') as f:
            plaintext = f.read()
            ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

        # Write the encrypted data to a file
        encrypted_file = os.path.join(self.output_dir, os.path.basename(input_file) + ".enc")
        with open(encrypted_file, 'wb') as f:
            [f.write(x) for x in (cipher_aes.nonce, tag, ciphertext)]

    def encrypt_directory(self, directory):
        # Load recipient's public key
        with open(self.recipient_public_key_file, 'rb') as f:
            recipient_key = RSA.import_key(f.read())

        # Load sender's private key
        with open(self.sender_private_key_file, 'rb') as f:
            sender_key = RSA.import_key(f.read())

        # Iterate through files in the directory
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)

                # Generate a new AES key for each file
                aes_key = self.generate_aes_key()

                # Encrypt the file using AES
                self.encrypt_file(file_path, aes_key)

                # Encrypt the AES key with the recipient's public key
                cipher_rsa = PKCS1_OAEP.new(recipient_key)
                enc_aes_key = cipher_rsa.encrypt(aes_key)

                # Save the encrypted AES key to a file
                key_file = os.path.join(self.output_dir, os.path.basename(file_path) + ".key.enc")
                with open(key_file, 'wb') as f:
                    f.write(enc_aes_key)

    def decrypt_file(self, encrypted_file, key_file, output_dir):
        # Load recipient's private key
        with open(self.sender_private_key_file, 'rb') as f:
            sender_key = RSA.import_key(f.read())

        # Decrypt the AES key using the recipient's private key
        with open(key_file, 'rb') as f:
            enc_aes_key = f.read()
            cipher_rsa = PKCS1_OAEP.new(sender_key)
            aes_key = cipher_rsa.decrypt(enc_aes_key)

        # Decrypt the file using the AES key
        with open(encrypted_file, 'rb') as f:
            nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
            cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

        # Write the decrypted data to a file
        decrypted_file = os.path.join(output_dir, os.path.basename(encrypted_file)[:-4])
        with open(decrypted_file, 'wb') as f:
            f.write(plaintext)

    def decrypt_directory(self, directory):
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".enc"):
                    encrypted_file = os.path.join(root, file)
                    key_file = os.path.join(root, file[:-4] + ".key.enc")
                    self.decrypt_file(encrypted_file, key_file, self.output_dir)

if __name__ == "__main__":
    recipient_public_key_file = "recipient_public_key.pem"  # Replace with the recipient's public key
    sender_private_key_file = "sender_private_key.pem"  # Replace with the sender's private key
    output_directory = "decrypted_files"  # Replace with the output directory

    encryptor = Encryptor(recipient_public_key_file, sender_private_key_file, output_directory)
    source_directory = "source_directory"  # Replace with the directory containing files to be encrypted
    encryptor.encrypt_directory(source_directory)
    encryptor.decrypt_directory(output_directory)