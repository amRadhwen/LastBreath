import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class FileEncryptor:
    def __init__(self, key):
        self.key = key

    def encrypt_file(self, input_file, output_file):
        cipher = AES.new(self.key, AES.MODE_EAX)
        with open(input_file, 'rb') as file_in:
            plaintext = file_in.read()
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        with open(output_file, 'wb') as file_out:
            [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]

    def encrypt_folder(self, input_folder):
        for root, dirs, files in os.walk(input_folder):
            for file in files:
                input_file = os.path.join(root, file)
                output_file = input_file + '.enc'
                self.encrypt_file(input_file, output_file)
                os.remove(input_file)

if __name__ == "__main__":
    key = get_random_bytes(32)  # 256-bit key
    encryptor = FileEncryptor(key)

    # Encrypt a single file
    input_file = 'your_file_to_encrypt.txt'
    output_file = 'encrypted_file.enc'
    encryptor.encrypt_file(input_file, output_file)

    # Encrypt a folder
    input_folder = 'your_folder_to_encrypt'
    encryptor.encrypt_folder(input_folder)
