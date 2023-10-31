from Crypto.Random import get_random_bytes

import FileEncryptor

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