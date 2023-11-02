
from Enctryptor import Encryptor

if __name__ == "__main__":
    input_folder = "encryptme"
    encryptor = Encryptor()
    encryptor.generate_key_pair()
    encryptor.encrypt_files_in_folder(input_folder)



