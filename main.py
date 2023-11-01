from FileEncryptor import FileEncryptor
from Enctryptor import Encryptor

# Usage example:
#password = "thisismysecretpassword"
#salt = b'thisismysecretsalt'  # You can specify your own salt or leave it empty for a random salt
#encryptor = FileEncryptor(password, salt)
#folder_to_encrypt = "encryptme"

# To encrypt files in the folder
#encryptor.encrypt_folder(folder_to_encrypt)

# To decrypt files in the folder
#encryptor.decrypt_folder(folder_to_encrypt)

if __name__ == "__main__":
    private_key_path = 'private_key.pem'
    public_key_path = 'public_key.pem'
    folder_path = 'encryptme'

    encryptor = Encryptor(private_key_path, public_key_path)
    encryptor.encrypt_files_in_folder(folder_path)
    # To decrypt, use: encryptor.decrypt_files_in_folder(folder_path)


