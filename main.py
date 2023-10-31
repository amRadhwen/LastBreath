from FileEncryptor import FileEncryptor
from Enctryptor import Encryptor

# Usage example:
password = "thisismysecretpassword"
salt = b'thisismysecretsalt'  # You can specify your own salt or leave it empty for a random salt
encryptor = FileEncryptor(password, salt)
folder_to_encrypt = "encryptme"

# To encrypt files in the folder
#encryptor.encrypt_folder(folder_to_encrypt)

# To decrypt files in the folder
#encryptor.decrypt_folder(folder_to_encrypt)


# Example usage (class Encryptor that combines symmetric and asymmetric encryption): 
public_key_path = 'public_key.pem'
private_key_path = 'private_key.pem'

encryptor = Encryptor(public_key_path, private_key_path)
encryptor.encrypt_folder(folder_to_encrypt)
#encryptor.decrypt_folder(folder_to_encrypt)

