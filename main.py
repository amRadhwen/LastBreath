from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


data = open("encryptme.txt", "wb")


key = get_random_bytes(16)

cipher = AES.new(key, AES.MODE_EAX)
cipher_text, tag = cipher.encrypt_and_digest(data)

file_out = open("encrypted.bin", "wb")
[ file_out.write(x) for x in  (cipher.nonce, tag, cipher_text) ]
file_out.close()