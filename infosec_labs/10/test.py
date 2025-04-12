import os
from Crypto.Cipher import AES

from .aes_eax_192 import encrypt, decrypt

def test_aes_eax():
    key = b"YELLOW SUBMARINEYELLOW SUBMARINE"  # AES key (16 bytes for AES-128)
    nonce = os.urandom(8)  # 8-byte nonce
    associated_data = b"Associated Data"
    plaintext = b"This is a test message."


    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    orig_ciphertext, orig_tag = cipher.encrypt_and_digest(plaintext)

    my_ciphertext, my_tag = encrypt()

    decipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    try:
        decrypted_text = decipher.decrypt_and_verify(orig_ciphertext, orig_tag)
        print("Decrypted text:", decrypted_text)
    except ValueError:
        print("Key incorrect or message corrupted")