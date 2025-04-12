import os

from utils import read_file, write_file
from logger import logger
from aes_eax_192 import encrypt, decrypt

def example(message_filename: str = 'data/10_input.txt', encrypted_message_filename = 'logs/10_encrypted.txt', decrypted_message_filename = "logs/10_decrypted.txt"):
    # Define inputs
    key = os.urandom(24) # 192 bit
    nonce = os.urandom(16) # 64 bit
    auth_data = 'key:password'.encode("utf-8")
    message = read_file(message_filename)

    # Encrypt
    encrypted_message = encrypt(message, key, nonce, auth_data)
    logger.info(f"Encrypted message: {encrypted_message.hex()}")
    write_file(encrypted_message_filename, encrypted_message)

    # Decrypt
    encrypted_message = read_file(encrypted_message_filename)
    decrypted_message = decrypt(encrypted_message, key, nonce, auth_data)
    logger.info(f"Decrypted message:\n{decrypted_message.decode()}[END]")
    write_file(decrypted_message_filename, encrypted_message)

    # Validate
    assert message == decrypted_message, "Decrypted message does not match original."
    logger.info("Message decrypted correctly!")

if __name__=='__main__':
    logger.info("Variant: 17. AES-EAX 192 bit key")
    example()
    # test_vectors()