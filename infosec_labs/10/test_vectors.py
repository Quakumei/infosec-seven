
from typing import List

from pydantic import BaseModel

from utils import read_file
from aes_eax_192 import encrypt, decrypt

class EAXTestVector(BaseModel):
    message: bytes
    key: bytes
    nonce: bytes
    auth_data: bytes
    cipher: bytes

    def test(self):
        encrypted_message = encrypt(self.message, self.key, self.nonce, self.auth_data)
        assert encrypted_message == self.cipher
        decrypted_message = decrypt(encrypted_message, self.key, self.nonce, self.auth_data)
        assert decrypted_message == encrypted_message

def parse_test_vector(lines: list[str]) -> EAXTestVector:
    assert len(lines) == 5
    keys = [
        "MSG",
        "KEY",
        "NONCE",
        "HEADER",
        "CIPHER",
    ]
    d = {}
    for line_i, k in enumerate(keys):
        assert lines[line_i].startswith(k)
        d[k] = lines[line_i].split(":")[1].strip()
    return EAXTestVector(
        message=bytes.fromhex(d[keys[0]]),
        key=bytes.fromhex(d[keys[1]]),
        nonce=bytes.fromhex(d[keys[2]]),
        auth_data=bytes.fromhex(d[keys[3]]),
        cipher=bytes.fromhex(d[keys[4]])
    )

def parse_test_vectors(content: str) -> List[EAXTestVector]:
    lines = list(filter(lambda x: x != '', map(str.strip, content.split('\n'))))
    test_vectors = []
    while lines:
        test_vector_data = lines[:5]
        test_vector = parse_test_vector(test_vector_data)
        test_vectors.append(test_vector)
        lines = lines[5:]
    return test_vectors

def test_vectors():
    # Source: https://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf
    # NOTE: those are for 128 bit key
    test_vectors_file = 'data/aes_test_vectors.txt'
    test_vectors_content = read_file(test_vectors_file).decode('utf-8')
    test_vectors = parse_test_vectors(test_vectors_content)

    for test_vector in test_vectors:
        test_vector.test()