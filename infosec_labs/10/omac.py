from Crypto.Cipher import AES


BLOCK_SIZE = 16
Rb = 0x87  # Константа для GF(2^128), используется при генерации сабключей


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def left_shift(b: bytes) -> bytes:
    shifted = int.from_bytes(b, "big") << 1
    if b[0] & 0x80:
        shifted ^= Rb
    return (shifted & ((1 << 128) - 1)).to_bytes(16, "big")


def pad(block: bytes) -> bytes:
    padding_len = BLOCK_SIZE - len(block)
    return block + b'\x80' + b'\x00' * (padding_len - 1)


def generate_subkeys(key: bytes) -> tuple[bytes, bytes]:
    zero_block = bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    L = cipher.encrypt(zero_block)

    K1 = left_shift(L)
    K2 = left_shift(K1)
    return K1, K2


def omac(key: bytes, message: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    K1, K2 = generate_subkeys(key)

    n_blocks = (len(message) + 15) // 16
    if n_blocks == 0:
        n_blocks = 1

    last_block_complete = len(message) % BLOCK_SIZE == 0 and len(message) != 0
    blocks = [message[i * 16:(i + 1) * 16] for i in range(n_blocks)]

    if last_block_complete:
        last_block = xor_bytes(blocks[-1], K1)
    else:
        last_block = xor_bytes(pad(blocks[-1]), K2)

    mac = bytes(16)
    for block in blocks[:-1]:
        mac = cipher.encrypt(xor_bytes(mac, block))

    tag = cipher.encrypt(xor_bytes(mac, last_block))
    return tag
