import hashlib
import random
import typing as tp


BLOCK_SIZE = 16 # bytes
GF_MOD = 0x187 # Полином x⁸ + x⁷ + x² + x + 1, Поле Галуа

def gf_mult(a: bytes, b: bytes, mod=GF_MOD) -> bytes:
    a_len = len(a)
    b = int.from_bytes(b, 'big')
    a = int.from_bytes(a, 'big')
    running_sum = 0
    for bit_i in range(8): # итерируемся по b
        if b & 0x01: # Если надо добавим разряд (1)
            running_sum ^= a
        a <<= 1 # После умножения следующее будет больше
        if a & 0x100: # Если вышли за пределы т.е. больше 1 байта стали
            a ^= mod # Делим по модулю, в поле галуа это + = -
        b >>= 1 # И идём дальше пока у нас b не будет из нулей полностью в итоге
    return (running_sum & 0xFF).to_bytes(a_len, 'big') # интересуют только последние 8 бит

def generate_s_blocks(key) -> tuple[list[int], list[int]]:
    seed = int.from_bytes(hashlib.sha256(key).digest(), 'big') # TODO: recheck
    random.seed(seed)

    # Случайная перестановка
    idx = list(range(256))
    random.shuffle(idx)
    s_block = {i: v for i, v in enumerate(idx)}
    reverse_s_block = {v:k for k, v in s_block.items()}

    return s_block, reverse_s_block

def xor_bytes(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))

def R(block: bytes, const_byte: bytes):
    # shift right + xor
    if len(const_byte) == len(block) // 2:
        const_byte += const_byte
    shift = block[-1:] + block[:-1]
    result = xor_bytes(shift, const_byte)
    assert block == inverse_R(result, const_byte)
    return result

def L(block: bytes):
    const = int(0x01).to_bytes(8, "big")
    factor = int(0x02).to_bytes(8, "big")
    for _ in range(4):
        block = R(block, const)
        const = gf_mult(const, factor)
    return block

def inverse_R(block: bytes, const_byte: bytes):
    # xor + shift left
    if len(const_byte) == len(block) // 2:
        const_byte += const_byte
    block = xor_bytes(block, const_byte)
    return block[1:] + block[:1]

def inverse_L(block):
    consts = [0x01, 0x02, 0x04, 0x08]
    consts = list(map(lambda x: x.to_bytes(8, 'big'), consts))
    for c in reversed(consts):
        block = inverse_R(block, c)
    return block

def generate_round_keys(start_key, pi_0):
    """
        Первые два раундовых ключа получаются путём
    разбиения первичного ключа на две равные части K1 , K 2 . Дальнейшие пары генерируются с
    помощью применения восьми итераций сети Фейстеля, где для каждой итерации
    используется константа, вычисляемая путём применения линейного преобразования к
    номеру итерации.
    """

    assert len(start_key) % 2 == 0
    k1 = start_key[:len(start_key) // 2]
    k2 = start_key[len(start_key) // 2:]
    keys = [k1, k2]
    for i in range(8):
        i_val = int(i).to_bytes(8, 'big')
        const_byte = L(i_val)

        l_prev = keys[-2]
        r_prev = keys[-1]

        r_prev = bytes([pi_0[b] for b in r_prev])
        f_r_prev = gf_mult(r_prev, const_byte)
        new_k = xor_bytes(f_r_prev, l_prev)
        keys.append(new_k)

    assert len(keys) == 10
    return keys

def encrypt_block(block, round_keys: list[bytes], pi_0):
    assert len(block) == BLOCK_SIZE
    assert len(round_keys) == 10
    block = block
    for key in round_keys[:-1]:
        block = xor_bytes(block, key)
        block = bytes(pi_0[b] for b in block)  # S-преобразование
        block = L(block)
    block = xor_bytes(block, round_keys[-1])
    return block

def decrypt_block(block, round_keys: list[bytes], pi_1):
    assert len(block) == BLOCK_SIZE
    assert len(round_keys) == 10
    block = xor_bytes(block, round_keys[-1])
    for key in round_keys[:-1][::-1]:
        block = inverse_L(block)
        block = bytes(pi_1[b] for b in block)
        block = xor_bytes(block, key)
    return block

def pkcs7_pad(data, block_size):
    # PKCS#7
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]*pad_len)

def pkcs7_unpad(data):
    # PKCS#7
    pad_len = data[-1]
    if pad_len < 1 or pad_len > len(data):
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def collect_blocks(blocks: tp.Iterable[bytes]) -> bytes:
    result = bytearray()
    for block in blocks:
        result.extend(block)
    return bytes(result)


def encrypt(data: bytes, start_key: bytes, block_size: int = BLOCK_SIZE) -> tp.Tuple[bytes, dict[str, tp.Any]]:
    pi_0, pi_1 = generate_s_blocks(start_key)
    decryption_data = {"pi_0": pi_0, "pi_1": pi_1, "key": start_key, "block_size": block_size}
    data = pkcs7_pad(data, block_size)
    split_blocks = (
        data[i:i+block_size]
        for i in range(0, len(data), block_size)
    )
    split_blocks = list(split_blocks)
    round_keys = generate_round_keys(start_key, pi_0)
    encrypted_blocks = map(lambda b: encrypt_block(b, round_keys, pi_0), split_blocks)

    return  collect_blocks(encrypted_blocks), decryption_data

def decrypt(data: bytes, decryption_data: dict[str, int]) -> bytes:
    pi_0 = decryption_data['pi_0']
    pi_1 = decryption_data['pi_1']
    start_key =  decryption_data['key']
    block_size = decryption_data['block_size']
    round_keys = generate_round_keys(start_key, pi_0)
    split_blocks = (
        data[i:i+block_size]
        for i in range(0, len(data), block_size)
    )
    decrypted_blocks = map(lambda eb: decrypt_block(eb, round_keys, pi_1), split_blocks)
    decrypted_collect = collect_blocks(decrypted_blocks)
    return pkcs7_unpad(decrypted_collect)



