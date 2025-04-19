import os
from pathlib import Path
import traceback

from Crypto.Random import get_random_bytes
from grasshopper import encrypt, decrypt

def get_encryption_data(log=False):
    encryption_data = {
        "key": get_random_bytes(256 // 8), # 32 bytes
        "block_size": 16
    }
    if log:
        print(encryption_data)
    return encryption_data

def test_text(text: str):
    encryption_data = get_encryption_data(log=False)
    encrypted, decryption_data = encrypt(text.encode('utf-8'), encryption_data["key"], encryption_data["block_size"])
    # encrypted, _ =  encrypt((text+'kek').encode('utf-8'), encryption_data["key"], encryption_data["block_size"])
    decryption_data.update(encryption_data)
    decrypted: bytes = decrypt(encrypted, decryption_data)
    decrypted_text: str = decrypted.decode('utf-8')

    assert text == decrypted_text, f'{text} != {decrypted_text}'


def cypher_file(path: str | Path, output_path: str | Path, overwrite: bool = True, save_p1p2=True):
    path = Path(path)
    output_path = Path(output_path)
    if not path.exists():
        raise FileNotFoundError()
    if output_path.exists() and not overwrite:
        raise FileExistsError()
    elif output_path.exists():
        os.unlink(str(output_path))
    with open(path, 'rb') as f:
        content = f.read()

    encryption_data = get_encryption_data(log=False)
    encrypted_content, decryption_data = encrypt(content, encryption_data['key'], encryption_data['block_size'])
    with open(output_path, "wb") as f:
        f.write(encrypted_content)
        print(f"Wrote file {output_path}")

    if save_p1p2:
        p1p2_file = str(output_path)+'.pi01'
        with open(p1p2_file, "w") as f:
            f.write(f"{' '.join(map(str, decryption_data['pi_0'].values()))}\n{' '.join(map(str, decryption_data['pi_1'].values()))}")
            print(f"Wrote file {str(p1p2_file)}")
    decryption_data.update(encryption_data)
    decrypted_content = decrypt(encrypted_content, decryption_data)

    assert decrypted_content == content

def main():
    # Some text tests
    try:
        test_text("1234567890_")
        test_text("1234567890_" * 10)
        test_text("1234567890_" * 7)
        print("✅ Text Checks passed")
    except AssertionError:
        print(f"❌ Text Checks failed \n{traceback.format_exc()}")

    # Encrypt/decrypt file
    try:
        cypher_file("infosec_labs/11/mit.txt", "infosec_labs/11/mit_encrypted.txt", save_p1p2=True)
        print("✅ File Encryption Checks passed")
    except AssertionError:
        print(f"❌ File Encryption Checks failed \n{traceback.format_exc()}")

if __name__=='__main__':
    # Вар 17 Полином - | **0x187** | x⁸ + x⁷ + x² + x + 1|, размер блока 16 байт
    main()