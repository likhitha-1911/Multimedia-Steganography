from PIL import Image
import numpy as np
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from ecies import encrypt as ecc_encrypt, decrypt as ecc_decrypt
import base64

DELIMITER = '####'  # Unique delimiter to mark end of encrypted message

def encode_image(image_file, message, method, key, output_path):
    img = Image.open(image_file)
    img = img.convert("RGB")
    data = np.array(img, dtype=np.uint8)  # enforce uint8 here
    
    # Encryption
    if method == 'AES':
        cipher = AES.new(key.encode('utf-8').ljust(16, b'0'), AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
    elif method == 'DES':
        cipher = DES.new(key.encode('utf-8').ljust(8, b'0'), DES.MODE_ECB)
        encrypted = cipher.encrypt(pad(message.encode(), DES.block_size))
    elif method == 'RSA':
        try:
            pub_key = RSA.import_key(key.encode())
            cipher = PKCS1_OAEP.new(pub_key)
            encrypted = cipher.encrypt(message.encode())
        except Exception as e:
            raise ValueError(f"RSA Encryption failed: {e}")
    elif method == 'ECC':
        encrypted = ecc_encrypt(key, message.encode())
    else:
        raise ValueError("Unsupported encryption method")

    # Append delimiter after base64 encoding
    b64_encrypted = base64.b64encode(encrypted).decode() + DELIMITER

    bits = ''.join([format(ord(c), '08b') for c in b64_encrypted])
    assert set(bits).issubset({'0', '1'}), "Bits must only be 0 or 1"
    
    flat_data = data.flatten().astype(np.uint8)
    if len(bits) > flat_data.size:
        raise ValueError("Message too large for image")

    for i in range(len(bits)):
        flat_data[i] = (flat_data[i] & 0xFE) | int(bits[i])

    stego_data = flat_data.reshape(data.shape).astype(np.uint8)
    stego_img = Image.fromarray(stego_data)
    stego_img.save(output_path)

    return stego_img

def decode_image(image_file, method, key):
    img = Image.open(image_file)
    img = img.convert("RGB")
    data = np.array(img, dtype=np.uint8).flatten()

    bits = ''.join([str(pixel & 1) for pixel in data])
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            break
        chars.append(chr(int(byte, 2)))
    full_message = ''.join(chars)

    if DELIMITER not in full_message:
        raise ValueError("Delimiter not found; corrupted or incomplete data")

    b64_encrypted = full_message.split(DELIMITER)[0]

    try:
        encrypted = base64.b64decode(b64_encrypted)
    except Exception:
        raise ValueError("Decryption failed: Invalid base64 data")

    if method == 'AES':
        cipher = AES.new(key.encode('utf-8').ljust(16, b'0'), AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size).decode()
    elif method == 'DES':
        cipher = DES.new(key.encode('utf-8').ljust(8, b'0'), DES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(encrypted), DES.block_size).decode()
    elif method == 'RSA':
        try:
            private_key = RSA.import_key(key.encode())
            cipher = PKCS1_OAEP.new(private_key)
            decrypted = cipher.decrypt(encrypted).decode()
        except Exception as e:
            raise ValueError(f"RSA Decryption failed: {e}")
    elif method == 'ECC':
        decrypted = ecc_decrypt(key, encrypted).decode()
    else:
        raise ValueError("Unsupported decryption method")

    return decrypted
