import wave
import numpy as np
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
from ecies.utils import generate_eth_key
from ecies import encrypt as ecc_encrypt, decrypt as ecc_decrypt

# ------------------ Encryption ------------------ #
def encrypt_message(message, key, method):
    if method == 'AES':
        cipher = AES.new(key.ljust(16)[:16].encode(), AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())
        return b64encode(cipher.nonce + tag + ciphertext).decode()
    
    elif method == 'DES':
        cipher = DES.new(key.ljust(8)[:8].encode(), DES.MODE_ECB)
        padded_msg = pad(message.encode(), DES.block_size)
        return b64encode(cipher.encrypt(padded_msg)).decode()
    
    elif method == 'RSA':
        rsa_key = RSA.generate(2048)
        cipher = PKCS1_OAEP.new(rsa_key.publickey())
        encrypted_msg = cipher.encrypt(message.encode())
        return b64encode(encrypted_msg).decode() + "::" + rsa_key.export_key().decode()
    
    elif method == 'ECC':
        eth_key = generate_eth_key()
        pub_key = eth_key.public_key.to_hex()
        encrypted = ecc_encrypt(pub_key, message.encode())
        return b64encode(encrypted).decode() + "::" + eth_key.to_hex()

    else:
        raise ValueError("Invalid encryption method.")

# ------------------ Decryption ------------------ #
def decrypt_message(encrypted_message, key, method):
    try:
        if method == 'AES':
            raw = b64decode(encrypted_message)
            nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
            cipher = AES.new(key.ljust(16)[:16].encode(), AES.MODE_EAX, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag).decode()
        
        elif method == 'DES':
            cipher = DES.new(key.ljust(8)[:8].encode(), DES.MODE_ECB)
            decrypted = unpad(cipher.decrypt(b64decode(encrypted_message)), DES.block_size)
            return decrypted.decode()
        
        elif method == 'RSA':
            enc_msg, priv_key_str = encrypted_message.split("::")
            rsa_key = RSA.import_key(priv_key_str.encode())
            cipher = PKCS1_OAEP.new(rsa_key)
            return cipher.decrypt(b64decode(enc_msg)).decode()
        
        elif method == 'ECC':
            enc_msg, priv_hex = encrypted_message.split("::")
            decrypted = ecc_decrypt(priv_hex, b64decode(enc_msg))
            return decrypted.decode()

        else:
            raise ValueError("Invalid decryption method.")
    
    except Exception as e:
        return f"Error decrypting: {str(e)}"

# ------------------ Audio Encoding ------------------ #
def encode_audio(audio_path, message, key, method, stego_path):
    encrypted_msg = encrypt_message(message, key, method)
    audio = wave.open(audio_path, mode='rb')
    frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))

    message_bits = ''.join(format(ord(i), '08b') for i in encrypted_msg)
    eof_marker = '1111111111111110'
    message_bits += eof_marker

    if len(message_bits) > len(frame_bytes):
        raise ValueError("Message too large to hide in audio")

    for i in range(len(message_bits)):
        frame_bytes[i] = (frame_bytes[i] & 254) | int(message_bits[i])

    modified_audio = wave.open(stego_path, 'wb')
    modified_audio.setparams(audio.getparams())
    modified_audio.writeframes(bytes(frame_bytes))

    audio.close()
    modified_audio.close()

    return encrypted_msg

# ------------------ Audio Decoding ------------------ #
def decode_audio(stego_audio_path, key, method):
    audio = wave.open(stego_audio_path, mode='rb')
    frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))
    extracted_bits = [frame_bytes[i] & 1 for i in range(len(frame_bytes))]

    bits_str = ''.join(map(str, extracted_bits))
    eof_index = bits_str.find('1111111111111110')
    if eof_index == -1:
        raise ValueError("EOF marker not found. Extraction failed.")

    message_bits = bits_str[:eof_index]
    decoded_chars = [chr(int(message_bits[i:i+8], 2)) for i in range(0, len(message_bits), 8)]
    encrypted_message = ''.join(decoded_chars)

    decrypted = decrypt_message(encrypted_message, key, method)
    audio.close()
    return decrypted
