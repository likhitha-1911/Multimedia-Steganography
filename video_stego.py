import numpy as np
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from base64 import b64encode, b64decode
import struct

VALID_METHODS = ['AES', 'DES', 'RSA', 'ECC']

def generate_key_pair(method, key_size=2048):
    """Generate key pairs for RSA or ECC"""
    if method == 'RSA':
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
    elif method == 'ECC':
        key = ECC.generate(curve='P-256')
        private_key = key.export_key(format='PEM')
        public_key = key.public_key().export_key(format='PEM')
    else:
        raise ValueError("Key generation only supported for RSA and ECC")
    return private_key, public_key

def encrypt_message(message, key, method):
    if method == 'AES':
        cipher = AES.new(key.ljust(16)[:16].encode(), AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())
        return b64encode(cipher.nonce + tag + ciphertext).decode()
    
    elif method == 'DES':
        cipher = DES.new(key.ljust(8)[:8].encode(), DES.MODE_ECB)
        padded_msg = message + (8 - len(message) % 8) * chr(8 - len(message) % 8)
        return b64encode(cipher.encrypt(padded_msg.encode())).decode()
    
    elif method == 'RSA':
        if isinstance(key, str):
            key = RSA.import_key(key)
        cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
        encrypted = cipher.encrypt(message.encode())
        return b64encode(encrypted).decode()
    
    elif method == 'ECC':
        if isinstance(key, str):
            key = ECC.import_key(key)
        cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
        encrypted = cipher.encrypt(message.encode())
        return b64encode(encrypted).decode()
    
    else:
        raise ValueError("Invalid encryption method")

def decrypt_message(encrypted_message, key, method):
    try:
        if method == 'AES':
            key = key.ljust(16)[:16].encode()
            raw = b64decode(encrypted_message)
            if len(raw) < 32:
                return "Invalid message: too short for AES components"
            nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag).decode()
        
        elif method == 'DES':
            key = key.ljust(8)[:8].encode()
            cipher = DES.new(key, DES.MODE_ECB)
            decrypted = cipher.decrypt(b64decode(encrypted_message)).decode()
            pad_len = ord(decrypted[-1])
            return decrypted[:-pad_len]
        
        elif method == 'RSA':
            if isinstance(key, str):
                key = RSA.import_key(key)
            cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
            return cipher.decrypt(b64decode(encrypted_message)).decode()
        
        elif method == 'ECC':
            if isinstance(key, str):
                key = ECC.import_key(key)
            cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
            return cipher.decrypt(b64decode(encrypted_message)).decode()
        
        else:
            return f"Unsupported method: {method}"
            
    except ValueError as e:
        return f"Key error: {str(e)}"
    except Exception as e:
        return f"Decryption failed: {str(e)}"

def encode_video(video_path, message, key, method, stego_path):
    encrypted_msg = encrypt_message(message, key, method)
    with open(video_path, 'rb') as video:
        video_bytes = bytearray(video.read())

    # Convert message to bits with length prefix and EOF marker
    msg_len = len(encrypted_msg)
    message_bits = format(msg_len, '032b')  # 4-byte length prefix
    message_bits += ''.join(format(ord(i), '08b') for i in encrypted_msg)
    message_bits += '1111111111111110'  # EOF marker

    if len(message_bits) > len(video_bytes):
        raise ValueError(f"Message too large (needs {len(message_bits)} bits, video has {len(video_bytes)} bytes)")

    for i in range(len(message_bits)):
        video_bytes[i] = (video_bytes[i] & 254) | int(message_bits[i])

    with open(stego_path, 'wb') as modified_video:
        modified_video.write(bytes(video_bytes))
    return encrypted_msg

def decode_video(stego_video_path, key, method=None):
    try:
        with open(stego_video_path, 'rb') as f:
            video_bytes = bytearray(f.read())
        
        # Extract LSBs
        message_bits = ''.join([str(byte & 1) for byte in video_bytes])
        
        # Read length prefix (first 32 bits)
        if len(message_bits) < 32:
            return "Invalid message: too short for length prefix"
        
        msg_len = int(message_bits[:32], 2)
        message_bits = message_bits[32:]
        
        # Find EOF marker
        eof_marker = '1111111111111110'
        eof_pos = message_bits.find(eof_marker)
        
        if eof_pos == -1 or eof_pos < msg_len * 8:
            return "No valid EOF marker found"
            
        # Extract the message
        message_bits = message_bits[:msg_len*8]
        message = ''.join([chr(int(message_bits[i:i+8], 2)) for i in range(0, len(message_bits), 8)])
        
        if method:
            result = decrypt_message(message, key, method)
            if not any(result.startswith(e) for e in ["Decryption failed", "Key error", "Unsupported method"]):
                return result
            return f"Failed with {method}: {result}"
        else:
            for method in VALID_METHODS:
                result = decrypt_message(message, key, method)
                if not any(result.startswith(e) for e in ["Decryption failed", "Key error", "Unsupported method"]):
                    return result
            return "Auto-decryption failed with all methods"
            
    except Exception as e:
        return f"Video processing error: {str(e)}"