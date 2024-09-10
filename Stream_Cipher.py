import secrets

# Stream Cipher: XOR-based encryption
def generate_secure_keystream(length):
    return [secrets.randbits(8) for _ in range(length)]  # Generates secure 8-bit keystream

def xor_bytes(data, keystream):
    return bytes([b ^ k for b, k in zip(data, keystream)])

def encrypt_stream_cipher(plaintext):
    plaintext_bytes = plaintext.encode('utf-8')  # Convert to bytes for XOR operation
    keystream = generate_secure_keystream(len(plaintext_bytes))
    ciphertext = xor_bytes(plaintext_bytes, keystream)
    return ciphertext, keystream

def decrypt_stream_cipher(ciphertext, keystream):
    decrypted_bytes = xor_bytes(ciphertext, keystream)
    return decrypted_bytes.decode('utf-8')  # Convert back to string

# Example usage
message = "Exams are on red USB drive in JO 18.103. Password is CaKe314."
ciphertext, keystream = encrypt_stream_cipher(message)
print("Ciphertext:", ciphertext)
decrypted_message = decrypt_stream_cipher(ciphertext, keystream)
print("Decrypted message:", decrypted_message)

