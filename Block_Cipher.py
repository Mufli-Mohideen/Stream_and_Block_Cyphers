import secrets
import base64

BLOCK_SIZE = 8  # 8 bytes = 64 bits

# Padding to ensure all blocks are the correct size
def pad(plaintext):
    padding_needed = BLOCK_SIZE - (len(plaintext) % BLOCK_SIZE)
    return plaintext + (bytes([padding_needed]) * padding_needed)  # PKCS#7 padding

def unpad(padded_plaintext):
    padding_len = padded_plaintext[-1]
    return padded_plaintext[:-padding_len]

# Simple substitution table (byte-level)
def substitute(block):
    return bytes([(b + 3) % 256 for b in block])

# Reverse substitution table (subtract 3 instead of adding)
def reverse_substitute(block):
    return bytes([(b - 3) % 256 for b in block])

# Simple permutation (reverse the block)
def permute(block):
    return block[::-1]

# XOR block with key
def xor_block(block, key):
    return bytes([b ^ k for b, k in zip(block, key)])

# Encrypt a single block
def encrypt_block(block, key, rounds=5):
    for _ in range(rounds):
        block = substitute(block)
        block = permute(block)
        block = xor_block(block, key)
    return block

# Decrypt a single block
def decrypt_block(block, key, rounds=5):
    for _ in range(rounds):
        block = xor_block(block, key)
        block = permute(block)  # Reverse permutation
        block = reverse_substitute(block)  # Reverse substitution
    return block

# CBC Mode: Encrypting the entire message
def encrypt_cbc(plaintext, key, iv, rounds=5):
    padded_plaintext = pad(plaintext)
    blocks = [padded_plaintext[i:i + BLOCK_SIZE] for i in range(0, len(padded_plaintext), BLOCK_SIZE)]
    ciphertext_blocks = []
    previous_block = iv

    for block in blocks:
        block_to_encrypt = xor_block(block, previous_block)  # XOR with IV or previous ciphertext block
        encrypted_block = encrypt_block(block_to_encrypt, key, rounds)
        ciphertext_blocks.append(encrypted_block)
        previous_block = encrypted_block

    return b''.join(ciphertext_blocks)

# CBC Mode: Decrypting the entire message
def decrypt_cbc(ciphertext, key, iv, rounds=5):
    blocks = [ciphertext[i:i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    plaintext_blocks = []
    previous_block = iv

    for block in blocks:
        decrypted_block = decrypt_block(block, key, rounds)
        plaintext_block = xor_block(decrypted_block, previous_block)
        plaintext_blocks.append(plaintext_block)
        previous_block = block

    decrypted_plaintext = b''.join(plaintext_blocks)
    return unpad(decrypted_plaintext)

# Example usage
key = secrets.token_bytes(BLOCK_SIZE)  # Generate a random 8-byte key
iv = secrets.token_bytes(BLOCK_SIZE)  # Random IV

message = b"Exams are on red USB drive in JO 18.103. Password is CaKe314."  # Use byte-level data

# Encrypt the message
ciphertext = encrypt_cbc(message, key, iv)

# Encode the ciphertext to base64 to avoid issues with non-printable characters
ciphertext_base64 = base64.b64encode(ciphertext).decode('utf-8')
print("Ciphertext (Base64):", ciphertext_base64)

# Decrypt the message
ciphertext_bytes = base64.b64decode(ciphertext_base64)
decrypted_message = decrypt_cbc(ciphertext_bytes, key, iv)

try:
    # Attempt to decode the decrypted message
    print("Decrypted message:", decrypted_message.decode('utf-8'))
except UnicodeDecodeError:
    # Print raw decrypted bytes if decoding fails
    print("Decrypted message (raw bytes):", decrypted_message)
