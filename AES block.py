from Crypto.Cipher import AES
import binascii

def xor_bytes(a, b):
    """XORs two byte strings together."""
    return bytes(x ^ y for x, y in zip(a, b))

def pkcs5_unpad(data):
    """Removes PKCS5/PKCS7 padding."""
    padding_len = data[-1]
    return data[:-padding_len]


def decrypt_cbc(key_hex, ct_hex):
    key = binascii.unhexlify(key_hex)
    ciphertext = binascii.unhexlify(ct_hex)
    
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    cipher = AES.new(key, AES.MODE_ECB)
    
    plaintext = b""
    previous_block = iv
    
    for i in range(0, len(actual_ciphertext), 16):
        block = actual_ciphertext[i:i+16]
    
        decrypted_block = cipher.decrypt(block)
        plaintext_block = xor_bytes(decrypted_block, previous_block)
        
        plaintext += plaintext_block
        previous_block = block
        
    return pkcs5_unpad(plaintext).decode('utf-8')

def decrypt_ctr(key_hex, ct_hex):
    key = binascii.unhexlify(key_hex)
    ciphertext = binascii.unhexlify(ct_hex)

    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    
    cipher = AES.new(key, AES.MODE_ECB)
    
    plaintext = b""
    
    counter_int = int.from_bytes(iv, byteorder='big')
  
    for i in range(0, len(actual_ciphertext), 16):
        block = actual_ciphertext[i:i+16]
  
        current_counter_bytes = counter_int.to_bytes(16, byteorder='big')
        keystream = cipher.encrypt(current_counter_bytes)
 
        plaintext_block = xor_bytes(block, keystream[:len(block)])
        
        plaintext += plaintext_block
        
        counter_int += 1
        
    return plaintext.decode('utf-8')

# --- Main Execution ---

# Question 1
q1_key = "140b41b22a29beb4061bda66b6747e14"
q1_ct  = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
print(f"Q1 Answer: {decrypt_cbc(q1_key, q1_ct)}")

# Question 2
q2_key = "140b41b22a29beb4061bda66b6747e14"
q2_ct  = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
print(f"Q2 Answer: {decrypt_cbc(q2_key, q2_ct)}")

# Question 3
q3_key = "36f18357be4dbd77f050515c73fcf9f2"
q3_ct  = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
print(f"Q3 Answer: {decrypt_ctr(q3_key, q3_ct)}")

# Question 4
q4_key = "36f18357be4dbd77f050515c73fcf9f2"
q4_ct  = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
print(f"Q4 Answer: {decrypt_ctr(q4_key, q4_ct)}")