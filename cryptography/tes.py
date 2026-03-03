from attacks.single_xor import single_xor_encrypt, single_xor_decrypt

plaintext = b"attack at dawn"
key = 42
ciphertext = single_xor_encrypt(plaintext, key)

result = single_xor_decrypt(ciphertext,key)
print(result)