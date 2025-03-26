from Cryptodome.Cipher import AES
import binascii
from Cryptodome.Util import Counter


def decrypt_cbc(ciphertext_hex, key_hex):
    key = binascii.unhexlify(key_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)
    iv = ciphertext[:16]
    encrypted_message = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_message)
    return decrypted[:-decrypted[-1]].decode()


def decrypt_ctr(ciphertext_hex, key_hex):
    key = binascii.unhexlify(key_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)
    iv = ciphertext[:16]
    encrypted_message = ciphertext[16:]
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    decrypted = cipher.decrypt(encrypted_message)
    return decrypted.decode()


# CBC Decryption
cbc_key = "140b41b22a29beb4061bda66b6747e14"
cbc_ciphertext1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
cbc_ciphertext2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"

print("CBC Plaintext 1:", decrypt_cbc(cbc_ciphertext1, cbc_key))
print("CBC Plaintext 2:", decrypt_cbc(cbc_ciphertext2, cbc_key))

# CTR Decryption
ctr_key = "36f18357be4dbd77f050515c73fcf9f2"
ctr_ciphertext1 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
ctr_ciphertext2 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"

print("CTR Plaintext 1:", decrypt_ctr(ctr_ciphertext1, ctr_key))
print("CTR Plaintext 2:", decrypt_ctr(ctr_ciphertext2, ctr_key))
