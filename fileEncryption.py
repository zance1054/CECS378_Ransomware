# File Encryption Lab
# CECS 378
# Alexander Fielding

import cryptography
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

#globals

key = ChaCha20Poly1305.generate_key()
message = "secret message"
backend = default_backend()
#functions

#In this method, you will generate a 16 Bytes IV, and encrypt the message using the key
# and IV in CBC mode (AES).
#You return an error if the len(key) < 32 (i.e., the key has to be 32 bytes= 256 bits).

def Myencrypt(msg,key):
    IV = os.random(16)
    algorithm = algorithms.ChaCha20(key, IV)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend
    encryptor = cipher.encryptor()

    byteMessage = str.encode(msg)

    padder = padding.PKCS7(blockSize).padder()
    padded_data = padder.update(byteMessage) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()

    return [ct, IV]

#In this method, you'll generate a 32Byte key. You open and read the file as a string.
#You then call the above method to encrypt your file using the key you generated.
#You return the cipher C, IV, key and the extension of the file (as a string).

def invertMyEncrypt(ct):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    ct = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(blockSize).unpadder()
    ct = unpadder.update(ct) + unpadder.finalize()
    ct = str(ct, 'utf-8')
    print("Decryption: ", ct)


#main

key = os.urandom(32)
if (len(key) < 32):
    print('Key must be length 32')

(C, IV) =  MyEncrypt(message, key)


invertMyEncrypt(C, IV)

#(C, IV, key, ext)= MyfileEncrypt (filepath):
