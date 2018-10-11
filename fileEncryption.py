# File Encryption Lab
# CECS 378
# Alexander Fielding

import cryptography
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

#globals

message = "secret message"
#functions

#In this method, you will generate a 16 Bytes IV, and encrypt the message using the key
# and IV in CBC mode (AES).
#You return an error if the len(key) < 32 (i.e., the key has to be 32 bytes= 256 bits).

def MyEncrypt(msg,key):
    IV = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()

    byteMessage = str.encode(msg)

    padder = padding.PKCS7(32).padder()
    padded_data = padder.update(byteMessage) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()

    return [ct, IV]

#In this method, you'll generate a 32Byte key. You open and read the file as a string.
#You then call the above method to encrypt your file using the key you generated.
#You return the cipher C, IV, key and the extension of the file (as a string).

def invertMyEncrypt(C, IV):
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()
    C = decryptor.update(C) + decryptor.finalize()
    unpadder = padding.PKCS7(32).unpadder()
    C = unpadder.update(C) + unpadder.finalize()
    C = str(C, 'utf-8')
    print("Decryption: ", C)


#main

key = os.urandom(32)
if (len(key) < 32):
    print('Key must be length 32')

(C, IV) =  MyEncrypt(message, key)

invertMyEncrypt(C, IV)

print(C, IV)


#invertMyEncrypt(C, IV)

#(C, IV, key, ext)= MyfileEncrypt (filepath):
