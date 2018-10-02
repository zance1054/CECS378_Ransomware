# File Encryption Lab
# CECS 378
# Alexander Fielding

import cryptography
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

#globals

key = ChaCha20Poly1305.generate_key()
print(key)
#functions

#In this method, you will generate a 16 Bytes IV, and encrypt the message using the key
# and IV in CBC mode (AES).
#You return an error if the len(key) < 32 (i.e., the key has to be 32 bytes= 256 bits).

def Myencrypt(msg,key):

    if(len(key > 32)):
        print("Invalid key, length must be 32 bytes (256bits)")
    return 0

#In this method, you'll generate a 32Byte key. You open and read the file as a string.
#You then call the above method to encrypt your file using the key you generated.
#You return the cipher C, IV, key and the extension of the file (as a string).

def MyfileEncrypt (filepath):
    return 0

def invertMyEncrypt():
    return 0

def invertMyfileEncrypt():
    return 0

#main
