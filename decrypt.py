#!/usr/bin/python 

# Simple python implementation of AES-CBC with pyCrypto
# to use you must have:
# --python 2.7
# --pyCrypto lib

import sys
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.Hash import HMAC
from Crypto.Hash import SHA # SHA-1 in pyCrypto

class AuthenticationError(Exception): pass
 

# In AES-128, the key must be of 16byte length
# this function replaces the key with its MD5 digest 
# if it is not 16 bytes
def extendkey(key):
	if (len(key) != 16):
		key = MD5.new(key).hexdigest()

	return key
 
 # Takes as arguments a message to be decrypted and a key
 # and decrypts the message with the AES-128 algorithm
def decrypt(ciphertext, key):
    unpad = lambda s: s[:-ord(s[-1])]
    IV = ciphertext[:AES.block_size]
    
    aes =  AES.new(key)
    decrypted = ""
    for i in range(16,len(ciphertext),16):
        block = aes.decrypt(ciphertext[i:i+16])
        tmp = ""
        for j in range(len(block)):
            tmp += chr( ord(IV[j]) ^ ord(block[j]) )
        IV = ciphertext[i:i+16]
        decrypted += tmp
    return unpad(decrypted)

def checkMAC(message, key):
	sig = message[-SHA.digest_size:]
	data = message[:-SHA.digest_size]
	if HMAC.new(key, data, SHA).digest() != sig:
		raise AuthenticationError("message authentication failed")

def showUsage():
    usage = """=========================================================\nCrypto 3000: Simple AES-CBC Implementation using PyCrypto\n=========================================================
    syntax: python decrypt encryptionKey authKey\n*The encrypted file en.crypt must be located in the same directory as the script*\n"""

    print usage

 
if __name__ == '__main__':
    
    if (len(sys.argv) != 3):
        print "Please provide the 2 keys needed...\n"
        showUsage()
        sys.exit()

    keyEnc = extendkey(sys.argv[1])
    keyAuth = extendkey(sys.argv[2])

    file = open ("en.crypt","rb")
    encrypted = file.read()
    file.close()

    decrypted = decrypt(encrypted, keyEnc)
    checkMAC(decrypted,keyAuth)
 
    file = open("decr_plain.txt","w+")
    file.write(decrypted[:-SHA.digest_size])# remove the HMAC tag
    file.close()

    print decrypted[:-SHA.digest_size]
