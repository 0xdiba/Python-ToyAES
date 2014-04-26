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
 
 # Takes as arguments a message to be encrypted and a key
 # and encrypts the message with the AES-128 algorithm
def encrypt(message, key):

    # Do padding as asked in the exercise
    def pad(msg):
        x = AES.block_size - len(msg) % AES.block_size
        return msg + (chr(x) * x)
 
    padded_message = pad(message)

    iv = Random.OSRNG.posix.new().read(AES.block_size)

    IV = iv
    cipher = AES.new(key)
    ciphertext = ""
    for i in range(0,len(padded_message), 16):
        block = ""
        for j in range(len(padded_message[i:i+16])):
            block += chr( ord(IV[j]) ^ ord(padded_message[i+j]) )
        while len(block) < 16:
                block += IV[len(block)]
        IV = cipher.encrypt(block)
        ciphertext += IV

    return iv + ciphertext

# In AES-128 the key must be of 16byte length
# this function replaces the key with its MD5 digest 
# if it is not 16 bytes
def extendkey(key):
	if (len(key) != 16):
		key = MD5.new(key).hexdigest()

	return key

def createMAC(message, key):
	h = HMAC.new(key,message,SHA)
	message = message + h.digest()
        return message

def showUsage():
    usage = """=========================================================\nCrypto 3000: Simple AES-CBC Implementation using PyCrypto\n=========================================================
    syntax: python encrypt encryptionKey authKey\n*The plaintext must be located at a file named plain.txt\n in the same directory as the script*\n"""

    print usage

 
if __name__ == '__main__':
    
    if (len(sys.argv) != 3):
        print "Please provide the 2 keys needed...\n"
        showUsage()
        sys.exit()

    keyEnc = extendkey(sys.argv[1])
    keyAuth = extendkey(sys.argv[2])

    txt = open("plain.txt","r+")
    message=txt.read()

    message = createMAC(message,keyAuth)
    encrypted = encrypt(message,keyEnc)
    file = open("en.crypt","wb")
    file.write(encrypted)
    file.close()
