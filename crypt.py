#!/usr/bin/python
# -*- coding: utf-8 -*-

import base64
import io
import fileinput
import argparse
import hashlib
import sys
from Crypto import Random
from Crypto.Cipher import AES

class AESEncryptor:

    def __init__(self, key): 
        self.defaultBlockSize = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, data):
        data = self.pad(data)
        initVector = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, initVector)
        return base64.b64encode(initVector + cipher.encrypt(data))

    def decrypt(self, data):
        data = base64.b64decode(data)
        initVector = data[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, initVector)
        return self.unpad(cipher.decrypt(data[AES.block_size:]))

    def pad(self, s):
        return s + (self.defaultBlockSize - len(s) % self.defaultBlockSize) * chr(self.defaultBlockSize - len(s) % self.defaultBlockSize) 

    def unpad(self, s):
        unpadData = s[:-ord(s[len(s)-1:])]
        return unpadData[0:len(unpadData) - 1]

class ArgumentsResolver:
    @staticmethod
    def getConsoleArgs():
        parser = argparse.ArgumentParser(prog="PyCoder")
        parser.add_argument('-k',required=True,help="[Encryption/Decryption key]",metavar="",dest="key")
        parser.add_argument('-e',action='store_true',help="[Encrypt input data]",dest="encrypt")
        parser.add_argument('-d',action='store_true',help="[Decrypt input data]",dest="decrypt")
        return parser.parse_args();

consoleArgumentsData = ArgumentsResolver.getConsoleArgs()

key = consoleArgumentsData.key
isEncryptionMode = consoleArgumentsData.encrypt
isDecryptionMode = consoleArgumentsData.decrypt

if len(key) == 0:
    print 'Length of encription key must be not zero'
    exit(0)

inputData = ''

while True:
    try:
        line = raw_input()
    except EOFError:
        break
    inputData += line
    if isEncryptionMode == True:
        inputData += '\n'


if isEncryptionMode:
    aesEncryptor = AESEncryptor(key=key)
    encryptedData = aesEncryptor.encrypt(data=inputData)
    print encryptedData
else:
    if isDecryptionMode == True:
        aesEncryptor = AESEncryptor(key=key)
        decryptedData = str(aesEncryptor.decrypt(inputData))
        print decryptedData
    else:
        print 'Error! Choose encrypt or decrypt option (Use [-h] for more information)'
        exit(0)
