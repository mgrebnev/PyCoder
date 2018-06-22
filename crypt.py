#!/usr/bin/python
# -*- coding: utf-8 -*-

import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESEncryptor:

    def __init__(self, key): 
        self.defaultBlockSize = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, data):
        raw = self.pad(data)
        initVector = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, initVector)
        return str(initVector + cipher.encrypt(raw))

    def decrypt(self, data):
        initVector = data[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, initVector)
        return self.unpad(cipher.decrypt(data[AES.block_size:]))

    def pad(self, s):
        return s + (self.defaultBlockSize - len(s) % self.defaultBlockSize) * chr(self.defaultBlockSize - len(s) % self.defaultBlockSize)

    def unpad(self, s):
        return s[:-ord(s[len(s)-1:])]

aesEncryptor = AESEncryptor(key='123321')
encryptedData = aesEncryptor.encrypt(data='Hello, World!')

print encryptedData
print aesEncryptor.decrypt(encryptedData)
