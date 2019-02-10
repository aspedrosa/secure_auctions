#!/usr/bin/python3

"""
Data structures stored on the manager
"""

from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

from base64 import b64encode, b64decode

class Auction:
    """
    To store
    -information of an auction
    -a key to encrypt/decrypt fields of bids for this auction
    -validation code to validate bids
    """
    def __init__(self, auctionInfo, validationCode, modificationCode, baseAmount):
        self.auctionInfo = auctionInfo

        self.validationCode = validationCode
        self.modificationCode = modificationCode
        self.baseAmount = baseAmount
        self.lastAmount = 0

        self.key = urandom(32)

        self.padding = PKCS7(AES.block_size)

    def encryptField(self, field):
        iv = urandom(int(AES.block_size / 8))

        cipher = Cipher(AES(self.key), CBC(iv), default_backend())

        bytesField = str(field).encode("utf-8")

        padder = self.padding.padder()
        paddedBytes = padder.update(bytesField) + padder.finalize()

        encryptor = cipher.encryptor()
        ct = encryptor.update(paddedBytes) + encryptor.finalize()

        return b64encode(ct).decode("ascii") + "\n" + b64encode(iv).decode("ascii")
