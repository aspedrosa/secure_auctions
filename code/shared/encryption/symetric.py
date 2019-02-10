#!/usr/bin/python3

"""
File with several classes to represent the different types of
    symmetric encryption possible

                SymmetricEncryption
                    /       \
AuthenticatedEncryption NonAuthenticatedEncryption
                            /           \
                    BlockEncryption StreamEncryption
                        /       \
            PaddedEncryption NonPaddedEncryption

The leaf classes on the tree above are the implementations
    and the nodes are abstractions
"""

from os import urandom
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA256

from base64 import b64encode, b64decode

class SymmetricEncryption(ABC):
    """
    Base class that represents all methods of symmetric encryption
    This tree of hierarchy allow us to build follow of messages
        not having to consider different algorithms or modes 
        of encryption
    """
    def __init__(self, cipherAlgorithm, key):
        """
        cipherAlgorithm : cipher algorithm : encryption and decryption algorithm
        key : bytes : key used in encryption and decryption
        """
        self.cipherAlg = cipherAlgorithm
        self.key = key

    @abstractmethod
    def encrypt(self, message):
        """
        Method used to encrypt any message received. Each
            specific method has its own implementation

        message : bytes : message to encrypt
        """
        pass

    @abstractmethod
    def decrypt(self, ciphertext, iv_nonce, mac):
        """
        Method used to decrypt a encrypted message received

        ciphertext : str : encrypted message
        iv_nonce : str : field used by multiple cipher algorithms
            some use a nonce other iv
        mac : str : field used for those method that don't have
            integrity control

        raise cryptography.exceptions.InvalidSignature verification with mac failed
        raise cryptography.exceptions.InvalidTag error on authenticated encryption algorithms
        """
        pass

class AuthenticatedEncryption(SymmetricEncryption):
    """
    Uses algorithms that have authentication
    Doesn't use the mac field on decryption because
        the algorithm can see if the message
        was changed
    """
    def __init__(self, cipherAlgorithm, key):
        super(AuthenticatedEncryption, self).__init__(cipherAlgorithm, key)
        self.cipherAlg = self.cipherAlg(self.key)

    def encrypt(self, message):
        nonce = urandom(12)

        ct = self.cipherAlg.encrypt(nonce, message, None)

        return {
                "ct":b64encode(ct).decode("ascii"),
                "iv_nonce":b64encode(nonce).decode("ascii"),
                "mac":""
               }

    def decrypt(self, ct, nonce, mac):
        nonce, nonce = bytes(ct, "ascii"), bytes(nonce, "ascii")

        ct = b64decode(ct)
        nonce = b64decode(nonce)

        return self.cipherAlg.decrypt(nonce, ct, None)

class NonAuthenticatedEncryption(SymmetricEncryption):
    """
    Abstract class to represent symmetric encryption that
        doesn't have integrity control
    To secure that they use MAC's (Message Authentication Codes) more
        specifically HMAC (hash-based MAC's)
    """
    def __init__(self, cipherAlgorithm, key, macKey):
        """
        macKey : bytes : used for mac
        """
        super(NonAuthenticatedEncryption, self).__init__(cipherAlgorithm, key)
        self.macKey = macKey


class BlockEncryption(NonAuthenticatedEncryption):
    """
    Non Authenticated Encryption that uses block cipher encryption
    """
    def __init__(self, cipherAlgorithm, key, macKey, mode):
        """
        Other fields see upper class doc's
        mode : Mode : mode of encryption
        """
        super(BlockEncryption, self).__init__(cipherAlgorithm, key, macKey)
        self.cipherAlg = self.cipherAlg(self.key)
        self.mode = mode

class StreamEncryption(NonAuthenticatedEncryption):
    """
    Non Authenticated Encryption that uses stream cipher encryption
    Because the python api that we are using only has one stream
        cipher algorithm, we hardcoded some fields like nonce size
        and cipher algorithm
    """
    def __init__(self, key, macKey):
        super(StreamEncryption, self).__init__(algorithms.ChaCha20, key, macKey)

    def encrypt(self, message):
        nonce = urandom(16) #generate random nonce

        encryptor = Cipher(self.cipherAlg(self.key, nonce), None, default_backend()).encryptor()

        ct = encryptor.update(message) + encryptor.finalize() #encryption

        ct, nonce = b64encode(ct), b64encode(nonce)

        h = HMAC(self.macKey, SHA256(), default_backend())
        h.update(ct+nonce)
        mac = h.finalize() #generate MAC

        return {
                "ct":ct.decode("ascii"),
                "iv_nonce":nonce.decode("ascii"),
                "mac":b64encode(mac).decode("ascii")
               }

    def decrypt(self, ct, nonce, mac):
        ct, nonce, mac = bytes(ct, "ascii"), bytes(nonce, "ascii"), bytes(mac, "ascii")

        mac = b64decode(mac)

        h = HMAC(self.macKey, SHA256(), default_backend())
        h.update(ct+nonce)
        h.verify(mac) #verify MAC

        ct, nonce = b64decode(ct), b64decode(nonce)

        decryptor = Cipher(self.cipherAlg(self.key, nonce), None, default_backend()).decryptor()
        message = decryptor.update(ct) + decryptor.finalize() #decrypt

        return message

class PaddedEncryption(BlockEncryption):
    """
    Block Encryption that uses padding
    This is mainly dictated by the mode used and on the api used there
        was only one mode that implied padding, CBC, so again
        we hardcoded the mode
    """
    def __init__(self, cipherAlgorithm, key, macKey, paddingAlgorithm):
        super(PaddedEncryption, self).__init__(cipherAlgorithm, key, macKey, modes.CBC)
        self.paddingAlg = paddingAlgorithm(self.cipherAlg.block_size)

    def encrypt(self, message):
        iv = urandom(int(self.cipherAlg.block_size / 8)) #generate random iv

        padder = self.paddingAlg.padder()
        paddedMessage = padder.update(message) + padder.finalize() #padding

        encryptor = Cipher(self.cipherAlg, self.mode(iv), default_backend()).encryptor()
        ct = encryptor.update(paddedMessage) + encryptor.finalize() #encryption

        ct, iv = b64encode(ct), b64encode(iv)

        h = HMAC(self.macKey, SHA256(), default_backend())
        h.update(ct+iv)
        mac = h.finalize() #generate MAC

        return {
                "ct":ct.decode("ascii"),
                "iv_nonce":iv.decode("ascii"),
                "mac":b64encode(mac).decode("ascii")
               }

    def decrypt(self, ct, iv, mac):
        ct, iv, mac = bytes(ct, "ascii"), bytes(iv, "ascii"), bytes(mac, "ascii")

        mac = b64decode(mac)

        h = HMAC(self.macKey, SHA256(), default_backend())
        h.update(ct+iv)
        h.verify(mac) #verify MAC

        ct, iv = b64decode(ct), b64decode(iv)

        decryptor = Cipher(self.cipherAlg, self.mode(iv), default_backend()).decryptor()
        paddedMessage = decryptor.update(ct) + decryptor.finalize() #decrypt

        unpadder = self.paddingAlg.unpadder()
        message = unpadder.update(paddedMessage) + unpadder.finalize() #unpad

        return message

class NonPaddedEncryption(BlockEncryption):
    """
    Block Encryption that doesn't need padding
    This is manly do to several modes that transform a block
        cipher into a stream cipher
    """
    def __init__(self, cipherAlgorithm, key, macKey, mode):
        super(NonPaddedEncryption, self).__init__(cipherAlgorithm, key, macKey, mode)

    def encrypt(self, message):
        iv = urandom(int(self.cipherAlg.block_size / 8)) #generate random iv

        encryptor = Cipher(self.cipherAlg, self.mode(iv), default_backend()).encryptor()
        ct = encryptor.update(message) + encryptor.finalize() #encryption

        ct, iv = b64encode(ct), b64encode(iv)

        h = HMAC(self.macKey, SHA256(), default_backend())
        h.update(ct+iv)
        mac = h.finalize() #generate MAC

        return {
                "ct":ct.decode("ascii"),
                "iv_nonce":iv.decode("ascii"),
                "mac":b64encode(mac).decode("ascii")
               }

    def decrypt(self, ct, iv, mac):
        ct, iv, mac = bytes(ct, "ascii"), bytes(iv, "ascii"), bytes(mac, "ascii")

        mac = b64decode(mac)

        h = HMAC(self.macKey, SHA256(), default_backend())
        h.update(ct+iv)
        h.verify(mac) #verify MAC

        ct, iv = b64decode(ct), b64decode(iv)

        decryptor = Cipher(self.cipherAlg, self.mode(iv), default_backend()).decryptor()
        message = decryptor.update(ct) + decryptor.finalize() #decrypt

        return message
