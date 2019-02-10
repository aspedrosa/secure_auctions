#!/usr/bin/python3

"""
"""

from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_pem_x509_certificate

from base64 import b64decode, b64encode

from encryption.assymetric import PublicKeyClient

from os import urandom

def solveCriptopuzzle(difficulty, toMine):
    target = 2 ** (256-difficulty)

    while True:
        nonce = b64encode(urandom(32)).decode("ascii")
        toMine["nonce"] = nonce

        hash = calculateHashOverFields(toMine)

        if int(hash.hex(), 16) < target:
            return nonce, b64encode(hash).decode("ascii")


def calculateHashOverList(lst, hashObj):
    for v in lst:
        if type(v) == dict:
            calculateHashOverDict(v, hashObj)
        elif type(v) == list:
            calculateHashOverList(v, hashObj)

        hashObj.update(str(v).encode("utf-8"))

def calculateHashOverDict(dicti, hashObj):
    for k in sorted(dicti.keys()):
        v = dicti[k]
        if type(v) == dict:
            calculateHashOverDict(v, hashObj)
        elif type(v) == list:
            calculateHashOverList(v, hashObj)

        hashObj.update(str(v).encode("utf-8"))


def calculateHashOverFields(fields):
    hashObj = Hash(SHA256(), default_backend())

    calculateHashOverDict(fields, hashObj)

    return hashObj.finalize()

def verifyCryptopuzzle(expectedHash, toMine, difficulty):

    target = 2 ** (256 - difficulty)

    newHash = calculateHashOverFields(toMine)

    if int(newHash.hex(), 16) < target:
        expectedHashBytes = b64decode(bytes(expectedHash, "ascii"))
        if newHash != expectedHashBytes:
            return False, "Hash not equal to the one received"
        return True, ""
    else:
        return False, "Hash not under target"
