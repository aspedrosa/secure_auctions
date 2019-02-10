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

def validateReceiptFromServerData(hashes, allData):

    assert len(hashes) < len(allData)

    firstHash = hashes[0]
    firstAllData = allData[0][3]

    hashAlg = Hash(SHA256(), default_backend())
    hashAlg.update(str(0).encode("ascii") +
                   b64encode(bytes(32)) +
                   str(0).encode("ascii") +

                   str(firstAllData["auctionId"]     ).encode("ascii") +
                   str(firstAllData["creatorId"]     ).encode("ascii") +
                   str(firstAllData["creatorName"]   ).encode("ascii") +
                   str(firstAllData["name"]          ).encode("utf-8") +
                   str(firstAllData["beginDate"]     ).encode("ascii") +
                   str(firstAllData["endDate"]       ).encode("ascii") +
                   str(firstAllData["description"]   ).encode("utf-8") +
                   str(firstAllData["type"]          ).encode("ascii")# +
                   )#str(firstAllData["validationCode"]).encode("ascii"))

    firstBlockHash = b64encode(hashAlg.finalize()).decode("ascii")

    assert firstHash == firstBlockHash

    hashes = hashes[1:]
    allData = allData[1:]

    prevHash = firstBlockHash
    for i, receiptHash in enumerate(hashes):
        data = allData[i]

        assert data[1] == prevHash

        hashObj = Hash(SHA256(), default_backend())
        hashObj.update(
         str(data[0]).encode("ascii") + #blockNum
         bytes(prevHash, "ascii") + #prevHash
         str(data[2]).encode("ascii")  + #nonce
         str(data[3]["clientId"]).encode("ascii") +
         str(data[3]["clientName"]).encode("ascii") +
         bytes(data[3]["certificate"], "ascii") +
         str(data[3]["auctionId"]).encode("ascii") +
         str(data[3]["amount"]).encode("ascii") +
         bytes(data[3]["signature"], "ascii")
         )
        blockHash = b64encode(hashObj.finalize()).decode("ascii")
        prevHash = blockHash

        assert receiptHash == blockHash

        certBytes = b64decode(bytes(data[3]["certificate"], "ascii"))
        cert = load_pem_x509_certificate(certBytes, default_backend())
        pubKey = PublicKeyClient(cert.public_key())

        hashObj = Hash(SHA256(), default_backend())
        hashObj.update(
         str(data[3]["clientId"]).encode("ascii") +
         str(data[3]["clientName"]).encode("ascii") +
         bytes(data[3]["certificate"], "ascii") +
         str(data[3]["auctionId"]).encode("ascii") +
         str(data[3]["amount"]).encode("ascii")
         )
        bidHash = hashObj.finalize()

        try:
            pubKey.verify(bidHash, b64decode(bytes(data[3]["signature"], "ascii")))
        except:
            print("verify")
            assert False

