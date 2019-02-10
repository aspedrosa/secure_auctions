#!/usr/bin/python3

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

from cryptography.x509 import load_pem_x509_certificate

from base64 import b64decode, b64encode

from datetime import datetime

from copy import deepcopy

from cryptopuzzle import calculateHashOverFields
from encryption.assymetric import PublicKeyServer, PublicKeyClient, validCertificate

def decryptField(key, padding, field):
    field, iv = field.split("\n")

    fieldBytes = b64decode(bytes(field, "ascii"))
    iv = b64decode(bytes(iv, "ascii"))

    cipher = Cipher(AES(key), CBC(iv), default_backend())

    fieldBytes = b64decode(bytes(field, "ascii"))

    decryptor = cipher.decryptor()
    uncryptedField = decryptor.update(fieldBytes) + decryptor.finalize()

    unpadder = padding.unpadder()
    unpaddedField = unpadder.update(uncryptedField) + unpadder.finalize()

    return unpaddedField.decode("utf-8")

def decryptBid(bid, key):
    padding = PKCS7(AES.block_size)

    auctionType = bid["auctionType"]

    if auctionType == "English" or auctionType == "BlindHidden":
        for field in ["clientId", "clientName", "clientCertificate", "timestamp"]:
            bid[field] =  decryptField(key, padding, bid[field])

    if "Blind" in auctionType:
        bid["amount"] = decryptField(key, padding, bid["amount"])

    bid["nonce"] = decryptField(key, padding, bid["nonce"])

def validateAuctionContent(allData, compareBid=None, compareBlock=None):
    previousHash = b64encode(bytes(32)).decode("ascii")

    key = None

    validateOpen = not all(k in allData[-1]["block"]["data"].keys() for k in ["key", "winnerBlockNumber"])

    if not validateOpen:
        key = b64decode(bytes(allData[-1]["block"]["data"]["key"], "ascii"))

    winnerAmount = winnerBlockNumber = difficulty = -1
    for i, blockData in enumerate(allData):
        blockHash = b64decode(bytes(blockData["hash"], "ascii"))
        block = blockData["block"]

        #print(block)

        if compareBlock != None and compareBlock["blockNumber"] == block["blockNumber"] and compareBlock != block:
            print("Data on the blockchain is different from the receipt")
            return

        if block["previousHash"] != previousHash:
            print("Hash of previous block don't match")
            return

        if block["blockNumber"] != i:
            print("Number of block does not match sequence")
            return

        if blockHash != calculateHashOverFields(block):
            print("Hash of blocks don't match")
            return
        previousHash = blockData["hash"]

        if i == 0:
            difficulty = block["data"]["difficulty"]
            continue
        elif i == len(allData) - 1 and not validateOpen:
            if winnerBlockNumber != block["data"]["winnerBlockNumber"]:
                print("Winner block number don't match")
                return
            continue

        if not (int(blockHash.hex(), 16) < 2 ** (256 - difficulty)):
            print("Hash of a block not under the target")
            return

        data = block["data"]

        managerValidation = data.pop("managerValidation")

        managerCertificateBytes = b64decode(bytes(managerValidation["certificate"], "ascii"))
        managerCertificate = load_pem_x509_certificate(managerCertificateBytes, default_backend())
        managerPublicKey = PublicKeyServer(managerCertificate.public_key())
        signature = b64decode(bytes(managerValidation["signature"], "ascii"))

        if not managerPublicKey.verify(calculateHashOverFields(data), signature):
            print("Signature of manager validation not valid")
            return

        if not validateOpen:
            originalBid = deepcopy(data["bid"])
            bid = data["bid"]

            if compareBlock != None and compareBlock["blockNumber"] == block["blockNumber"] and compareBid != bid:
                print("Bid sent is different!")
                return

            decryptBid(bid, key)

            if bid["auctionId"] != allData[0]["block"]["data"]["auctionId"]:
                print("Auction Id on a bid doesn't match")
                return

            if bid["auctionType"] != allData[0]["block"]["data"]["type"]:
                print("Auction type on a bid doesn't match")
                return

            valid, _,_,_ = validCertificate(managerCertificateBytes, datetime.fromtimestamp(int(bid["timestamp"])))
            if not valid:
                print("Manager certificate not valid")
                return

            clientCertificateBytes = b64decode(bytes(bid["clientCertificate"], "ascii"))
            clientCertificate = load_pem_x509_certificate(clientCertificateBytes, default_backend())

            valid, _,_,_ = validCertificate(clientCertificateBytes, datetime.fromtimestamp(int(bid["timestamp"])))
            if not valid:
                print("Client certificate not valid")
                return

            clientPublicKey = PublicKeyClient(clientCertificate.public_key())

            signature = data["clientValidation"]

            if bid["auctionType"] in ["English", "BlindHidden"]:
                signature, iv = signature.split("\n")

                iv = b64decode(bytes(iv, "ascii"))
                signature = b64decode(bytes(signature, "ascii"))

                decryptor = Cipher(AES(key), CBC(iv), default_backend()).decryptor()
                uncryptedField = decryptor.update(signature) + decryptor.finalize()

                unpadder = PKCS7(AES.block_size).unpadder()
                signature = unpadder.update(uncryptedField) + unpadder.finalize()

                signature = b64decode(signature)
            else:
                signature = b64decode(bytes(signature, "ascii"))

            if not clientPublicKey.verify(calculateHashOverFields(bid), signature):
                print("Signature of client over bids not valid")
                return

            if float(bid["amount"]) > winnerAmount:
                winnerAmount = float(bid["amount"])
                winnerBlockNumber = block["blockNumber"]

    print("All ok")

def validReceiptSignature(signature, certificate, data):
    signature = b64decode(bytes(signature, "ascii"))
    certificateBytes = b64decode(bytes(certificate, "ascii"))

    certificate = load_pem_x509_certificate(certificateBytes, default_backend())

    valid, _,_,_ = validCertificate(certificateBytes)
    if not valid:
        return False

    serverPublicKey = PublicKeyServer(certificate.public_key())

    if not serverPublicKey.verify(calculateHashOverFields({"":data}), signature):
        return False

    return True

def validateReceiptLoaded(receipt, auctionData, auctionId):
    whatIsaw = receipt["whatISaw"]

    bidSent = whatIsaw["bid"] # == to the bid decrypted

    cryptopuzzleChallange = whatIsaw["cryptopuzzleChallange"]
    difficulty = cryptopuzzleChallange["difficulty"] # == on the difficulty on the first block
    toMine = cryptopuzzleChallange["toMine"] # == to the block

    received = receipt["received"]["receipt"]

    if received != auctionData[:len(received)]:
        print("There are some changes on the blockchain")
        return

    if difficulty != auctionData[0]["block"]["data"]["difficulty"]:
        print("Difficulties don't match")
        return

    if auctionId != auctionData[0]["block"]["data"]["auctionId"]:
        print("Auction Id don't match")
        return

    validateAuctionContent(received, bidSent, toMine)
