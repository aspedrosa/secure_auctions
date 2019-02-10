#!/usr/bin/python3

"""
Data structures used by the Auction Repository to hold information
    about auctions, bids and clients
"""

from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.backends import default_backend 

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.padding import PKCS7

from base64 import b64encode, b64decode

from cryptopuzzle import calculateHashOverFields

class Auction:
    """
    Stores all information associated with an auction
        -BlockChain
        -thread to close auction after duration sent by the client
    """
    def __init__(self, auctionInfo):
        self.blockChain = BlockChain(auctionInfo)

    def getAuctionInfo(self):
        """
        Info to display when a client asks to list all open/closed auctions
        """
        return self.blockChain.head.data

    def getAuctionBids(self):
        """
        Info to display when a client asks to list all bids of an auction
        """
        block = self.blockChain.head.next
        if block == None:
            return []

        bids = []
        while block != None:
            if "winnerBlockNumber" in block.data.keys():
                break

            bids.append(block.data["bid"])
            block = block.next

        return bids

    def getClientBids(self, clientId):
        assert self.getAuctionInfo()["type"] == "BlindShown" or "key" in self.blockChain.tail.data.keys()

        block = self.blockChain.head.next
        if block == None:
            return []

        bids = []
        while block != None:
            if "winnerBlockNumber" in block.data.keys():
                break

            if self.getAuctionInfo()["type"] == "BlindShown":
                blockClientId = block.data["bid"]["clientId"]
            else:
                key = b64decode(bytes(self.blockChain.tail.data["key"], "ascii"))
                field, iv = block.data["bid"]["clientId"].split("\n")

                fieldBytes = b64decode(bytes(field, "ascii"))
                iv = b64decode(bytes(iv, "ascii"))

                decryptor = Cipher(AES(key), CBC(iv), default_backend()).decryptor()
                uncryptedField = decryptor.update(fieldBytes) + decryptor.finalize()

                unpadder = PKCS7(AES.block_size).unpadder()
                unpaddedField = unpadder.update(uncryptedField) + unpadder.finalize()

                blockClientId = unpaddedField.decode("ascii")

            if blockClientId == clientId:
                bids.append(block.data["bid"])


            block = block.next

        if bids == []:
            return []

        if "key" in self.blockChain.tail.data.keys():
            key = self.getKey()

            return {"key":key, "bidsList":bids}

        return bids

    def newBid(self, data, nonce, newHash):
        """
        Executed after a bid is created and its fields are encrypted
            by the auction manager
        """
        newBlock = Block(self.blockChain.tail.blockNum + 1,
                         self.blockChain.tail.hash,
                         data,
                         nonce)

        self.blockChain.addBlock(newBlock)

        assert self.blockChain.tail.hash == newHash

    def lastBlockInfo(self):
        """
        Function used to get information how the blockchain is, to know what
            fields to put on the new block
        """
        return self.blockChain.tail.blockNum, self.blockChain.tail.hash

    def makePublic(self, key):
        auctionType = self.getAuctionInfo()["type"]

        keyBytes = b64decode(bytes(key, "ascii"))

        padding = PKCS7(AES.block_size)

        block = self.blockChain.head.next
        if block == None:
            self.blockChain.addBlock(Block(self.blockChain.tail.blockNum + 1,
                                           self.blockChain.tail.hash,
                                           {"winnerBlockNumber":-1, "key":key},
                                           b64encode(bytes(32)).decode("ascii")
                                           )
                                    )
            return {}, set()

        winnerAmount = -1
        winnerBlockNumber = -1
        winnerBid = {}
        clients = set()
        while block != None:
            if "Blind" in auctionType:
                field, iv = block.data["bid"]["amount"].split("\n")

                fieldBytes = b64decode(bytes(field, "ascii"))
                iv = b64decode(bytes(iv, "ascii"))

                cipher = Cipher(AES(keyBytes), CBC(iv), default_backend())

                decryptor = cipher.decryptor()
                uncryptedField = decryptor.update(fieldBytes) + decryptor.finalize()

                unpadder = padding.unpadder()
                unpaddedField = unpadder.update(uncryptedField) + unpadder.finalize()

                amount = float(unpaddedField.decode("ascii"))
            else:
                amount = block.data["bid"]["amount"]

            if winnerBid == {} or winnerAmount < amount:
                winnerBid = block.data["bid"]
                winnerAmount = amount
                winnerBlockNumber = block.blockNum

            if auctionType != "BlindShown":
                field, iv = block.data["bid"]["clientId"].split("\n")

                fieldBytes = b64decode(bytes(field, "ascii"))
                iv = b64decode(bytes(iv, "ascii"))

                cipher = Cipher(AES(keyBytes), CBC(iv), default_backend())

                decryptor = cipher.decryptor()
                uncryptedField = decryptor.update(fieldBytes) + decryptor.finalize()

                unpadder = padding.unpadder()
                unpaddedField = unpadder.update(uncryptedField) + unpadder.finalize()

                clientId = unpaddedField.decode("ascii")

                clients.add(clientId)

            block = block.next

        self.blockChain.addBlock(Block(self.blockChain.tail.blockNum + 1,
                                       self.blockChain.tail.hash,
                                       {"winnerBlockNumber":winnerBlockNumber, "key":key},
                                       b64encode(bytes(32)).decode("ascii")
                                       )
                                )

        return winnerBid, clients

    def getWinnerBid(self):
        key = self.getKey()

        winnerBlockNumber = self.blockChain.tail.data["winnerBlockNumber"]

        if winnerBlockNumber == -1:
            return {"winnerBid":{}, "key":key}

        block = self.blockChain.head.next

        while block != None:
            if block.blockNum == winnerBlockNumber:
                return {"winnerBid":block.data["bid"], "key":key}

            block = block.next

        assert False

    def getKey(self):
        assert "key" in self.blockChain.tail.data.keys()

        return self.blockChain.tail.data["key"]
    
    def getAllData(self):
        block = self.blockChain.head

        allData = []
        while block != None:
            allData.append({
                    "block":{
                        "blockNumber":block.blockNum,
                        "previousHash":block.prevHash,
                        "nonce":block.nonce,
                        "data":block.data,
                        },
                    "hash":block.hash
                })

            block = block.next

        return allData

class BlockChain:
    """
    Represents the blockchain of an auction. It's first block has
        a different structure from the following ones, having the information
        of the creation of the auction. The following blocks contain information
        about the bids made to an auction
    """
    def __init__(self, firstData):
        self.head = Block(0, b64encode(bytes(32)).decode("ascii"), firstData, b64encode(bytes(32)).decode("ascii"))
        self.tail = self.head

    def addBlock(self, newBlock):
        """
        Adds a new block to the blockchain ands makes it the last one
        """
        self.tail.next = newBlock
        self.tail = newBlock

class Block:
    """
    Representation of all types of blocks
    """
    def __init__(self, blockNumber, previousHash, data, nonce):
        self.blockNum = blockNumber
        self.prevHash = previousHash
        self.nonce = nonce
        self.data = data

        toMine = dict()
        toMine["blockNumber"] = self.blockNum
        toMine["previousHash"] = self.prevHash
        toMine["nonce"] = self.nonce
        toMine["data"] = self.data

        self.hash = b64encode(calculateHashOverFields(toMine)).decode("ascii")

        self.next = None
