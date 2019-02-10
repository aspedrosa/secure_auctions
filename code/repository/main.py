#!/usr/bin/python3

#system libraries
import socket
import threading
from time import sleep, time
from sys import exit
from exceptions import ErrorMessage

from cryptography.hazmat.primitives.serialization import Encoding
from base64 import b64decode, b64encode

#local libraries
import constants
from message import *
from encryption import handshake
from message import readMessage, sendEncryptedMessage, Field, BytesField
from encryption.assymetric import PrivateKeyServer, PublicKeyClient, getUserInfo
from encryption.handshake import POSSIB_MODES, POSSIB_CIPHERS, POSSIB_PADDING
from utilServers import *
from storage import *
from cryptopuzzle import verifyCryptopuzzle, calculateHashOverFields

privateKey = loadPrivateKey()
certificate = loadCertificate()

mutex = threading.Semaphore()
SERIAL_NUMBER = 1
CLIENTS = dict() #key:clientId value:set
CLIENTS_BIDS_COUNT = dict() #key:clientId value:dict(key:auctionId value:numberOfBids)
OPEN_AUCTIONS = dict() #key:auctionId value:Auction
CLOSED_AUCTIONS = dict() #key:auctionId value:Auction 


def newBid(sock, clientCert, symmetricEncryption, sessionId):

    mutex.acquire()

    openAuctionList = []
    for auction in OPEN_AUCTIONS.values():
        openAuctionList.append(auction.getAuctionInfo())

    #Sends lists with all open auctions
    sendEncryptedMessage(sock, {"openAuctionList" : openAuctionList}, symmetricEncryption, sessionId, 4)

    mandatoryFields = []
    mandatoryFields.append(Field("auctionId", int))
    mandatoryFields.append(Field("timestamp", int))
    mandatoryFields.append(Field("amount", float))
    mandatoryFields.append(BytesField("nonce"))
    mandatoryFields.append(BytesField("signature"))
    msg = readMessage(sock, mandatoryFields, symmetricEncryption, sessionId, 5)

    auctionId = msg["auctionId"]

    if auctionId not in OPEN_AUCTIONS.keys():
        sendEncryptedMessage(sock, {"error" : "No auction with that id"}, symmetricEncryption, sessionId, 6)
        return

    clientId, clientName = getUserInfo(clientCert)
    clientCertBytes = b64encode(clientCert.public_bytes(Encoding.PEM)).decode("ascii")

    bid = {
        "timestamp":msg["timestamp"],
        "clientId":clientId,
        "clientName":clientName,
        "clientCertificate":clientCertBytes,
        "amount":msg["amount"],
        "nonce":msg["nonce"],
        "auctionId":auctionId,
        "auctionType":OPEN_AUCTIONS[auctionId].getAuctionInfo()["type"]
    }

    if not PublicKeyClient(clientCert.public_key()).verify(
            calculateHashOverFields(bid),
            b64decode(bytes(msg["signature"], "ascii"))
            ):
        mutex.release()
        sendEncryptedMessage(sock, {"error" : "Invalid signature over bid"}, symmetricEncryption, sessionId, 6)
        return

    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2.connect(constants.MANAGER_ADDR)

    symmetricEncryption2, sessionId2 = handshake.clientHandShake(
        sock2, privateKey, certificate, POSSIB_CIPHERS, POSSIB_MODES, POSSIB_PADDING)

    sendEncryptedMessage(sock2, {"action":ActionTypes.VALIDATE_BID}, symmetricEncryption2, sessionId2, 3)

    toValidate = {
        "clientValidation":msg["signature"],
        "bid":bid
    }

    auction = OPEN_AUCTIONS[auctionId]
    if auction.getAuctionInfo()["type"] == "BlindShown":
        if clientId not in CLIENTS_BIDS_COUNT.keys():
            CLIENTS_BIDS_COUNT[clientId] = dict()
        if auctionId not in CLIENTS_BIDS_COUNT[clientId].keys():
            CLIENTS_BIDS_COUNT[clientId][auctionId] = 0

        toValidate["countBidsDone"] = CLIENTS_BIDS_COUNT[clientId][auctionId]

    sendEncryptedMessage(sock2, toValidate, symmetricEncryption2, sessionId2, 4)

    exceptionHappen = False
    try:
        msg = readMessage(sock2, [], symmetricEncryption2, sessionId2, 5)
    except ErrorMessage as e:
        exceptionHappen = True
        sendEncryptedMessage(sock, {"error": e.args[0]}, symmetricEncryption, sessionId, 6)

    if exceptionHappen:
        mutex.release()
        return

    sock2.close()

    blockNum, prevHash = auction.lastBlockInfo()
    blockNum += 1

    cryptopuzzleChallange = {
        "difficulty":auction.getAuctionInfo()["difficulty"],
        "toMine":{
            "blockNumber":blockNum,
            "previousHash":prevHash,
            "data":msg
        }
    }

    sendEncryptedMessage(sock, cryptopuzzleChallange, symmetricEncryption, sessionId, 6)

    mandatoryFields = []
    mandatoryFields.append(BytesField("hash"))
    mandatoryFields.append(BytesField("nonce"))
    msg = readMessage(sock, mandatoryFields, symmetricEncryption, sessionId, 7, 60)

    blockInfo = cryptopuzzleChallange["toMine"]
    blockInfo["nonce"] = msg["nonce"]

    valid, cause = verifyCryptopuzzle(msg["hash"], blockInfo, auction.getAuctionInfo()["difficulty"])

    if not valid:
        mutex.release()
        sendEncryptedMessage(sock, {"error":cause}, symmetricEncryption, sessionId, 8)
        return

    if auction.getAuctionInfo()["type"] == "BlindShown":
        if clientId not in CLIENTS.keys():
            CLIENTS[clientId] = set()
        CLIENTS[clientId].add(auctionId)

    auction.newBid(blockInfo["data"], blockInfo["nonce"], msg["hash"])

    receipt = auction.getAllData()
    signature = privateKey.sign(calculateHashOverFields({"":receipt}))
    signature = b64encode(signature).decode("ascii")
    cert = b64encode(certificate.public_bytes(Encoding.PEM)).decode("ascii")

    sendEncryptedMessage(sock, {"receipt":receipt, "signature":signature, "certificate":cert}, symmetricEncryption, sessionId, 8)

    mutex.release()

def listAllOpenAuctions(sock, symmetricEncryption, sessionId):

    mutex.acquire()

    openAuctionList = []
    for auction in OPEN_AUCTIONS.values():
        openAuctionList.append(auction.getAuctionInfo())

    mutex.release()

    #Sends lists with all open auctions
    sendEncryptedMessage(sock, {"openAuctionList" : openAuctionList}, symmetricEncryption, sessionId, 4)

def listAllClosedAuctions(sock, symmetricEncryption, sessionId):

    mutex.acquire()

    closedAuctionList = []
    for auction in CLOSED_AUCTIONS.values():
        closedAuctionList.append(auction.getAuctionInfo())

    mutex.release()

    #sends list with all closed auctions
    sendEncryptedMessage(sock, {"closedAuctionList" : closedAuctionList}, symmetricEncryption, sessionId, 4)

def listAllClientBids(sock, symmetricEncryption, sessionId):

    mandatoryFields = []
    mandatoryFields.append(Field("clientId", str))
    msg = readMessage(sock, mandatoryFields, symmetricEncryption, sessionId, 4)
    clientId = msg["clientId"]

    mutex.acquire()

    if clientId not in CLIENTS.keys():
        sendEncryptedMessage(sock, {"auctionsList":[]}, symmetricEncryption, sessionId, 5)
    else:
        auctionsList = []

        for auctionId in CLIENTS[clientId]:
            bids = []

            if auctionId in OPEN_AUCTIONS.keys():
                bids = OPEN_AUCTIONS[auctionId].getClientBids(clientId)
            else: #auctionId in CLOSED_AUCTIONS.keys()
                bids = CLOSED_AUCTIONS[auctionId].getClientBids(clientId)

            if bids != []:
                auctionsList.append(bids)

        sendEncryptedMessage(sock, {"auctionsList":auctionsList}, symmetricEncryption, sessionId, 5)
    
    mutex.release()

def listAllAuctionBids(sock, symmetricEncryption, sessionId):

    mutex.acquire()

    auctionList = []
    for auction in OPEN_AUCTIONS.values():
        auctionList.append(auction.getAuctionInfo())
    for auction in CLOSED_AUCTIONS.values():
        auctionList.append(auction.getAuctionInfo())

    sendEncryptedMessage(sock, {"auctionList":auctionList}, symmetricEncryption, sessionId, 4)

    mandatoryFields = []
    mandatoryFields.append(Field("auctionID", int))
    msg = readMessage(sock, mandatoryFields, symmetricEncryption, sessionId, 5)

    auctionId = msg["auctionID"]
    bidsList = []
    if auctionId in OPEN_AUCTIONS.keys():
        sendEncryptedMessage(sock, {"bidsList":OPEN_AUCTIONS[auctionId].getAuctionBids()} , symmetricEncryption, sessionId, 6)
    elif auctionId in CLOSED_AUCTIONS.keys():
        auction = CLOSED_AUCTIONS[auctionId]

        bids = auction.getAuctionBids()
        key = auction.getKey()

        toSend = {"bidsList":bids,
                  "key":key
                 }

        sendEncryptedMessage(sock, toSend , symmetricEncryption, sessionId, 6)
    else:
        sendEncryptedMessage(sock, {"error":"No auction with that auctionID"}, symmetricEncryption, sessionId, 6)

    mutex.release()

def checkOutcomeOfAuction(sock, clientCert, symmetricEncryption, sessionId):

    clientId, clientName = getUserInfo(clientCert)

    mutex.acquire()

    if clientId not in CLIENTS.keys():
        mutex.release()
        sendEncryptedMessage(sock, {"participatedAuctionList":[]}, symmetricEncryption, sessionId, 4)
        return

    auctions = []
    for auctionId in CLIENTS[clientId]:
        auctions.append(CLOSED_AUCTIONS[auctionId].getAuctionInfo())

    sendEncryptedMessage(sock, {"participatedAuctionList":auctions}, symmetricEncryption, sessionId, 4)

    mandatoryFields = []
    mandatoryFields.append(Field("auctionId", int))
    msg = readMessage(sock, mandatoryFields, symmetricEncryption, sessionId, 5)
    auctionId = msg["auctionId"]

    if auctionId not in CLOSED_AUCTIONS.keys():
        mutex.release()
        sendEncryptedMessage(sock, {"error":"Invalid auctionId"}, sessionId, 6)
        return

    sendEncryptedMessage(sock, CLOSED_AUCTIONS[auctionId].getWinnerBid(), symmetricEncryption, sessionId, 6)

    mutex.release()

def validateReceipt(sock, clientCert, symmetricEncryption, sessionId):

    mandatoryFields = []
    mandatoryFields.append(Field("auctionId", int))
    msg = readMessage(sock, mandatoryFields, symmetricEncryption, sessionId, 4)
    auctionId = msg["auctionId"]
    clientId, clientName = getUserInfo(clientCert)

    mutex.acquire()

    if clientId not in CLIENTS.keys() or auctionId not in CLIENTS[clientId]:
        mutex.release()
        sendEncryptedMessage(sock, {"error":"No participation of the client on the auction"}, symmetricEncryption, sessionId, 5)
        return

    if auctionId in OPEN_AUCTIONS.keys():
        sendEncryptedMessage(sock, {"dataToValidate":OPEN_AUCTIONS[auctionId].getAllData()}, symmetricEncryption, sessionId, 5)
    elif auctionId in CLOSED_AUCTIONS.keys():
        sendEncryptedMessage(sock, {"dataToValidate":CLOSED_AUCTIONS[auctionId].getAllData()}, symmetricEncryption, sessionId, 5)
    else:
        sendEncryptedMessage(sock, {"error":"No auction with that id"}, symmetricEncryption, sessionId, 5)

    mutex.release()

def closeAuctionTime(auctionId, creatorId):

    mutex.acquire()

    if auctionId not in OPEN_AUCTIONS.keys():
        mutex.release()
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(constants.MANAGER_ADDR)

    symmetricEncryption, sessionId = handshake.clientHandShake(sock, privateKey, certificate, POSSIB_CIPHERS, POSSIB_MODES, POSSIB_PADDING)

    sendEncryptedMessage(sock, {"action":ActionTypes.CLOSE_AUCTION_TIME}, symmetricEncryption, sessionId, 3)

    auction = OPEN_AUCTIONS[auctionId]
    sendEncryptedMessage(sock, {"auctionId":auctionId}, symmetricEncryption, sessionId, 4)

    mandatoryFields = []
    mandatoryFields.append(BytesField("key"))
    msgRecv = readMessage(sock, mandatoryFields, symmetricEncryption, sessionId, 5)

    _, participatingClients = auction.makePublic(msgRecv["key"])

    creatorId = auction.getAuctionInfo()["creatorId"]
    if creatorId not in CLIENTS:
        CLIENTS[creatorId] = set()
    CLIENTS[creatorId].add(auctionId)

    for clientId in participatingClients:
        if clientId not in CLIENTS:
            CLIENTS[clientId] = set()
        CLIENTS[clientId].add(auctionID)

        if auction.getAuctionInfo()["type"] == "BlindShown":
            del CLIENTS_BIDS_COUNT[clientId][auctionID]

    #Moves auction from openAuctions to closedAuctions 
    CLOSED_AUCTIONS[auctionId] = OPEN_AUCTIONS.pop(auctionId)

    mutex.release()

def createAuction(sock, symmetricEncryption, sessionId):
    global SERIAL_NUMBER

    #Gets auction details
    msgRecv = readMessage(sock, [], symmetricEncryption, sessionId, 4)

    mutex.acquire()

    msgRecv["auctionId"] = SERIAL_NUMBER
    creationTime = int(time())
    msgRecv["creationTime"] = creationTime

    #Create auction with: auctionId = SERIAL_NUMBER
    auction = Auction(msgRecv)

    OPEN_AUCTIONS[SERIAL_NUMBER] = auction 
    #Returns to manager auctionId
    sendEncryptedMessage(sock, {'auctionId': SERIAL_NUMBER, "creationTime": creationTime}, symmetricEncryption, sessionId, 5)

    auction.timerThread = threading.Timer(msgRecv["duration"] * 60, closeAuctionTime, [SERIAL_NUMBER, msgRecv["creatorId"]])

    auction.timerThread.start()

    SERIAL_NUMBER += 1

    mutex.release()

def closeAuction(sock, symmetricEncryption, sessionId):

    #Gets AuctionID to close it
    msgRecv = readMessage(sock, [], symmetricEncryption, sessionId, 4)
    auctionID = msgRecv['auctionID']

    mutex.acquire()

    if auctionID not in OPEN_AUCTIONS.keys():
        mutex.release()
        sendEncryptedMessage(sock, {"error":"Auction already closed"}, sessionId, 5)
        return

    auction = OPEN_AUCTIONS[auctionID]

    auction.timerThread.cancel()

    winnerBid, participatingClients = auction.makePublic(msgRecv["key"])

    creatorId = auction.getAuctionInfo()["creatorId"]
    if creatorId not in CLIENTS:
        CLIENTS[creatorId] = set()
    CLIENTS[creatorId].add(auctionID)

    for clientId in participatingClients:
        if clientId not in CLIENTS:
            CLIENTS[clientId] = set()
        CLIENTS[clientId].add(auctionID)

        if auction.getAuctionInfo()["type"] == "BlindShown":
            del CLIENTS_BIDS_COUNT[clientId][auctionID]

    #Moves auction from openAuctions to closedAuctions 
    CLOSED_AUCTIONS[auctionID] = OPEN_AUCTIONS.pop(auctionID)

    sendEncryptedMessage(sock, {"winnerBid":winnerBid}, symmetricEncryption, sessionId, 5)

    mutex.release()

def validateAuction(sock, symmetricEncryption, sessionId):

    auctionsList = []

    mutex.acquire()

    for auction in OPEN_AUCTIONS.values():
        auctionsList.append(auction.getAuctionInfo())
    for auction in CLOSED_AUCTIONS.values():
        auctionsList.append(auction.getAuctionInfo())

    #sends list with all closed auctions
    sendEncryptedMessage(sock, {"auctionList" : auctionsList}, symmetricEncryption, sessionId, 4)

    mandatoryFields = []
    mandatoryFields.append(Field("auctionId", int))
    msg = readMessage(sock, mandatoryFields, symmetricEncryption, sessionId, 5)

    auctionId = msg["auctionId"]

    if auctionId in OPEN_AUCTIONS.keys():
        sendEncryptedMessage(sock, {"allData":OPEN_AUCTIONS[auctionId].getAllData()}, symmetricEncryption, sessionId, 6)
    elif auctionId in CLOSED_AUCTIONS.keys():
        sendEncryptedMessage(sock, {"allData":CLOSED_AUCTIONS[auctionId].getAllData()}, symmetricEncryption, sessionId, 6)
    else:
        sendEncryptedMessage(sock, {"error" : "No auction with that id"}, symmetricEncryption, sessionId, 6)

    mutex.release()

class APS(threading.Thread):
    def __init__(self, conn):
        super(APS, self).__init__()
        self.conn = conn

    def run(self):
        symmetricEncryption, clientCert, clientIsServer, sessionId = handshake.serverHandShake(self.conn, privateKey, certificate)

        mandatoryFields = []
        mandatoryFields.append(Field("action", int))
        msg = readMessage(self.conn, mandatoryFields, symmetricEncryption, sessionId, 3)

        #client's requests
        if msg["action"] == ActionTypes.NEW_BID:
            if clientIsServer:
                sendEncryptedMessage(self.conn, {"error":"Action not allowed"}, symmetricEncryption, sessionId, 4)
                return
            newBid(self.conn, clientCert, symmetricEncryption, sessionId)
        elif msg["action"] == ActionTypes.LIST_ALL_OPEN_AUCTIONS:
            if clientIsServer:
                sendEncryptedMessage(self.conn, {"error":"Action not allowed"}, symmetricEncryption, sessionId, 4)
                return
            listAllOpenAuctions(self.conn, symmetricEncryption, sessionId)
        elif msg["action"] == ActionTypes.LIST_ALL_CLOSED_AUCTIONS:
            if clientIsServer:
                sendEncryptedMessage(self.conn, {"error":"Action not allowed"}, symmetricEncryption, sessionId, 4)
                return
            listAllClosedAuctions(self.conn, symmetricEncryption, sessionId)
        elif msg["action"] == ActionTypes.LIST_ALL_CLIENT_BIDS:
            if clientIsServer:
                sendEncryptedMessage(self.conn, {"error":"Action not allowed"}, symmetricEncryption, sessionId, 4)
                return
            listAllClientBids(self.conn, symmetricEncryption, sessionId)
        elif msg["action"] == ActionTypes.LIST_ALL_AUCTION_BIDS:
            if clientIsServer:
                sendEncryptedMessage(self.conn, {"error":"Action not allowed"}, symmetricEncryption, sessionId, 4)
                return
            listAllAuctionBids(self.conn, symmetricEncryption, sessionId)
        elif msg["action"] == ActionTypes.CHECK_OUTCOME_OF_AUCTION:
            if clientIsServer:
                sendEncryptedMessage(self.conn, {"error":"Action not allowed"}, symmetricEncryption, sessionId, 4)
                return
            checkOutcomeOfAuction(self.conn, clientCert, symmetricEncryption, sessionId)
        elif msg["action"] == ActionTypes.VALIDATE_RECEIPT:
            if clientIsServer:
                sendEncryptedMessage(self.conn, {"error":"Action not allowed"}, symmetricEncryption, sessionId, 4)
                return
            validateReceipt(self.conn, clientCert,symmetricEncryption, sessionId)
        elif msg["action"] == ActionTypes.VALIDATE_AUCTION:
            if clientIsServer:
                sendEncryptedMessage(self.conn, {"error":"Action not allowed"}, symmetricEncryption, sessionId, 4)
                return
            validateAuction(self.conn, symmetricEncryption, sessionId)
        #manager's requests
        elif msg["action"] == ActionTypes.CREATE_AUCTION:
            if not clientIsServer:
                sendEncryptedMessage(self.conn, {"error":"Action not allowed"}, symmetricEncryption, sessionId, 4)
                return
            createAuction(self.conn, symmetricEncryption, sessionId)
        elif msg["action"] == ActionTypes.CLOSE_AUCTION:
            if not clientIsServer:
                sendEncryptedMessage(self.conn, {"error":"Action not allowed"}, symmetricEncryption, sessionId, 4)
                return
            closeAuction(self.conn, symmetricEncryption, sessionId)
        else:
            sendEncryptedMessage(self.conn, {"error":"Invalid action field"}, symmetricEncryption, sessionId, 4)
            return

        self.conn.close()


def main():
    print("    ___              __  _                            \n" + \
          "   /   | __  _______/ /_(_)___  ____                  \n" + \
          "  / /| |/ / / / ___/ __/ / __ \/ __ \                 \n" + \
          " / ___ / /_/ / /__/ /_/ / /_/ / / / /                 \n" + \
          "/_/  |_\__,_/\___/\__/_/\____/_/ /_/                  \n" + \
          "    ____                        _ __                  \n" + \
          "   / __ \___  ____  ____  _____(_) /_____  _______  __\n" + \
          "  / /_/ / _ \/ __ \/ __ \/ ___/ / __/ __ \/ ___/ / / /\n" + \
          " / _, _/  __/ /_/ / /_/ (__  ) / /_/ /_/ / /  / /_/ / \n" + \
          "/_/ |_|\___/ .___/\____/____/_/\__/\____/_/   \__, /  \n" + \
          "          /_/                                /____/   ")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(constants.REPOSITORY_ADDR)
    sock.listen()

    while True:
        conn, address = sock.accept()
        
        t = APS(conn)
        t.start()
        t.join()

if __name__ == "__main__":
    main()
