#!/usr/bin/python3

# system libraries
import socket
import threading
import sys
import json
import py_compile
from copy import deepcopy

from cryptography.hazmat.primitives.serialization import Encoding

# local libraries
import constants
from message import *
from encryption import handshake
from message import readMessage, sendEncryptedMessage, Field
from encryption.assymetric import PrivateKeyClient, getUserInfo
from utilServers import *
from encryption.handshake import POSSIB_CIPHERS, POSSIB_MODES, POSSIB_PADDING
from cryptopuzzle import calculateHashOverFields

from dynamicCode import *

from storage import *

privateKey = loadPrivateKey()
certificate = loadCertificate()

CLIENTS = dict()  # key:clientID value:list of auctionId
AUCTIONS = dict()  # key:auctionId value:auction obj

def createAuction(sock, clientCert, symmetricEncryption, sessionId):

    # Receive auction info
    mandatoryFields = []
    mandatoryFields.append(Field("name", str))
    mandatoryFields.append(Field("duration", int))
    mandatoryFields.append(Field("description", str))
    mandatoryFields.append(Field("type", str, lambda v : v in ["English", "BlindShown", "BlindHidden"]))
    mandatoryFields.append(Field("difficulty", int))
    mandatoryFields.append(Field("baseAmount", float))
    mandatoryFields.append(Field("validationCode", str))
    mandatoryFields.append(Field("modificationCode", str))
    msgRecv = readMessage(sock, mandatoryFields, symmetricEncryption, sessionId, 4)

    for code in [msgRecv["validationCode"], msgRecv["modificationCode"]]:
        with open("dummy.py", "w+") as f:
            f.write(code)

        #check syntax of validation code
        try:
            py_compile.compile("dummy.py", doraise=True)
        except py_compile.PyCompileError:
            sendEncryptedMessage(sock, {"error": "Dynamic code with syntatic errors"}, symmetricEncryption, sessionId, 5)
            return

    # Insert client id and name to auction info
    clientId, clientName = getUserInfo(clientCert)
    msgRecv["creatorId"] = clientId
    msgRecv["creatorName"] = clientName

    # Connect to repository to instantiate an auction
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2.connect(constants.REPOSITORY_ADDR)
    symmetricEncryption2, sessionId2 = handshake.clientHandShake(
        sock2, privateKey, certificate, POSSIB_CIPHERS, POSSIB_MODES, POSSIB_PADDING)

    # Send auction info
    sendEncryptedMessage(
        sock2, {"action": ActionTypes.CREATE_AUCTION}, symmetricEncryption2, sessionId2, 3)
    sendEncryptedMessage(sock2, msgRecv, symmetricEncryption2, sessionId2, 4)

    # Receive auction Id of the created auction
    msgRecv2 = readMessage(sock2, [], symmetricEncryption2, sessionId2, 5)
    auctionId = msgRecv2['auctionId']
    creationTime = msgRecv2['creationTime']

    # Create some info on manager to show if users want to close auctions
    auctionInfo = msgRecv
    auctionInfo["auctionId"] = auctionId
    auctionInfo["creationTime"] = creationTime

    # Save that info
    AUCTIONS[auctionId] = Auction(auctionInfo, msgRecv["validationCode"], msgRecv["modificationCode"], msgRecv["baseAmount"])
    if clientId in CLIENTS.keys():
        CLIENTS[clientId].append(auctionId)
    else:
        CLIENTS[clientId] = [auctionId]

    sendEncryptedMessage(sock, {"auctionId":auctionId, "creationTime":creationTime}, symmetricEncryption, sessionId, 5)

def closeAuction(sock, clientCert, symmetricEncryption, sessionId):

    # Gets clientID to receive open auctions
    clientID,clientName = getUserInfo(clientCert)

    # Verify if the current client has auction open
    if clientID not in CLIENTS.keys() or len(CLIENTS[clientID]) == 0:
        sendEncryptedMessage(sock, {"openAuctionList" : []}, symmetricEncryption, sessionId, 4)
        return

    # Gather info of all open auction of the client
    openAuctionList = []
    for auctionId in CLIENTS[clientID]:
        openAuctionList.append(AUCTIONS[auctionId].auctionInfo)

    # Sends open auctions
    sendEncryptedMessage(
        sock, {'openAuctionList': openAuctionList}, symmetricEncryption, sessionId, 4)

    # Gets auctionID to close
    mandatoryFields = []
    mandatoryFields.append(Field("auctionID", int))
    msgRecv = readMessage(sock, mandatoryFields, symmetricEncryption, sessionId, 5)
    auctionID = msgRecv['auctionID']
    auction = AUCTIONS[auctionID]

    # Connect to the repository to close the auction
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2.connect(constants.REPOSITORY_ADDR)
    symmetricEncryption2, sessionId2 = handshake.clientHandShake(
        sock2, privateKey, certificate, POSSIB_CIPHERS, POSSIB_MODES, POSSIB_PADDING)

    key = b64encode(auction.key).decode("ascii")

    # Sends the request to Repository
    sendEncryptedMessage(
        sock2, {'action': ActionTypes.CLOSE_AUCTION}, symmetricEncryption2, sessionId2, 3)
    sendEncryptedMessage(sock2, {"auctionID":auctionID , 'key': key}, symmetricEncryption2, sessionId2, 4)

    # Receive the winner bid
    msgRecv = readMessage(sock2, [], symmetricEncryption2, sessionId2, 5)

    # Send the winner bid to the creator
    sendEncryptedMessage(sock, {'winnerBid':msgRecv["winnerBid"], "key":key}, symmetricEncryption, sessionId, 6)

    # Remove local info
    AUCTIONS.pop(auctionID)
    CLIENTS[clientID].remove(auctionID)

def validateBid(sock, symmetricEncryption, sessionId):

    msg = readMessage(sock, [], symmetricEncryption, sessionId, 4)

    bid = msg["bid"]
    clientValidation = msg["clientValidation"]

    auction = AUCTIONS[bid["auctionId"]]
    type = auction.auctionInfo["type"]

    if type == "BlindShown":
        assert "countBidsDone" in msg.keys()
        countBidsDone = msg["countBidsDone"]
    else:
        countBidsDone = None

    if not bidValidation(auction.validationCode, type, deepcopy(bid), auction.lastAmount, countBidsDone):
        sendEncryptedMessage(sock, {"error":"Bid failed bid validation"}, symmetricEncryption, sessionId, 5)
        return

    payload = bidModification(auction.modificationCode, type, deepcopy(bid), auction.lastAmount, countBidsDone)

    if float(bid["amount"]) < auction.baseAmount:
        sendEncryptedMessage(sock, {"error":"Amount has to greater than the base amount"}, symmetricEncryption, sessionId, 5)
        return
    bidAmount = float(bid["amount"])
    if type == "English":
        if bidAmount <= auction.lastAmount:
            sendEncryptedMessage(sock, {"error":"Amount has to greater than the last one"}, symmetricEncryption, sessionId, 5)
            return
        else:
            auction.lastAmount = bidAmount

    if type == "English" or type == "BlindHidden":
        for field in ["clientId", "clientName", "clientCertificate", "timestamp"]:
            bid[field] = auction.encryptField(bid[field])
        clientValidation = auction.encryptField(clientValidation)

    if "Blind" in type:
        bid["amount"] = auction.encryptField(bid["amount"])
    bid["nonce"] = auction.encryptField(bid["nonce"])

    posValidation = {
        "bid":bid,
        "payload":payload,
        "clientValidation":clientValidation
    }

    signature = b64encode(privateKey.sign(calculateHashOverFields(posValidation))).decode("ascii")

    posValidation["managerValidation"] = {
                "signature":signature,
                "certificate":b64encode(certificate.public_bytes(Encoding.PEM)).decode("ascii")
            }

    sendEncryptedMessage(sock, posValidation, symmetricEncryption, sessionId, 5)

def closeAuctionTime(sock, symmetricEncryption, sessionId):

    # Receive bids to decript
    msgRecv = readMessage(sock, [], symmetricEncryption, sessionId, 4)
    auctionId = msgRecv["auctionId"]

    auction = AUCTIONS[auctionId]
    creatorId = auction.auctionInfo["creatorId"]

    cipherData = {
        "key":b64encode(auction.key).decode("ascii")
    }

    # Send data to repository
    sendEncryptedMessage(sock, cipherData, symmetricEncryption, sessionId, 5)

    # Remove local info
    AUCTIONS.pop(auctionId)
    CLIENTS[creatorId].remove(auctionId)

class APS(threading.Thread):
    def __init__(self, conn):
        super(APS, self).__init__()
        self.conn = conn

    def run(self):
        symmetricEncryption, clientCert, clientIsServer, sessionId = handshake.serverHandShake(
          self.conn, privateKey, certificate)

        mandatoryFields = []
        mandatoryFields.append(Field("action", int))
        msg = readMessage(self.conn, mandatoryFields, symmetricEncryption, sessionId, 3)

        # client's requests
        if msg["action"] == ActionTypes.CREATE_AUCTION:
            if clientIsServer:
                sendEncryptedMessage(self.conn, {"error":"Action not allowed"}, symmetricEncryption, sessionId, 4)
                return
            createAuction(self.conn, clientCert, symmetricEncryption, sessionId)
        elif msg["action"] == ActionTypes.CLOSE_AUCTION:
            if clientIsServer:
                sendEncryptedMessage(self.conn, {"error":"Action not allowed"}, symmetricEncryption, sessionId, 4)
                return
            closeAuction(self.conn, clientCert, symmetricEncryption, sessionId)
        # repository's requests
        elif msg["action"] == ActionTypes.VALIDATE_BID:
            if not clientIsServer:
                sendEncryptedMessage(self.conn, {"error":"Action not allowed"}, symmetricEncryption, sessionId, 4)
                return
            validateBid(self.conn, symmetricEncryption, sessionId)
        elif msg["action"] == ActionTypes.CLOSE_AUCTION_TIME:
            if not clientIsServer:
                sendEncryptedMessage(self.conn, {"error":"Action not allowed"}, symmetricEncryption, sessionId, 4)
                return
            closeAuctionTime(self.conn, symmetricEncryption, sessionId)
        else:
            sendEncryptedMessage(
              self.conn, {"error": "Invalid action field"}, symmetricEncryption, sessionId, 4)

        self.conn.close()


def main():
    print("    ___        __  _                        \n" +
          "   /   | _____/ /_(_)___  ____              \n" +
          "  / /| |/ ___/ __/ / __ \/ __ \             \n" +
          " / ___ / /__/ /_/ / /_/ / / / /             \n" +
          "/_/  |_\___/\__/_/\____/_/ /_/              \n" +
          "    __  ___                                 \n" +
          "   /  |/  /___ _____  ____ _____ ____  _____\n" +
          "  / /|_/ / __ `/ __ \/ __ `/ __ `/ _ \/ ___/\n" +
          " / /  / / /_/ / / / / /_/ / /_/ /  __/ /    \n" +
          "/_/  /_/\__,_/_/ /_/\__,_/\__, /\___/_/     \n" +
          "                         /____/             ")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(constants.MANAGER_ADDR)
    sock.listen()

    while True:
        conn, address = sock.accept()

        t = APS(conn)
        t.start()
        t.join()


if __name__ == "__main__":
    main()
