#!/usr/bin/python3

import socket
from re import match
from os import urandom, scandir
import os
import random
import json
from base64 import b64decode, b64encode
import time
from pprint import pprint
from exceptions import ErrorMessage

from cryptography.hazmat.primitives.serialization import Encoding

from encryption.handshake import clientHandShake
from encryption.handshake import POSSIB_CIPHERS, POSSIB_MODES, POSSIB_PADDING
from encryption.assymetric import PrivateKeyClient, getUserInfo
from encryption.citizenCard import getCertificate

from cryptopuzzle import solveCriptopuzzle, calculateHashOverFields

from message import Field, readMessage, sendEncryptedMessage
from message import ActionTypes

import constants

from utilClient import *


def getClientCMP():
    ciphers  = POSSIB_CIPHERS.copy()
    modes = POSSIB_MODES.copy()
    paddings = POSSIB_PADDING.copy()
    no_ciphers = random.randint(1,len(POSSIB_CIPHERS) - 1)
    no_modes = random.randint(1,len(POSSIB_MODES) - 1)
    no_paddings = random.randint(1,len(POSSIB_PADDING) - 1)

    for i in range(no_ciphers):
        ciphers.remove(random.choice(ciphers))

    for i in range(no_modes):
        modes.remove(random.choice(modes))
    
    for i in range(no_paddings):
        paddings.remove(random.choice(paddings))
    
    return (ciphers, modes, paddings)

ciphers, modes, paddings = getClientCMP()

privateKey = PrivateKeyClient()

def createAuction():

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Get type of auction
    while True:
        print("########################################\n" + \
              "#                                      #\n" + \
              "#  1 - English Auction                 #\n" + \
              "#  2 - Blind Auction (Entities Shown)  #\n" + \
              "#  3 - Blind Auction (Entities Hidden) #\n" + \
              "#  0 - Go Back                         #\n" + \
              "#                                      #\n" + \
              "########################################")

        choice = input("$ ")

        if not match("^[0-9]+$", choice):
            print("ERROR: Insert a valid number!")
            continue

        choice = int(choice)

        if choice == 1:
            type = "English"
            break
        elif choice == 2:
            type = "BlindShown"
            break
        elif choice == 3:
            type = "BlindHidden"
            break
        elif choice == 0:
            return
        else:
            print("ERROR: No option {}! Choose a number from 0 to 2.".format(choice))
            continue

    # Get auction Name
    name = input("Auction name(Max 40): ")[:40]

    # Get auction duration (days:hours:minutes)
    while True:
        duration = input("Duration (days:hours:minutes): ")
        if not match("^[0-9]+:[0-9]+:[0-9]+$", duration):
            print("ERROR: Invalid input!")
            continue
        
        days, hours, minutes = duration.split(":")

        days = int(days)
        hours = int(hours)
        minutes = int(minutes)

        #convert all to minutes
        duration = (days * 24 * 60) + \
                   (hours * 60) + \
                   minutes

        if duration == 0:
            print("ERROR: Duration can't be zero")
            continue

        break

    # Get auction description
    description = input("Description (Max:200): ")[:200]

    print("Base amount")
    while True:
        baseAmount = input("$ ")

        if not match("^[0-9]+(\.[0-9][0-9]?)?$", baseAmount):
            print("ERROR: Insert a valid amount")
            continue

        baseAmount = float(baseAmount)

        if baseAmount < 0:
            print("ERROR: Insert a number greater than 0")
            continue

        break

    print("Difficulty")
    print("Value in the interval [0, 256[")
    print("Higher the number, higher the difficulty")
    while True:
        difficulty = input("$ ")

        if not match("^[0-9]+$", difficulty):
            print("ERROR: Insert a valid number!")
            continue

        difficulty = int(difficulty)

        if not (0 <= difficulty < 256):
            print("ERROR: Insert a number in the interval [0, 256[!")
            continue

        break

    #Get dinamic code of auction
    print("Validation Code")
    print("DISCLAIMER: We only do a syntax check on your code")
    print("so if there's any semantic error the auction will")
    print("reject all bids")

    print("You have acess to the variable \"data\" that is a dictionary")
    print("that has the fields:")
    if type == "English":
        print("amount")
        print("lastAmount : last amount made to this auction")
    elif type == "BlindShown":
        print("clientId")
        print("clientName")
        print("timestamp")
        print("clientCertificate")
        print("numberOfBids : Number of bids made by the creator of the bid to this auction")
    elif type == "Hidden":
        print("Nothin both identities and amount are hidden")
    print("The goal is to change the variable validBid to True or False")
    while True:
        filename = input("Filename: ")

        if filename == "":
            validationCode = ""
            break

        if not os.path.exists("code/" + filename):
            print("No such file")
            continue

        with open("code/" + filename) as f:
            validationCode = f.read()
        break

    print("---------")
    print("Modification code")
    print("DISCLAIMER: We only do a syntax check on your code")
    print("so if there's any semantic error the auction will")
    print("reject all bids")

    print("You have acess to the variable \"data\" that is a dictionary")
    print("that has the fields:")
    if type == "English":
        print("amount")
        print("lastAmount : last amount made to this auction")
    elif type == "BlindShown":
        print("clientId")
        print("clientName")
        print("timestamp")
        print("clientCertificate")
        print("numberOfBids : Number of bids made by the creator of the bid to this auction")
    elif type == "Hidden":
        print("Nothing both identities and amount are hidden")
    print("The goal is to change the variable payload with something to add to the block")
    while True:
        filename = input("Filename: ")

        if filename == "":
            modificationCode = ""
            break

        if not os.path.exists("code/" + filename):
            print("No such file")
            continue

        with open("code/" + filename) as f:
            modificationCode = f.read()
        break

    msg = {'name': name, 
           'duration': duration, 
           'description' : description,
           'type' : type,
           "difficulty":difficulty,
           "baseAmount":baseAmount,
           'validationCode':validationCode,
           "modificationCode":modificationCode
           }

    #connect to the manager to send the auction info
    sock.connect(constants.MANAGER_ADDR)
    cert = getCertificate()
    symmetricEncryption, sessionId = clientHandShake(sock, privateKey, cert, ciphers, modes, paddings)
    
    sendEncryptedMessage(sock, {"action":ActionTypes.CREATE_AUCTION}, symmetricEncryption, sessionId, 3)

    sendEncryptedMessage(sock, msg, symmetricEncryption, sessionId, 4)
    
    #get info of created auction
    msg = readMessage(sock, [], symmetricEncryption, sessionId, 5)
    
    print("Auction created successfully with id", msg["auctionId"], "on", msg["creationTime"], "(timestamp)")

    sock.close()

def newBid():

    while True:
        amount = input("Amount to bid: ")

        if not match("^[0-9]+(\.[0-9][0-9]?)?$", amount):
            print("ERROR: Insert a valid amount")
            continue

        amount = float(amount)

        break

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.connect(constants.REPOSITORY_ADDR)
    cert = getCertificate()
    symmetricEncryption, sessionId = clientHandShake(sock, privateKey, cert, ciphers, modes, paddings)

    sendEncryptedMessage(sock, {'action':ActionTypes.NEW_BID}, symmetricEncryption, sessionId, 3)

    msgRecv = readMessage(sock, [], symmetricEncryption, sessionId, 4)

    #display data
    openAuctionList = msgRecv["openAuctionList"]

    if len(openAuctionList) == 0:
        print("No open auctions")
        sock.close()
        return

    for i, auction in enumerate(openAuctionList):
        print("## {} ##".format(i+1))
        print("Auction Id:     ",     auction["auctionId"])
        print("Name:           ",     auction["name"])
        print("Description:    ",     auction["description"])
        print("Type:           ",     auction["type"])
        print("Duration:       ",     auction["duration"])
        print("Creation Time:  ",     auction["creationTime"])
        print("Difficulty:     ",     auction["difficulty"])
        print("Base amount:    ",     auction["baseAmount"])
        print("Validation Code\n"   + auction["validationCode"])
        print("Modification Code\n" + auction["modificationCode"])
        print("Creator Id:     ",     auction["creatorId"])
        print("Creator Name:   ",     auction["creatorName"])
        print("--------------------------------------\n")

    while True:
        opt = input("$ ")

        if not match("^[0-9]+$", opt):
            print("ERROR: Insert a valid number!")
            continue

        opt = int(opt)
    
        if opt < 1 or opt > len(openAuctionList):
            print("Error: Insert a number between 1 and " + str(len(openAuctionList)))
            continue

        opt -= 1

        break

    clientId, clientName = getUserInfo(cert)

    auctionId = openAuctionList[opt]["auctionId"]
    auctionType = openAuctionList[opt]["type"]
    timestamp = int(time.time())
    nonce = b64encode(urandom(32)).decode("ascii")
    bid = {
        "timestamp":timestamp,
        "clientId":clientId,
        "clientName":clientName,
        "clientCertificate":b64encode(cert.public_bytes(Encoding.PEM)).decode("ascii"),
        "amount":amount,
        "nonce":nonce,
        "auctionId":auctionId,
        "auctionType":auctionType
    }

    signature = b64encode(privateKey.sign(calculateHashOverFields(bid))).decode("ascii")

    sendEncryptedMessage(sock, {'auctionId': auctionId, "timestamp":timestamp, "nonce":nonce, "amount":amount, "signature":signature},
            symmetricEncryption, sessionId, 5)

    cryptopuzzleChallange = readMessage(sock, [], symmetricEncryption, sessionId, 6)

    nonce, newHash = solveCriptopuzzle(cryptopuzzleChallange["difficulty"], cryptopuzzleChallange["toMine"])

    sendEncryptedMessage(sock, {"nonce":nonce, "hash":newHash}, symmetricEncryption, sessionId, 7)

    msg = readMessage(sock, [], symmetricEncryption, sessionId, 8)

    if not validReceiptSignature(msg["signature"], msg["certificate"], msg["receipt"]):
        print("Signature on receipt received not valid")
        return
    else:
        print("Signature on receipt ok")

    if not os.path.exists("receipts"):
        os.mkdir("receipts")
        os.mkdir("receipts/" + clientId)

    if not os.path.exists("receipts/" + clientId):
        os.mkdir("receipts/" + clientId)

    while True:
        receiptName = input("Name for receipt: ")
        if receiptName == "":
            print("ERROR: Insert a valid name")
            continue
        break

    cryptopuzzleChallange["toMine"]["nonce"] = nonce

    receipt = {
        "whatISaw":{
            'bid': bid,
            "cryptopuzzleChallange":cryptopuzzleChallange
        },
        "received":msg
    }

    f = open("receipts/" + clientId + "/" + receiptName + ".txt", "w+")
    f.write(json.dumps({"auctionId":auctionId, "receipt":receipt}))
    f.close()

    sock.close()

def closeAuction():

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.connect(constants.MANAGER_ADDR)
    cert = getCertificate()
    symmetricEncryption, sessionId = clientHandShake(sock, privateKey, cert, ciphers, modes, paddings)

    sendEncryptedMessage(sock, {'action':ActionTypes.CLOSE_AUCTION}, symmetricEncryption, sessionId, 3)

    #get all open auctions that this client created
    msgRecv = readMessage(sock, [], symmetricEncryption, sessionId, 4)

    openAuctionList = msgRecv["openAuctionList"]

    if len(openAuctionList) == 0:
        print("No aucton to close")
        sock.close()
        return

    for i, auction in enumerate(openAuctionList):
        print("## {} ##".format(i+1))
        print("Auction Id:     ",     auction["auctionId"])
        print("Name:           ",     auction["name"])
        print("Description:    ",     auction["description"])
        print("Type:           ",     auction["type"])
        print("Duration:       ",     auction["duration"])
        print("Creation Time:  ",     auction["creationTime"])
        print("Difficulty:     ",     auction["difficulty"])
        print("Base amount:    ",     auction["baseAmount"])
        print("Validation Code\n"   + auction["validationCode"])
        print("Modification Code\n" + auction["modificationCode"])
        print("Creator Id:     ",     auction["creatorId"])
        print("Creator Name:   ",     auction["creatorName"])
        print("--------------------------------------\n")


    #choose one
    while True:
        opt = input("$ ")

        if not match("^[0-9]+$", opt):
            print("ERROR: Insert a valid number!")
            continue

        opt = int(opt)
    
        if opt < 1 or opt > len(openAuctionList):
            print("Error: Insert a number between 1 and " + str(len(openAuctionList)))
            continue

        opt -= 1

        break

    #send the serial number/auction Id of the chosen one
    sendEncryptedMessage(sock, {'auctionID':openAuctionList[opt]["auctionId"]}, symmetricEncryption, sessionId, 5)

    #wait to see if all went good
    msgRecv = readMessage(sock, [], symmetricEncryption, sessionId, 6)
    
    if msgRecv["winnerBid"] == {}:
        print("No winner!")
        return

    decryptBid(
            msgRecv["winnerBid"],
            b64decode(bytes(msgRecv["key"], "ascii"))
            )

    print("Winner Bid")
    print("Client Id:",          msgRecv["winnerBid"]["clientId"])
    print("Client Name:",        msgRecv["winnerBid"]["clientName"])
    print("Client Certificate:", msgRecv["winnerBid"]["clientCertificate"])
    print("Amount:",             msgRecv["winnerBid"]["amount"])
    print("Timestamp:",          msgRecv["winnerBid"]["timestamp"])
    print("Nonce:",              msgRecv["winnerBid"]["nonce"])
    print("Auction Id:",         msgRecv["winnerBid"]["auctionId"])
    print("Auction Type:",       msgRecv["winnerBid"]["auctionType"])

    sock.close()

def listOpenAuctions(): 

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #connect to the repository to get data
    sock.connect(constants.REPOSITORY_ADDR)
    cert = getCertificate()
    symmetricEncryption, sessionId = clientHandShake(sock, privateKey, cert, ciphers, modes, paddings)

    sendEncryptedMessage(sock, {'action':ActionTypes.LIST_ALL_OPEN_AUCTIONS}, symmetricEncryption, sessionId, 3)

    msgRecv = readMessage(sock, [], symmetricEncryption, sessionId, 4)

    #display data
    openAuctionList = msgRecv["openAuctionList"]

    if len(openAuctionList) == 0:
        print("No open auctions")
        sock.close()
        return

    for auction in openAuctionList:
        print("Auction Id:     ",     auction["auctionId"])
        print("Name:           ",     auction["name"])
        print("Description:    ",     auction["description"])
        print("Type:           ",     auction["type"])
        print("Duration:       ",     auction["duration"])
        print("Creation Time:  ",     auction["creationTime"])
        print("Difficulty:     ",     auction["difficulty"])
        print("Base amount:    ",     auction["baseAmount"])
        print("Validation Code\n"   + auction["validationCode"])
        print("Modification Code\n" + auction["modificationCode"])
        print("Creator Id:     ",     auction["creatorId"])
        print("Creator Name:   ",     auction["creatorName"])
        print("--------------------------------------\n")

    sock.close()

def listCloseAuctions():

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #connect to the repository to get data
    sock.connect(constants.REPOSITORY_ADDR)
    cert = getCertificate()
    symmetricEncryption, sessionId = clientHandShake(sock, privateKey, cert, ciphers, modes, paddings)

    sendEncryptedMessage(sock, {'action':ActionTypes.LIST_ALL_CLOSED_AUCTIONS}, symmetricEncryption, sessionId, 3)

    msgRecv = readMessage(sock, [], symmetricEncryption, sessionId, 4)

    #display data
    closedAuctionList = msgRecv["closedAuctionList"]

    if len(closedAuctionList) == 0:
        print("No closed auctions")
        sock.close()
        return

    for auction in closedAuctionList:
        print("Auction Id:     ",     auction["auctionId"])
        print("Name:           ",     auction["name"])
        print("Description:    ",     auction["description"])
        print("Type:           ",     auction["type"])
        print("Duration:       ",     auction["duration"])
        print("Creation Time:  ",     auction["creationTime"])
        print("Difficulty:     ",     auction["difficulty"])
        print("Base amount:    ",     auction["baseAmount"])
        print("Validation Code\n"   + auction["validationCode"])
        print("Modification Code\n" + auction["modificationCode"])
        print("Creator Id:     ",     auction["creatorId"])
        print("Creator Name:   ",     auction["creatorName"])
        print("--------------------------------------\n")

    sock.close()

def listAuctionBids():

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.connect(constants.REPOSITORY_ADDR)
    cert = getCertificate()
    symmetricEncryption, sessionId = clientHandShake(sock, privateKey, cert, ciphers, modes, paddings)

    sendEncryptedMessage(sock, {'action':ActionTypes.LIST_ALL_AUCTION_BIDS}, symmetricEncryption, sessionId, 3)

    msgRecv = readMessage(sock, [], symmetricEncryption, sessionId, 4)

    openAuctionList = msgRecv["auctionList"]

    if len(openAuctionList) == 0:
        print("No auctions")
        sock.close()
        return

    for i, auction in enumerate(openAuctionList):
        print("## {} ##".format(i+1))
        print("Auction Id:     ",     auction["auctionId"])
        print("Name:           ",     auction["name"])
        print("Description:    ",     auction["description"])
        print("Type:           ",     auction["type"])
        print("Duration:       ",     auction["duration"])
        print("Creation Time:  ",     auction["creationTime"])
        print("Difficulty:     ",     auction["difficulty"])
        print("Base amount:    ",     auction["baseAmount"])
        print("Validation Code\n"   + auction["validationCode"])
        print("Modification Code\n" + auction["modificationCode"])
        print("Creator Id:     ",     auction["creatorId"])
        print("Creator Name:   ",     auction["creatorName"])
        print("--------------------------------------\n")

    while True:
        opt = input("$ ")

        if not match("^[0-9]+$", opt):
            print("ERROR: Insert a valid number!")
            continue

        opt = int(opt)
    
        if opt < 1 or opt > len(openAuctionList):
            print("Error: Insert a number between 1 and " + str(len(openAuctionList)))
            continue

        opt -= 1

        break

    sendEncryptedMessage(sock, {'auctionID': openAuctionList[opt]["auctionId"]}, symmetricEncryption, sessionId, 5)

    msgRecv = readMessage(sock, [], symmetricEncryption, sessionId, 6)

    bidsList = msgRecv['bidsList']

    if len(bidsList) == 0:
        print("No bids")
        sock.close()
        return

    auctionType = openAuctionList[opt]["type"]

    if "key" in msgRecv.keys():
        key = b64decode(bytes(msgRecv["key"], "ascii"))
        for bid in bidsList:
            decryptBid(bid, key)

    for bid in bidsList:
        print("Client Id:",          bid["clientId"])
        print("Client Name:",        bid["clientName"])
        print("Client Certificate:", bid["clientCertificate"])
        print("Amount:",             bid["amount"])
        print("Timestamp:",          bid["timestamp"])
        print("Nonce:",              bid["nonce"])
        print("Auction Id:",         bid["auctionId"])
        print("Auction Type:",       bid["auctionType"])
        print("------------------------\n")

    sock.close()
    
def listClientBids():

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    clientId = input("Client Id to search: ")

    sock.connect(constants.REPOSITORY_ADDR)
    cert = getCertificate()
    symmetricEncryption, sessionId = clientHandShake(sock, privateKey, cert, ciphers, modes, paddings)

    sendEncryptedMessage(sock, {'action':ActionTypes.LIST_ALL_CLIENT_BIDS}, symmetricEncryption, sessionId, 3)
    sendEncryptedMessage(sock, {'clientId':clientId}, symmetricEncryption, sessionId, 4)

    msgRecv = readMessage(sock, [], symmetricEncryption, sessionId, 5)

    if len(msgRecv["auctionsList"]) == 0:
        print("No bids of this client")
        sock.close()
        return

    for auction in msgRecv["auctionsList"]:
        bids = []
        if type(auction) == list:
            bids = auction
        elif type(auction) == dict:
            key = b64decode(bytes(auction["key"], "ascii"))

            for bid in auction["bidsList"]:
                decryptBid(bid, key)

            bids = auction["bidsList"]
        else:
            assert False

        for bid in bids:
            print("Client Id:",          bid["clientId"])
            print("Client Name:",        bid["clientName"])
            print("Client Certificate:", bid["clientCertificate"])
            print("Amount:",             bid["amount"])
            print("Timestamp:",          bid["timestamp"])
            print("Nonce:",              bid["nonce"])
            print("Auction Id:",         bid["auctionId"])
            print("Auction Type:",       bid["auctionType"])
            print("------------------------\n")

    sock.close()

def checkOutcome():

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.connect(constants.REPOSITORY_ADDR)
    cert = getCertificate()
    symmetricEncryption, sessionId = clientHandShake(sock, privateKey, cert, ciphers, modes, paddings)

    sendEncryptedMessage(sock, {'action':ActionTypes.CHECK_OUTCOME_OF_AUCTION}, symmetricEncryption, sessionId, 3)

    msgRecv = readMessage(sock, [], symmetricEncryption, sessionId, 4)

    closedAuctionList = msgRecv["participatedAuctionList"]

    if len(closedAuctionList) == 0:
        print("No closed auctions participated")
        sock.close()
        return

    for i, auction in enumerate(closedAuctionList):
        print("## {} ##".format(i+1))
        print("Auction Id:     ",     auction["auctionId"])
        print("Name:           ",     auction["name"])
        print("Description:    ",     auction["description"])
        print("Type:           ",     auction["type"])
        print("Duration:       ",     auction["duration"])
        print("Creation Time:  ",     auction["creationTime"])
        print("Difficulty:     ",     auction["difficulty"])
        print("Base amount:    ",     auction["baseAmount"])
        print("Validation Code\n"   + auction["validationCode"])
        print("Modification Code\n" + auction["modificationCode"])
        print("Creator Id:     ",     auction["creatorId"])
        print("Creator Name:   ",     auction["creatorName"])
        print("--------------------------------------\n")

    print("Select an auction to check who won")
    while True:
        opt = input("$ ")

        if not match("^[0-9]+$", opt):
            print("ERROR: Insert a valid number!")
            continue

        opt = int(opt)
    
        if opt < 1 or opt > len(closedAuctionList):
            print("Error: Insert a number between 1 and " + str(len(closedAuctionList)))
            continue

        opt -= 1

        break

    sendEncryptedMessage(sock, {'auctionId':closedAuctionList[opt]["auctionId"]}, symmetricEncryption, sessionId, 5)

    msgRecv = readMessage(sock, [], symmetricEncryption, sessionId, 6)

    if msgRecv["winnerBid"] == {}:
        print("No winner!")
        return

    decryptBid(
            msgRecv["winnerBid"],
            b64decode(bytes(msgRecv["key"], "ascii"))
            )

    print("Winner Bid")
    print("Client Id:",          msgRecv["winnerBid"]["clientId"])
    print("Client Name:",        msgRecv["winnerBid"]["clientName"])
    print("Client Certificate:", msgRecv["winnerBid"]["clientCertificate"])
    print("Amount:",             msgRecv["winnerBid"]["amount"])
    print("Timestamp:",          msgRecv["winnerBid"]["timestamp"])
    print("Nonce:",              msgRecv["winnerBid"]["nonce"])
    print("Auction Id:",         msgRecv["winnerBid"]["auctionId"])
    print("Auction Type:",       msgRecv["winnerBid"]["auctionType"])

    sock.close()

def validateReceipt():

    receipts = []
    names = []

    cert = getCertificate()
    clientId, _ = getUserInfo(cert)

    if not os.path.exists("receipts/" + clientId):
        print("No receipts found!")
        return

    for entry in scandir("receipts/" + clientId):
        names.append(entry.name)
        with open("receipts/" + clientId + "/" + entry.name, "r") as f:
            receipts.append(json.loads(f.read()))

    for i, name in enumerate(names):
        print("## {} ##".format(i+1))
        print("Receipt name:", name)
        print("-----------------\n")

    while True:
        opt = input("$ ")

        if not match("^[0-9]+$", opt):
            print("ERROR: Insert a valid number!")
            continue

        opt = int(opt)
    
        if opt < 1 or opt > len(names):
            print("Error: Insert a number between 1 and " + str(len(names)))
            continue

        opt -= 1

        break

    receipt = receipts[opt]
    auctionId = receipt["auctionId"]
    receipt = receipt["receipt"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.connect(constants.REPOSITORY_ADDR)
    cert = getCertificate()
    symmetricEncryption, sessionId = clientHandShake(sock, privateKey, cert, ciphers, modes, paddings)

    sendEncryptedMessage(sock, {"action":ActionTypes.VALIDATE_RECEIPT}, symmetricEncryption, sessionId, 3)
    sendEncryptedMessage(sock, {"auctionId":auctionId}, symmetricEncryption, sessionId, 4)

    msgRecv = readMessage(sock, [], symmetricEncryption, sessionId, 5)

    sock.close()

    validateReceiptLoaded(receipt, msgRecv["dataToValidate"], auctionId)

def validateAuction():

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #connect to the repository to get data
    sock.connect(constants.REPOSITORY_ADDR)
    cert = getCertificate()
    symmetricEncryption, sessionId = clientHandShake(sock, privateKey, cert, ciphers, modes, paddings)

    sendEncryptedMessage(sock, {'action':ActionTypes.VALIDATE_AUCTION}, symmetricEncryption, sessionId, 3)

    msgRecv = readMessage(sock, [], symmetricEncryption, sessionId, 4)

    #display data
    auctionList = msgRecv["auctionList"]

    if len(auctionList) == 0:
        print("No auctions")
        sock.close()
        return

    for i, auction in enumerate(auctionList):
        print("## {} ##".format(i+1))
        print("Auction Id:     ",     auction["auctionId"])
        print("Name:           ",     auction["name"])
        print("Description:    ",     auction["description"])
        print("Type:           ",     auction["type"])
        print("Duration:       ",     auction["duration"])
        print("Creation Time:  ",     auction["creationTime"])
        print("Difficulty:     ",     auction["difficulty"])
        print("Base amount:    ",     auction["baseAmount"])
        print("Validation Code\n"   + auction["validationCode"])
        print("Modification Code\n" + auction["modificationCode"])
        print("Creator Id:     ",     auction["creatorId"])
        print("Creator Name:   ",     auction["creatorName"])
        print("--------------------------------------\n")

    while True:
        opt = input("$ ")

        if not match("^[0-9]+$", opt):
            print("ERROR: Insert a valid number!")
            continue

        opt = int(opt)
    
        if opt < 1 or opt > len(auctionList):
            print("Error: Insert a number between 1 and " + str(len(auctionList)))
            continue

        opt -= 1

        break

    sendEncryptedMessage(sock, {"auctionId":auctionList[opt]["auctionId"]}, symmetricEncryption, sessionId, 5)

    msgRecv = readMessage(sock, [], symmetricEncryption, sessionId, 6)

    sock.close()

    validateAuctionContent(msgRecv["allData"])

def main():

    print("    ___        __  _           \n" + \
          "   /   | _____/ /_(_)___  ____ \n" + \
          "  / /| |/ ___/ __/ / __ \/ __ \\\n" + \
          " / ___ / /__/ /_/ / /_/ / / / /\n" + \
          "/_/  |_\___/\__/_/\____/_/ /_/ \n" + \
          "   _________            __     \n" + \
          "  / ____/ (_)__  ____  / /_    \n" + \
          " / /   / / / _ \/ __ \/ __/    \n" + \
          "/ /___/ / /  __/ / / / /_      \n" + \
          "\____/_/_/\___/_/ /_/\__/      ")

    while True:
        print("#####################################\n" + \
              "#                                   #\n" + \
              "#   1 - Create Auction              #\n" + \
              "#   2 - New Bid                     #\n" + \
              "#   3 - Close Auction               #\n" + \
              "#   4 - List Open Auctions          #\n" + \
              "#   5 - List Close Auctions         #\n" + \
              "#   6 - All Bids in Auction         #\n" + \
              "#   7 - All Bids Sent by a Client   #\n" + \
              "#   8 - Check Outcome               #\n" + \
              "#   9 - Validate a Receipt          #\n" + \
              "#  10 - Validate a Auction          #\n" + \
              "#   0 - Log Out                     #\n" + \
              "#                                   #\n" + \
              "#####################################")

        choice = input("$ ")

        if not match("^[0-9]+$", choice):
            print("ERROR: Insert a valid number!")
            continue

        choice = int(choice)

        if choice < 0 or choice > 10:
            print("ERROR: No option {}! Choose a number from 0 to 10.".format(choice))
            continue

        try:
            if choice == 1:
                createAuction()
            elif choice == 2:
                newBid()
            elif choice == 3:
                closeAuction()
            elif choice == 4:
                listOpenAuctions()
            elif choice == 5:
                listCloseAuctions()
            elif choice == 6:
                listAuctionBids()
            elif choice == 7:
                listClientBids()
            elif choice == 8:
                checkOutcome()
            elif choice == 9:
                validateReceipt()
            elif choice == 10:
                validateAuction()
            elif choice == 0:
                break
            else:
                assert False, "Missing some case"

        except ErrorMessage as e: 
            print(e)

if __name__ == "__main__":
    main()
