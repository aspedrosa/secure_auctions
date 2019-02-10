#!/usr/bin/python3

"""
Classes and functions related to deal/interact
    with messages
"""

import json
from exceptions import ErrorMessage

from cryptography.exceptions import InvalidSignature, InvalidTag

import struct

from base64 import b64decode, b64encode

class ActionTypes:
    #Client -> Auction Manager | Auction Repository -> Auction Manager
    CREATE_AUCTION = 1
    CLOSE_AUCTION = 2
    CLOSE_AUCTION_TIME = 3
    NEW_BID = 4

    #Client -> Auction Repository
    LIST_ALL_OPEN_AUCTIONS = 5
    LIST_ALL_CLOSED_AUCTIONS = 6
    LIST_ALL_AUCTION_BIDS = 7
    LIST_ALL_CLIENT_BIDS = 8
    CHECK_OUTCOME_OF_AUCTION = 9
    VALIDATE_RECEIPT = 10
    VALIDATE_AUCTION = 11

    #Auction Manager -> Auction Repository
    VALIDATE_BID = 12

def verififyBytes(bytesData):
    """
    Function to verify if a field holds valid binary data
    """
    try:
        b64decode(bytes(bytesData, "ascii"))
        return True
    except:
        return False

class Field:
    """
    Class to represent a field of a message
    It is used to do verifications to the message
        -expected name of the field
        -expected type
        -a lambda function that can be executed
            to the value of the field
    """
    def __init__(self, name, type, verification=lambda v : True):
        self.name = name
        self.type = type
        self.verification = verification

class BytesField(Field):
    """
    Sub class of Field to represent fields of a message
        that imply a verification that is a good byte encoded strings
    """
    def __init__(self, name):
        super(BytesField, self).__init__(name, str, verififyBytes)

encryptedMandatoryFields = [
        BytesField("ct"),
        BytesField("iv_nonce"),
        BytesField("mac")
        ]

def readMessage(sock, mandatoryFields, symmetricEncryption=None, sessionId=None, sequenceNumber=None, timeout=30):
    """
    Function that works like a proxy of messages
        that checks if it's structure respects the standards
        used in the system
    Returns True if the message is valid to parse
            False if not
    """
    sock.settimeout(timeout)
    msgLen = sock.recv(4)
    msgLen = struct.unpack(">I", msgLen)[0]

    msg = b""
    while len(msg) < msgLen:
        package = sock.recv(msgLen - len(msg))
        #if not package:
        #    raise
        msg += package

    try:
        msg = msg.decode("ascii")

        msg = json.loads(msg)

        if type(msg) != dict:
            raise json.decoder.JSONDecodeError
    except UnicodeError:
        raise MessageParsingException("Can't decode message received")
    except json.decoder.JSONDecodeError:
        raise MessageParsingException("Invalid message structure")

    if symmetricEncryption != None:
        for field in encryptedMandatoryFields:
            if field.name not in msg.keys():
                raise MessageParsingException("Message with missing fields or invalid fields")
            elif field.type != type(msg[field.name]):
                raise MessageParsingException("Wrong type for field" + field.name \
                                            + ": is " + str(field.type) + " must be " + type(msg[field.name]))
            elif not field.verification(msg[field.name]):
                raise MessageParsingException("Verification for field " + field.name + "failed")

        try:
            msg = symmetricEncryption.decrypt(
                        msg["ct"],
                        msg["iv_nonce"],
                        msg["mac"],
                    )
        except (InvalidSignature, InvalidTag):
            raise messagenonauthentication


        try:
            msg = msg.decode("utf-8")

            msg = json.loads(msg)
        except UnicodeError:
            raise MessageParsingException("Can't decode message received")
        except json.decoder.JSONDecodeError:
            raise MessageParsingException("Invalid message structure")

        if "messageId" not in msg.keys():
            raise MessageParsingException("Message with missing fields or invalid fields")
        if int(b64decode(bytes(msg["messageId"], "ascii")).hex(), 16) != sessionId + sequenceNumber:
            raise MessageParsingException("Message id not valid")

        del msg["messageId"]


    if "error" in msg.keys():
        raise ErrorMessage(msg["error"])

    for field in mandatoryFields:
        if field.name not in msg.keys():
            raise MessageParsingException("Message with missing fields or invalid fields")
        elif field.type != type(msg[field.name]):
            raise MessageParsingException("Wrong type for field" + field.name \
                                        + ": is " + str(field.type) + " must be " + type(msg[field.name]))
        elif not field.verification(msg[field.name]):
            raise MessageParsingException("Verification for field " + field.name + "failed")

    return msg

def sendMessage(sock, msg):
    """
    To send a message to a socket
    """
    msgBytes = bytes(json.dumps(msg), "ascii")

    sendMsg = struct.pack(">I", len(msgBytes)) + msgBytes
    sock.sendall(sendMsg)

def sendEncryptedMessage(sock, msg, symmetricEncryption, sessionId, sequenceNumber):
    """
    To send a message to a socket encrypting it before
        sending using symmetric encryption
    """
    msg["messageId"] = b64encode((sessionId + sequenceNumber).to_bytes(33, "big")).decode("ascii")

    msgBytes = bytes(json.dumps(msg), "ascii")

    encryptedMsg = symmetricEncryption.encrypt(msgBytes)
    encryptedMsgBytes = bytes(json.dumps(encryptedMsg), "ascii")

    sendMsg = struct.pack(">I", len(encryptedMsgBytes)) + encryptedMsgBytes
    sock.sendall(sendMsg)
