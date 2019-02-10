#!/usr/bin/python3

"""
On this file there's two function used by the several
    entities of the system, clients and servers,
    to negotiate cipher algorithms and cipher keys
    before they start to communicate though encrypted
    messages
"""

#system packages
from os import urandom

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import padding
from cryptography import x509
from cryptography.exceptions import InvalidSignature

from base64 import b64decode, b64encode

#Our packages
from encryption import symetric
from encryption import assymetric

from message import Field, BytesField, readMessage, sendEncryptedMessage, sendMessage

POSSIB_AUTH_CIPHERS = [
"AESGCM", "AESCCM"
]

POSSIB_CIPHERS = [
"AESGCM", "AESCCM", "AES",
#"Camellia",
"ChaCha20",
#"CAST5",
#"SEED",
"TripleDES"]

POSSIB_MODES = [
"CBC",
"CTR",
"OFB",
"CFB", "CFB8"
]

POSSIB_PADDING = [
"PKCS7", "ANSIX923"
]

def serverHandShake(sock, privKey, cert):
    """
    Function used by server's. They execute them
        after they receive a connection from a client
        to negotiate encrypt parameter and to
        authenticate both sides
    """
    mandatoryFields = []
    verification = lambda v : all(type(s)==str for s in v)
    mandatoryFields.append(Field("supportedCiphers", list, verification))
    mandatoryFields.append(Field("supportedModes", list, verification))
    mandatoryFields.append(Field("supportedPaddings", list, verification))
    msg = readMessage(sock, mandatoryFields)

    cipherAlg = ""
    for cipher in POSSIB_CIPHERS:
        if cipher in msg["supportedCiphers"]:
            cipherAlg = cipher
            break
    if cipherAlg == "":
        raise UnkownAlgorithm("Unkown cipher algorithm")

    mode = paddingAlg = ""
    authEncryption = True
    if cipher not in POSSIB_AUTH_CIPHERS:
        authEncryption = False
        if cipher != "ChaCha20":
            for mod in POSSIB_MODES:
                if mod in msg["supportedModes"] and not (cipher == "CAST5" and mode == "CTR"):
                    mode = mod
                    break
            if mode == "":
                raise UnkownAlgorithm("Unkown cipher mode")
            
            if mode == "CBC":
                for padd in POSSIB_PADDING:
                    if padd in msg["supportedPaddings"]:
                        paddingAlg = padd
                        break

                if paddingAlg == "":
                    raise UnkownAlgorithm("Unkown padding algorithm")


    authenticationData = urandom(64)

    sendMessage(sock, {
            "chosenCipher":cipherAlg,
            "chosenMode":mode,
            "chosenPadding":paddingAlg,
            "certificate":b64encode(cert.public_bytes(Encoding.PEM)).decode("ascii"),
            "authenticationData":b64encode(authenticationData).decode("ascii")
            })
    ##################################################

    mandatoryFields = []
    mandatoryFields.append(BytesField("sharedKey"))
    mandatoryFields.append(BytesField("sessionId"))
    mandatoryFields.append(BytesField("certificate"))
    mandatoryFields.append(BytesField("signature"))
    mandatoryFields.append(BytesField("macKey"))
    msg = readMessage(sock, mandatoryFields)

    certBytes = b64decode(bytes(msg["certificate"], "ascii"))

    valid, cause, clientCert, clientIsServer = assymetric.validCertificate(certBytes)
    if not valid:
        raise InvalidCertificate("Client's invalid certificate")

    if clientIsServer:
        publicKeyClient = assymetric.PublicKeyServer(clientCert.public_key())
    else:
        publicKeyClient = assymetric.PublicKeyClient(clientCert.public_key())

    signature = b64decode(bytes(msg["signature"], "ascii"))

    try:
        publicKeyClient.verify(authenticationData, signature)
    except InvalidSignature:
        raise FailedClientAuthentication("Failed to authenticate client")

    try:
        sharedKey = privKey.decrypt(b64decode(bytes(msg["sharedKey"], "ascii")))
        sessionId = privKey.decrypt(b64decode(bytes(msg["sessionId"], "ascii")))
        sessionId = int(sessionId.hex(), 16)

        macKey = None
        if not authEncryption:
            macKey = privKey.decrypt(b64decode(bytes(msg["macKey"], "ascii")))
    except:
        raise FailedDescrytingKeys("Decryption of shared keys failed")

    symmetricEncryption = None
    if cipherAlg in POSSIB_AUTH_CIPHERS:
        symmetricEncryption = symetric.AuthenticatedEncryption(
                                        getattr(aead, cipherAlg),
                                        sharedKey
                                        )
    else:
        if cipherAlg == "ChaCha20":
            symmetricEncryption = symetric.StreamEncryption(
                                    sharedKey,
                                    macKey
                                    )
        else:
            if mode == "CBC":
                symmetricEncryption = symetric.PaddedEncryption(
                                        getattr(algorithms, cipherAlg),
                                        sharedKey,
                                        macKey,
                                        getattr(padding, paddingAlg)
                                        )
            else:
                symmetricEncryption = symetric.NonPaddedEncryption(
                                        getattr(algorithms, cipherAlg),
                                        sharedKey,
                                        macKey,
                                        getattr(modes, mode)
                                        )
    ##################################################

    mandatoryFields = []
    mandatoryFields.append(Field("handshake finish", str))
    msg = readMessage(sock, mandatoryFields, symmetricEncryption, sessionId, 1)

    sendEncryptedMessage(sock, {"handshake finish":""}, symmetricEncryption, sessionId, 2)

    return symmetricEncryption, clientCert, clientIsServer, sessionId

def clientHandShake(sock, privKey, cert,
        supportCiphers, supportModes, supportPadding):
    """
    """
    sendMessage(sock, {
            "supportedCiphers":supportCiphers,
            "supportedModes":supportModes,
            "supportedPaddings": supportPadding
            })
    ##################################################

    mandatoryFields = []
    mandatoryFields.append(BytesField("certificate"))
    mandatoryFields.append(BytesField("authenticationData"))
    mandatoryFields.append(Field("chosenCipher", str))
    mandatoryFields.append(Field("chosenMode", str))
    mandatoryFields.append(Field("chosenPadding", str))
    msg = readMessage(sock, mandatoryFields)

    certBytes = b64decode(bytes(msg["certificate"], "ascii"))

    valid, cause, serverCert, clientIsServer = assymetric.validCertificate(certBytes)
    if not clientIsServer:
        raise Exception #TODO
    if not valid:
        raise InvalidCertificate("Server's certificate not valid")

    cipher = msg["chosenCipher"]
    mode = msg["chosenMode"]
    paddingAlg = msg["chosenPadding"]

    sharedKey = macKey = symmetricEncryption = None
    if cipher not in supportCiphers:
        raise UnkownAlgorithm("Unkown cipher algorithm")
    elif cipher in POSSIB_AUTH_CIPHERS: #see if it's a cipher algorithm with authentication
        cipher = getattr(aead, cipher)
        sharedKey = urandom(32)

        symmetricEncryption = symetric.AuthenticatedEncryption(cipher, sharedKey)
    else: # if it's a valid algorithm
        macKey = urandom(SHA256.digest_size)

        if cipher == "ChaCha20":
            cipher = algorithms.ChaCha20
            sharedKey = urandom(int(max(cipher.key_sizes) / 8))
            symmetricEncryption = symetric.StreamEncryption(
                                    sharedKey,
                                    macKey
                                    )
        else:
            cipher = getattr(algorithms, cipher)
            if cipher == algorithms.AES:
                sharedKey = urandom(32)
            else:
                sharedKey = urandom(int(max(cipher.key_sizes) / 8))

            if mode not in supportModes:
                raise UnkownAlgorithm("Unkown cipher mode")
            elif mode == "CBC":
                if paddingAlg not in supportPadding:
                    raise UnkownAlgorithm("Unkown padding algorithm")

                symmetricEncryption = symetric.PaddedEncryption(
                                        cipher,
                                        sharedKey,
                                        macKey,
                                        getattr(padding, paddingAlg)
                                        )
            else:
                symmetricEncryption = symetric.NonPaddedEncryption(
                                        cipher,
                                        sharedKey,
                                        macKey,
                                        getattr(modes, mode)
                                        )

    
    publicKeyServer = assymetric.PublicKeyServer(serverCert.public_key())

    encryptedSharedKey = publicKeyServer.encrypt(sharedKey)

    authenticationData = b64decode(bytes(msg["authenticationData"], "ascii"))
    signature = privKey.sign(authenticationData)

    sessionId = urandom(32)
    encryptedSessionId = publicKeyServer.encrypt(sessionId)

    msg = {
            "sharedKey":b64encode(encryptedSharedKey).decode("ascii"),
            "sessionId":b64encode(encryptedSessionId).decode("ascii"),
            "certificate":b64encode(cert.public_bytes(Encoding.PEM)).decode("ascii"),
            "signature":b64encode(signature).decode("ascii")
        }

    if macKey != None:
        encryptedMacKey = publicKeyServer.encrypt(macKey)
        msg["macKey"] = b64encode(encryptedMacKey).decode("ascii")
    else:
        msg["macKey"] = ""

    
    sendMessage(sock, msg)
    ##################################################

    sessionId = int(sessionId.hex(), 16)

    sendEncryptedMessage(sock, {"handshake finish":""}, symmetricEncryption, sessionId, 1)
    ##################################################

    mandatoryFields = []
    mandatoryFields.append(Field("handshake finish", str))
    msg = readMessage(sock, mandatoryFields, symmetricEncryption, sessionId, 2)

    return symmetricEncryption, sessionId
