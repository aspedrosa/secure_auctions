#!/usr/bin/python3

"""
            PrivateKey
             /      \
PrivateKeyClient PrivateKeyServer

            PublicKey
             /    \
PublicKeyClient PublicKeyServer

Contains classes to iteract with assymetric keys
    of an entity (server or client)
This way the used of theses keys are equal for both
    server and client allowing us to create code
    dependent on abstraction that have the same interface
"""

from abc import ABC, abstractmethod
from datetime import datetime
import os

#Encryption
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

#Certificates
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID

import encryption

class PrivateKey(ABC):
    """
    Used by an entity to send messages and receive messages
        from other entities to ensure authentication to
        the receiver
    Allow an entity to do operations with her
        private key
    """
    @abstractmethod
    def sign(self, message):
        """
        Encrypt a message using a private key
        The receiver has the assurance that only the entity that
            has this key could have sent this message
        """
        pass

    @abstractmethod
    def decrypt(self, cypherText):
        """
        Decrypt a message using a public key
        The sender has the assurance that only the entity that
            has this key can read the message
        """
        pass

class PublicKey(ABC):
    """
    Class created by an entiry to store and to operations
        with a public key of another entity
    """
    def __init__(self, publicKey):
        """
        publicKey : RSAPublicKey : public key extrated from a
            valid certificate
        """
        self.pubKey = publicKey

    @abstractmethod
    def encrypt(self, message):
        """
        Used by and entity to send message to another entity.
        Ensures that only that entity can see the message
        """
        pass

    @abstractmethod
    def verify(self, message, signature):
        """
        Used by and entity to receive message of another entity.
        Ensures that only that entity could have sent the message
        """
        pass

class PrivateKeyClient(PrivateKey):
    """
    In our system the authentication of the client is made
        using the portugueses citizen card so for that
        the operations using the private key have to made
        through/inside the citizen card
    """
    def sign(self, message):
        return encryption.citizenCard.sign(message)
    def decrypt(self, cypherText):
        raise TypeError("Operation not supported")

class PrivateKeyServer(PrivateKey):
    """
    Our servers in the system can load theirs private
        key and to all operations with it
    """
    def __init__(self, privateKey):
        """
        privateKey : RSAPrivateKey : loaded from encrypted file
        """
        self.privKey = privateKey

    def sign(self, message):
        return self.privKey.sign(
                 message,
                 padding.PSS(
                   mgf=padding.MGF1(SHA256()),
                   salt_length=padding.PSS.MAX_LENGTH
                 ),
                 SHA256()
               )

    def decrypt(self, cypherText):
        return self.privKey.decrypt(
                 cypherText,
                 padding.OAEP(
                   mgf=padding.MGF1(algorithm=SHA256()),
                   algorithm=SHA256(),
                   label=None
                 )
               )

class PublicKeyServer(PublicKey):
    """
    Allow a server to do operations with his public key
    """
    def __init__(self, publicKey):
        super(PublicKeyServer, self).__init__(publicKey)

    def encrypt(self, message):
        return self.pubKey.encrypt(
                 message,
                 padding.OAEP(
                   mgf=padding.MGF1(algorithm=SHA256()),
                   algorithm=SHA256(),
                   label=None
                 )
               )

    def verify(self, message, signature):
        try:
            self.pubKey.verify(
              signature,
              message,
              padding.PSS(
                mgf=padding.MGF1(SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
              ),
              SHA256()
            )
        except InvalidSignature:
            return False
        return True

class PublicKeyClient(PublicKey):
    """
    Allow the client to do operations with his public key
    """
    def __init__(self, publicKey):
        super(PublicKeyClient, self).__init__(publicKey)

    def encrypt(self, message):
        raise TypeError("Operation not supported")

    def verify(self, message, signature):
        try:
            self.pubKey.verify(
              signature,
              message,
              padding.PKCS1v15(),
              SHA256()
            )
        except InvalidSignature:
            return False
        return True

def expiredOrRevoked(cert, crls, date):
    """
    Function to check if a certificate is valid
        (if it's between the validation dates)
        (not in CRL's)
    """

    if not (cert.not_valid_before < date < cert.not_valid_after):
        return True

    if cert.issuer not in crls.keys():
        return False

    for crl in crls[cert.issuer]:
        if crl.get_revoked_certificate_by_serial_number(cert.serial_number) != None and crl.last_update < date:
            return True

    return False

CERTS_LOCATION = "encryption/certs"
CRLS_LOCATION = "encryption/crls"

def validCertificate(certBytes, date=datetime.now()):
    """
    Verifies a certificate
    -checks if it's valid (between validation dates)
    -Creates a chain with trusted CA's and intermediate CA's
    -verify signature validity within the chain

    returns Valid or not, Cause of error, certificate object, if it's a server or a client
    """
    try:
        cert = x509.load_pem_x509_certificate(certBytes, default_backend())
    except:
        print("error loading")
        return False, "Invalid certificate format", None, None

    if not cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.digital_signature:
        print("not end-entity")
        return False, "Entities communicating must be a end-entity", None, None

    #load crls
    crls = dict()
    for entry in os.scandir(CRLS_LOCATION):
        with open(CRLS_LOCATION + "/" + entry.name, "rb") as f:
            crl = x509.load_der_x509_crl(f.read(), default_backend())
            if crl.issuer not in crls.keys():
                crls[crl.issuer] = []
            crls[crl.issuer].append(crl)

    if expiredOrRevoked(cert, crls, date):
        print("certificate expired or revoked")
        return False, "Certificate expired or rovoked", None, None

    certs = dict()
    for entry in os.scandir(CERTS_LOCATION):
        if entry.is_file() and entry.name.endswith(".pem"):
            with open(CERTS_LOCATION + "/" + entry.name, "rb") as f:
                tmpCert = x509.load_pem_x509_certificate(f.read(), default_backend())
                certs[tmpCert.subject] = tmpCert

    chain = [cert]
    prev = cert
    try:
        while chain[-1].subject != chain[-1].issuer:
            tmpCert = certs[chain[-1].issuer]
            if expiredOrRevoked(tmpCert, crls, date):
                print("invalid date chain")
                return False, "A certificate in the chain expired or was revoked when signed", None, None
            if not tmpCert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.key_cert_sign:
                print("signed by nor a ca nor intermediate ca")
                return False, "Signed by nor a CA nor a intermediate CA", None, None
            chain.append(tmpCert)
            prev = tmpCert
    except: #no trusted certificate issuer found
        print("issuer not found")
        return False , "Certificate in the chain unknown", None, None

    validating = chain.pop(0)
    try:
        while len(chain) > 0:
            chain[0].public_key().verify(
              validating.signature,
              validating.tbs_certificate_bytes,
              padding.PKCS1v15(),
              validating.signature_hash_algorithm
            )

            validating = chain.pop(0)


        validating.public_key().verify(
          validating.signature,
          validating.tbs_certificate_bytes,
          padding.PKCS1v15(),
          validating.signature_hash_algorithm
        )
    except:
        print("signature invalid")
        return False, "Signature in chain not valid", None, None

    if validating.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "SIO CA":
        return True, "", cert, True
    else:
        return True, "", cert, False

def getUserInfo(cert):
    """
    Retrives from the clients citizen card it's civil number and their name
    """
    id = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value[:-1]
    name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
    return id ,"Andre"#name
