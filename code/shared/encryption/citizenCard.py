#!/usr/bin/python3

"""
File that has all function/classes to do the interation
    with the portuguese citizen card
"""

import PyKCS11

pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load("/usr/local/lib/libpteidpkcs11.so")

#certificates
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend

class SlotsException(Exception):
    """
    Base exception to Exception that can
        happen using smart card reader slots
    """
    pass
class MultipleSlots(SlotsException):
    """
    When the program multiple slots.
    Must only exist one so the program
        can know wich to use
    """
    pass
class NoSlots(SlotsException):
    """
    No slots found
    """
    pass

def getSlot():
    """
    Function used to get a smart card reader slot

    raises MultipleSlots multiple slots found
    raises NoSlots no slots found
    """
    slots = pkcs11.getSlotList()

    if len(slots) > 1:
        raise MultipleSlots
    elif len(slots) == 0:
        raise NoSlots

    return slots[0]

def getCertificate():
    """
    Function used to retrieve the certificate from the users
        smart card
    """
    slot = getSlot()

    session = pkcs11.openSession(slot)
    cert = session.findObjects([
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
        (PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION CERTIFICATE")])[0] #TODO indexOutOfBounds

    data = session.getAttributeValue(cert, [PyKCS11.CKA_VALUE])[0] #TODO indexOutOfBounds
    data = bytes(data)

    session.closeSession()

    return x509.load_der_x509_certificate(data, default_backend())

def sign(message):
    """
    Function used to encrypt a message using a private key stored
        inside the smart card
    """
    slot = getSlot()

    session = pkcs11.openSession(slot)
    private_key = session.findObjects([
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
        ])[0] #TODO indexOutOfBounds

    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)

    signature = bytes(session.sign(private_key, message, mechanism))

    session.closeSession()

    return signature
