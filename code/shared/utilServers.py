#!/usr/bin/python3

"""
Functions used by both server
Just to compact/organize code
"""

from sys import exit
from getpass import getpass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from encryption.assymetric import PrivateKeyServer

def loadPrivateKey():
    """
    Load private key of server.
    Because the private key is encrypted it is
        asked the user the password to decrypt it.
    """
    tries = 3
    while True:
        try:
            with open("privateKey.pem", "rb") as f:
                privateKey = serialization.load_pem_private_key(
                            f.read(),
                            password=bytes(getpass("Admin Password: "), "utf-8"),
                            backend=default_backend()
                        )
            break
        except:
            print("Wrong Password")

            tries -= 1
            if tries == 0:
                print("Number of Tries Exceeded\nExiting...")
                exit(1)

    return PrivateKeyServer(privateKey)

def loadCertificate():
    """
    Load certificate of server.
    """
    with open("cert.crt", "rb") as f:
        certificate = x509.load_pem_x509_certificate(
                    f.read(),
                    default_backend()
                )

    return certificate
