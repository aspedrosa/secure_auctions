#!/usr/bin/python3

"""
"""

class Error(Exception):
    pass

class HandShakeException(Error):
    pass
class UnkownAlgorithm(HandShakeException):
    pass
class InvalidCertificate(HandShakeException):
    pass
class FailedClientAuthentication(HandShakeException):
    pass
class FailedDescrytingKeys(HandShakeException):
    pass

class MessageException(Error):
    pass
class AuthenticationException(Error):
    pass
class ParsingMessageException(Error):
    pass

class ErrorMessage(Error):
    pass

#Extra exption to handle
#broken pipe
#connection refused
#timeout
