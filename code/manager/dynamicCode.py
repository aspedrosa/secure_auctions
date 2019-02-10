#!/usr/bin/python3

def bidValidation(code, auctionType, data, lastAmount, countBidsDone):
    validBid = False

    del data["nonce"]

    if auctionType == "English" or auctionType == "BlindHidden":
        for field in ["clientId", "clientName", "clientCertificate", "timestamp"]:
            del data[field]
        countBidsDone = None
    else:
        data["countBidsDone"] = countBidsDone

    if "Blind" in auctionType:
        del data["amount"]
        lastAmount = None
    else:
        data["lastAmount"] = lastAmount

    namespace = {"data":data, "validBid":validBid}
    try:
        exec(code, namespace)
    except:
        return False

    if namespace["validBid"] not in [False, True]:
        return False

    return namespace["validBid"]

def bidModification(code, auctionType, data, lastAmount, countBidsDone):
    payload = "defaultPayload"

    del data["nonce"]

    if auctionType == "English" or auctionType == "BlindHidden":
        for field in ["clientId", "clientName", "clientCertificate", "timestamp"]:
            del data[field]
        countBidsDone = None
    else:
        data["countBidsDone"] = countBidsDone

    if "Blind" in auctionType:
        del data["amount"]
        lastAmount = None
    else:
        data["lastAmount"] = lastAmount

    namespace = {"data":data, "payload":payload}
    try:
        exec(code, namespace)
    except:
        return "defaultPayload"

    return namespace["payload"]
