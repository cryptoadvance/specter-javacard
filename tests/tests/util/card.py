#!/usr/bin/env python3
from smartcard.System import readers
from smartcard.CardConnection import CardConnection

class ISOException(Exception):
    def __init__(self, code):
        self.code = code

def get_reader():
    """Returns first found reader """
    rarr=readers()
    if len(rarr) == 0:
        raise RuntimeError("Reader not found")
    return rarr[0]

def get_connection(reader=None, protocol=CardConnection.T1_protocol):
    """Establish connection with a card"""
    if reader is None:
        reader = get_reader()
    connection = reader.createConnection()
    connection.connect(protocol)
    return connection

def maybe_fromhex(d):
    # check if we got a string or bytes
    if hasattr(d,"encode"):
        return list(bytes.fromhex(d))
    else:
        return d

def select_applet(connection, appletID):
    """Select an applet with appletID
    appletID can be either a hex-encoded string or byte sequence
    """
    data = maybe_fromhex(appletID)
    # Select:
    # CLA = 0x00
    # INS = 0xA4
    # P1 = 0x04
    # P2 = 0x00
    # Data = the instance AID
    cmd = [0x00, # CLA
           0xA4, # INS
           0x04, # P1
           0x00, # P2
           len(data), # Lc (content length)
          ] + data + [0x00]
    data, *sw = connection.transmit(cmd)
    data = bytes(data)
    sw = bytes(sw)
    if sw == b"\x90\x00":
        return data
    else:
        raise ISOException(sw.hex())

def request(connection, APDU):
    cmd = maybe_fromhex(APDU)
    data, *sw = connection.transmit(cmd)
    data = bytes(data)
    sw = bytes(sw)
    if sw == b"\x90\x00":
        return data
    else:
        raise ISOException(sw.hex())

class Card:
    def __init__(self, aid):
        self.aid = aid
        self.conn = get_connection()

    def connect(self):
        select_applet(self.conn, self.aid)

    def transmit(self, apdu):
        return self.conn.transmit(apdu)

    def request(self, apdu):
        """More friendly function. Raises an error if card returned an error"""
        data, *sw = self.transmit(list(apdu))
        sw = bytes(sw)
        if sw!=b"\x90\x00":
            raise ISOException(sw.hex())
        return bytes(data)

    def disconnect(self):
        self.conn.disconnect()
