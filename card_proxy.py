#!/usr/bin/env python3

"""
Listens on 127.0.0.1:21111 and forwards all the data to the smartcard reader.
Useful for testing Specter-DIY simulator with a real card.
"""
import socket
from smartcard.System import readers
from smartcard.CardConnection import CardConnection

PORT = 21111
HOST = '127.0.0.1'

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

def main():
    cardconn = get_connection()
    print(f"Smartcard proxy started. Connect to {HOST}:{PORT}")
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                while True:
                    apdu = conn.recv(1024)
                    print(">>>", apdu.hex())
                    if not apdu:
                        break
                    data, *sw = cardconn.transmit(list(apdu))
                    res = bytes(data)+bytes(sw)
                    print("<<<", res.hex())
                    conn.sendall(res)

if __name__ == '__main__':
    main()