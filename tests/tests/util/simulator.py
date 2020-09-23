#!/usr/bin/env python3
import socket
import subprocess
import time
import os

CURRENT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)))
CLASSES_PATH = os.path.abspath(os.path.join(CURRENT_DIR,"../../../build/classes"))
JAR = os.path.abspath(os.path.join(CURRENT_DIR,"../../../simulator.jar"))
PORT="6666"
AID="01020304050607080901"
MAX_RESPONCE_LEN = 256
HOST = '127.0.0.1'

class ISOException(Exception):
    def __init__(self, code):
        self.code = code

class Simulator:
    def __init__(self, aid, applet, classdir):
        self.applet = applet
        self.aid = aid
        self.url = f"file://{CLASSES_PATH}/{classdir}/"
        print(self.url)

    def connect(self):
        args = ["java", "-jar", JAR, 
                "-p", PORT, 
                "-a", self.aid, 
                "-c", self.applet, 
                "-u", self.url
        ]
        self.proc = subprocess.Popen(args)
        time.sleep(1)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((HOST, int(PORT)))

    def transmit(self, apdu):
        """Mimics connection.transmit"""
        apdu = bytes(apdu)
        self.s.sendall(apdu)
        data = self.s.recv(MAX_RESPONCE_LEN)
        sw = list(data[-2:])
        responce = list(data[:-2])
        return responce, sw[0], sw[1]

    def request(self, apdu):
        """More friendly function. Raises an error if card returned an error"""
        data, *sw = self.transmit(list(apdu))
        sw = bytes(sw)
        if sw!=b"\x90\x00":
            raise ISOException(sw.hex())
        return bytes(data)

    def disconnect(self):
        self.s.close()
        self.proc.kill()
        time.sleep(1)