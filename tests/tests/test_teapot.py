#!/usr/bin/env python3
import unittest, os

AID = "B00B5111CA01"
APPLET = "toys.TeapotApplet"
CLASSDIR = "Teapot"

mode = os.environ.get('TEST_MODE', "simulator")
if mode=="simulator":
    from util.simulator import Simulator, ISOException
    sim = Simulator(AID, APPLET, CLASSDIR)
elif mode=="card":
    from util.card import Card, ISOException
    sim = Card(AID)
else:
    raise RuntimeError("Not supported")

def setUpModule():
    sim.connect()

def tearDownModule():
    sim.disconnect()

SELECT = b"\x00\xA4\x04\x00"
GET    = b"\xB0\xA1\x00\x00"
STORE  = b"\xB0\xA2\x00\x00"

def encode(data):
    return bytes([len(data)])+data

class TeapotTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def test_select(self):
        # selecting applet
        data = SELECT+encode(bytes.fromhex(AID))
        res = sim.request(data)
        self.assertEqual(res, b"")

    def test_storage(self):
        # test default value
        default = b"I am a teapot gimme some tea plz"
        stored = default
        data = sim.request(GET)
        self.assertEqual(data, stored)

        # check data in GET is ignored
        data = sim.request(GET+b"\x03abc")
        self.assertEqual(data, stored)

        # store something small
        stored = b"\x00\x80"
        data = sim.request(STORE+encode(stored))
        self.assertEqual(data, stored)
        # check it is actually stored
        data = sim.request(GET)
        self.assertEqual(data, stored)

        # store something large - max capacity
        stored = b"a"*254
        data = sim.request(STORE+encode(stored))
        self.assertEqual(data, stored)
        # check it is actually stored
        data = sim.request(GET)
        self.assertEqual(data, stored)

        # store empty string
        stored = b""
        data = sim.request(STORE+encode(stored))
        self.assertEqual(data, stored)
        # check it is actually stored
        data = sim.request(GET)
        self.assertEqual(data, stored)

        # set back default
        data = sim.request(STORE+encode(default))

    def test_invalid(self):
        with self.assertRaises(ISOException) as e:
            # invalid INS
            sim.request(b"\xB0\xA3\x00\x00")

        with self.assertRaises(ISOException) as e:
            # invalid CLA
            sim.request(b"\xB1\xA1\x00\x00")

if __name__ == '__main__':
    unittest.main()