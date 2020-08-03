#!/usr/bin/env python3
import unittest, os
from util.securechannel import SecureChannel, SecureError

AID = "B00B5111FF01"
APPLET = "toys.SecureApplet"
CLASSDIR = "SecureApplet"

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

SELECT     = b"\x00\xA4\x04\x00"
GET_RANDOM = b"\xB0\xB1\x00\x00"
GET_PUBKEY = b"\xB0\xB2\x00\x00"

def encode(data):
    return bytes([len(data)])+data

class SecureAppletTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_secure_channel(self, open=True):
        sc = SecureChannel(sim)
        sc.open()
        self.assertEqual(sc.is_open, True)
        return sc

    def test_select(self):
        # selecting applet
        data = SELECT+encode(bytes.fromhex(AID))
        res = sim.request(data)
        self.assertEqual(res, b"")

    def test_random(self):
        # test default value
        d1 = sim.request(GET_RANDOM)
        d2 = sim.request(GET_RANDOM)
        self.assertNotEqual(d1, d2)
        self.assertEqual(len(d1), 32)

    def test_pubkey(self):
        pub = sim.request(GET_PUBKEY)
        self.assertEqual(pub[0], 0x04)
        self.assertEqual(len(pub), 65)

    def test_sc(self):
        sc = self.get_secure_channel()
        # echo
        data = sc.request(b"\x00\x00ping")
        self.assertEqual(data, b"ping")
        # secure random
        d1 = sc.request(b"\x01\x00")
        d2 = sc.request(b"\x01\x00")
        self.assertNotEqual(d1, d2)
        self.assertEqual(len(d1), 32)
        # close channel
        sc.close()
        self.assertEqual(sc.is_open, False)

    def test_duplicate_sc(self):
        # open one channel
        sc1 = self.get_secure_channel()
        # open another channel
        sc2 = self.get_secure_channel()
        # first should be invalid now
        with self.assertRaises(ISOException) as e:
            # trying to get random data 
            # with outdated channel
            sc1.request(b"\x01\x00")
        sc2.close()

    def test_pin(self):
        sc = self.get_secure_channel()
        status = sc.request(b'\x03\x00')
        left, total, is_set = list(status)
        self.assertEqual(left, 10)
        self.assertEqual(total, left)
        self.assertEqual(is_set, 0)
        # if PIN is not set - check should raise
        with self.assertRaises(SecureError) as e:
            sc.request(b'\x03\x01'+b'q')
        # set PIN
        pin = b"My PIN code"
        sc.request(b"\x03\x04"+pin)
        # check if it's set and card is unlocked now
        status = sc.request(b'\x03\x00')
        left, total, is_set = list(status)
        self.assertEqual(left, 10)
        self.assertEqual(total, left)
        self.assertEqual(is_set, 2)
        # lock the card
        sc.request(b"\x03\x02")
        # check it's locked
        status = sc.request(b'\x03\x00')
        left, total, is_set = list(status)
        self.assertEqual(left, 10)
        self.assertEqual(total, left)
        self.assertEqual(is_set, 1)
        # check we can't unlock with wrong PIN
        with self.assertRaises(SecureError) as e:
            sc.request(b'\x03\x01'+pin+b'q')
        # check that we have 9 attempts now
        status = sc.request(b'\x03\x00')
        left, total, is_set = list(status)
        self.assertEqual(left, 9)
        self.assertEqual(total, 10)
        self.assertEqual(is_set, 1)
        # check we can unlock with valid PIN
        sc.request(b'\x03\x01'+pin)
        status = sc.request(b'\x03\x00')
        left, total, is_set = list(status)
        # number of attempts should be 10 again
        self.assertEqual(left, 10)
        self.assertEqual(total, 10)
        self.assertEqual(is_set, 2)

        # check we can change PIN with valid PIN
        pin2 = b"qqq"
        sc.request(b'\x03\x03'+encode(pin)+encode(pin2))
        status = sc.request(b'\x03\x00')
        left, total, is_set = list(status)
        self.assertEqual(left, 10)
        self.assertEqual(total, 10)
        self.assertEqual(is_set, 2)
        pin = pin2
        # check we can't change pin with invalid pin
        with self.assertRaises(SecureError) as e:
            sc.request(b'\x03\x03'+encode(pin2+b"q")+encode(pin2))
        # card should be locked now
        status = sc.request(b'\x03\x00')
        left, total, is_set = list(status)
        self.assertEqual(left, 9)
        self.assertEqual(total, 10)
        self.assertEqual(is_set, 1)
        # check we can't unset PIN with invalid PIN
        with self.assertRaises(SecureError) as e:
            sc.request(b'\x03\x05'+pin+b'q')
        # card should be locked now
        status = sc.request(b'\x03\x00')
        left, total, is_set = list(status)
        self.assertEqual(left, 8)
        self.assertEqual(total, 10)
        self.assertEqual(is_set, 1)

        # get random should still work 
        # even if the card is locked
        d = sc.request(b"\x01\x00")
        self.assertEqual(len(d), 32)

        # check we can unset with valid PIN
        sc.request(b'\x03\x05'+pin)
        # should be unset now
        status = sc.request(b'\x03\x00')
        left, total, is_set = list(status)
        self.assertEqual(left, 10)
        self.assertEqual(total, left)
        self.assertEqual(is_set, 0)
        sc.close()

    def test_invalid(self):
        with self.assertRaises(ISOException) as e:
            # invalid INS
            sim.request(b"\xB0\xA3\x00\x00")

        with self.assertRaises(ISOException) as e:
            # invalid CLA
            sim.request(b"\xB1\xA1\x00\x00")

if __name__ == '__main__':
    unittest.main()