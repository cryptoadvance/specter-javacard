#!/usr/bin/env python3
import unittest, os
from util.securechannel import SecureChannel, SecureError
from util import secp256k1

AID = "B00B5111CE01"
APPLET = "toys.BlindOracleApplet"
CLASSDIR = "BlindOracle"

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

    def test_root(self):
        sc = self.get_secure_channel()
        # check derivation from seed
        seed = bytes.fromhex("ae361e712e3fe66c8f1d57192d80abe076137c917d37cee7da8ed152e993226df0ced36f35c0967f96a5291f35035e87be9b3df626e6eb96ad2b59fbd9c503f4")
        expect = bytes.fromhex("5d85539e0995941e1dafd9fc27df3efea381461c13cfd245137b43bb37c29c39025a94ecdc430e6508ea7a432d1ae30e1d656194a028848f652a08bc43439b8561")
        res = sc.request(b"\x10\x00"+seed)
        self.assertEqual(res, expect)
        # check loading of xprv
        # chain code + 00 + prvkey
        root = bytes.fromhex("5d85539e0995941e1dafd9fc27df3efea381461c13cfd245137b43bb37c29c39004cfa6a4f047f2c3fcad170a3a5f0ef254f0bbe2b2bec7554043c145dcc779428")
        res = sc.request(b"\x10\x01"+root)
        self.assertEqual(res, expect)
        # check random xprv
        res = sc.request(b"\x10\x7d"+root)
        self.assertEqual(len(res), 65)
        self.assertTrue(res[32] >= 2 and res[32] <= 3)
        sc.close()

    def test_derive(self):
        sc = self.get_secure_channel()
        # load seed
        seed = bytes.fromhex("ae361e712e3fe66c8f1d57192d80abe076137c917d37cee7da8ed152e993226df0ced36f35c0967f96a5291f35035e87be9b3df626e6eb96ad2b59fbd9c503f4")
        res = sc.request(b"\x10\x00"+seed)
        # m/44h/0h/1h/0/55
        path = [44+0x80000000, 0x80000000, 0x80000001, 0, 55]
        bpath = b"".join(p.to_bytes(4,'big') for p in path)
        res = sc.request(b"\x11\x01"+b"\x00"+bpath)
        expect = bytes.fromhex("3902805bec66b8546bae3984ee186dd9d9620cead3d242bf8893e984aa472912033156b64844e8ce5f3d1d52092c9809a75bcbac93bfc9fc5b3a543842fb4d3558")
        self.assertEqual(res, expect)
        # derive first two indexes
        res = sc.request(b"\x11\x01"+b"\x00"+bpath[:8])
        # derive the rest
        res = sc.request(b"\x11\x01"+b"\x01"+bpath[8:])
        self.assertEqual(res, expect)
        # check it's stored as child
        res = sc.request(b"\x11\x02")
        self.assertEqual(res, expect)
        sc.close()

    def test_sign(self):
        sc = self.get_secure_channel()
        # load seed
        seed = bytes.fromhex("ae361e712e3fe66c8f1d57192d80abe076137c917d37cee7da8ed152e993226df0ced36f35c0967f96a5291f35035e87be9b3df626e6eb96ad2b59fbd9c503f4")
        res = sc.request(b"\x10\x00"+seed)
        # message to sign
        msg = b"5"*32
        # sign with root
        sec = bytes.fromhex("025a94ecdc430e6508ea7a432d1ae30e1d656194a028848f652a08bc43439b8561")
        pub = secp256k1.ec_pubkey_parse(sec)
        res = sc.request(b"\x11\x03"+msg+b"\x00")
        sig = secp256k1.ecdsa_signature_parse_der(res)
        self.assertTrue(secp256k1.ecdsa_verify(sig, msg, pub))
        # sign with current
        # m/44h/0h/1h/0/55
        path = [44+0x80000000, 0x80000000, 0x80000001, 0, 55]
        bpath = b"".join(p.to_bytes(4,'big') for p in path)
        res = sc.request(b"\x11\x01"+b"\x00"+bpath)
        sec = bytes.fromhex("033156b64844e8ce5f3d1d52092c9809a75bcbac93bfc9fc5b3a543842fb4d3558")
        pub = secp256k1.ec_pubkey_parse(sec)
        res = sc.request(b"\x11\x03"+msg+b"\x01")
        sig = secp256k1.ecdsa_signature_parse_der(res)
        self.assertTrue(secp256k1.ecdsa_verify(sig, msg, pub))
        # derive and sign
        # derive first two indexes
        current = sc.request(b"\x11\x01"+b"\x00"+bpath[:8])
        # derive the rest and sign
        res = sc.request(b"\x11\x04"+msg+b"\x01"+bpath[8:])
        sig = secp256k1.ecdsa_signature_parse_der(res)
        self.assertTrue(secp256k1.ecdsa_verify(sig, msg, pub))
        # check that current did not change
        res = sc.request(b"\x11\x02")
        self.assertEqual(res, current)
        sc.close()

if __name__ == '__main__':
    unittest.main()