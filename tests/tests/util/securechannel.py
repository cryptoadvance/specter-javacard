from util import secp256k1
import hashlib, hmac, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from io import BytesIO

encode = lambda d: bytes([len(d)])+d

class SecureError(Exception):
    def __init__(self, code):
        self.code = code

class SecureChannel:
    HMAC_LEN = 14
    def __init__(self, card):
        """Pass Card or Simulator instance here"""
        self.card = card
        self.iv = 0
        self.card_pubkey = None
        self.card_aes_key = None
        self.host_aes_key = None
        self.card_mac_key = None
        self.host_mac_key = None
        self.mode = "es"
        self.is_open = False

    def get_card_pubkey(self):
        sec = self.card.request(b"\xB0\xB2\x00\x00")
        self.card_pubkey = secp256k1.ec_pubkey_parse(sec)
        return self.card_pubkey

    def derive_keys(self, shared_secret):
        self.host_aes_key = hashlib.sha256(b'host_aes'+shared_secret).digest()
        self.card_aes_key = hashlib.sha256(b'card_aes'+shared_secret).digest()
        self.host_mac_key = hashlib.sha256(b'host_mac'+shared_secret).digest()
        self.card_mac_key = hashlib.sha256(b'card_mac'+shared_secret).digest()
        return hashlib.sha256(shared_secret).digest()[:4]

    def open(self, mode=None):
        # save mode for later - i.e. reestablish secure channel
        if mode is None:
            mode = self.mode
        else:
            self.mode = mode
        # check if we know pubkey already
        if self.card_pubkey is None:
            self.get_card_pubkey()
        # generate ephimerial key
        secret = os.urandom(32)
        host_prv = secret
        host_pub = secp256k1.ec_pubkey_create(secret)
        # ee mode - ask card to create ephimerial key and send it to us
        if mode=="ee":
            data = secp256k1.ec_pubkey_serialize(host_pub, secp256k1.EC_UNCOMPRESSED)
            # get ephimerial pubkey from the card
            res = self.card.request(b"\xB0\xB5\x00\x00"+encode(data))
            s = BytesIO(res)
            data = s.read(65)
            pub = secp256k1.ec_pubkey_parse(data)
            secp256k1.ec_pubkey_tweak_mul(pub, secret)
            shared_secret = hashlib.sha256(secp256k1.ec_pubkey_serialize(pub)[1:33]).digest()
            shared_fingerprint = self.derive_keys(shared_secret)
            recv_hmac = s.read(self.HMAC_LEN)
            h = hmac.new(self.card_mac_key, digestmod='sha256')
            h.update(data)
            expected_hmac = h.digest()[:self.HMAC_LEN]
            if expected_hmac != recv_hmac:
                raise RuntimeError("Wrong HMAC. Got %s, expected %s" % (recv_hmac.hex(),expected_hmac.hex()))
            data += recv_hmac
            raw_sig = s.read()
            sig = secp256k1.ecdsa_signature_parse_der(raw_sig)
            # in case card doesn't follow low s rule (but it should)
            sig = secp256k1.ecdsa_signature_normalize(sig)
            if not secp256k1.ecdsa_verify(sig, hashlib.sha256(data).digest(), self.card_pubkey):
                raise RuntimeError("Signature is invalid: %r", raw_sig.hex())
        # se mode - use our ephimerial key with card's static key
        else:
            data = secp256k1.ec_pubkey_serialize(host_pub, secp256k1.EC_UNCOMPRESSED)
            # ugly copy
            pub = secp256k1.ec_pubkey_parse(secp256k1.ec_pubkey_serialize(self.card_pubkey))
            secp256k1.ec_pubkey_tweak_mul(pub, secret)
            shared_secret = secp256k1.ec_pubkey_serialize(pub)[1:33]
            res = self.card.request(b"\xB0\xB4\x00\x00"+encode(data))
            s = BytesIO(res)
            nonce_card = s.read(32)
            recv_hmac = s.read(self.HMAC_LEN)
            secret_with_nonces = hashlib.sha256(shared_secret+nonce_card).digest()
            shared_fingerprint = self.derive_keys(secret_with_nonces)
            data = nonce_card
            h = hmac.new(self.card_mac_key, digestmod='sha256')
            h.update(data)
            expected_hmac = h.digest()[:self.HMAC_LEN]
            if expected_hmac != recv_hmac:
                raise RuntimeError("Wrong HMAC. Got %s, expected %s"%(recv_hmac.hex(),expected_hmac.hex()))
            data += recv_hmac
            sig = secp256k1.ecdsa_signature_parse_der(s.read())
            # in case card doesn't follow low s rule (but it should)
            sig = secp256k1.ecdsa_signature_normalize(sig)
            if not secp256k1.ecdsa_verify(sig, hashlib.sha256(data).digest(), self.card_pubkey):
                raise RuntimeError("Signature is invalid")
        # reset iv
        self.iv = 0
        self.is_open = True

    def encrypt(self, data):
        # add padding
        d = data+b'\x80'
        if len(d)%16 != 0:
            d += b'\x00'*(16 - (len(d)%16))
        iv = self.iv.to_bytes(16, 'big')
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.host_aes_key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(d)+encryptor.finalize()
        h = hmac.new(self.host_mac_key, digestmod='sha256')
        h.update(iv)
        h.update(ct)
        ct += h.digest()[:self.HMAC_LEN]
        return ct
    
    def decrypt(self, ct):
        recv_hmac = ct[-self.HMAC_LEN:]
        ct = ct[:-self.HMAC_LEN]
        iv = self.iv.to_bytes(16, 'big')
        h = hmac.new(self.card_mac_key, digestmod='sha256')
        h.update(iv)
        h.update(ct)
        expected_hmac = h.digest()[:self.HMAC_LEN]
        if expected_hmac != recv_hmac:
            raise RuntimeError("Wrong HMAC. Got %s, expected %s"%(recv_hmac.hex(),expected_hmac.hex()))
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.card_aes_key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        # check and remove \x80... padding
        plain = decryptor.update(ct)+decryptor.finalize()
        arr = plain.split(b"\x80")
        if len(arr)==1 or len(arr[-1].replace(b'\x00',b''))>0:
            raise RuntimeError("Wrong padding")
        return (b"\x80".join(arr[:-1]))
    
    def request(self, data):
        # if counter reached maximum - reestablish channel
        if self.iv >= 2**16 or not self.is_open:
            self.establish_secure_channel()
        ct = self.encrypt(data)
        res = self.card.request(b"\xB0\xB6\x00\x00"+(bytes([len(ct)])+ct))
        plaintext = self.decrypt(res)
        self.iv += 1
        if plaintext[:2] == b'\x90\x00':
            return plaintext[2:]
        else:
            raise SecureError(plaintext[:2].hex())

    def close(self):
        self.card.request(b"\xB0\xB7\x00\x00")
        self.is_open = False
