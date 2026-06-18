"""
Secure channel implementation compatible with the JavaCard SecureApplet.

Supports ``ss`` (both host and card use static keys with nonces),
``es`` (host-ephemeral / card-static), and ``ee`` (both ephemeral) modes.
"""
import hashlib, hmac, os
from io import BytesIO
from cryptography.hazmat.primitives.asymmetric.ec import (
    derive_private_key, EllipticCurvePublicKey, SECP256K1, ECDH, ECDSA,
)
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

_encode = lambda data: bytes([len(data)]) + data

HMAC_LEN = 14
MAX_IV = 2 ** 16

# APDU bytes
_CLA = 0xB0
_INS_GET_PUBKEY      = 0xB2
_INS_OPEN_SS         = 0xB3  # ss mode
_INS_OPEN_SE         = 0xB4  # es mode
_INS_OPEN_EE         = 0xB5  # ee mode
_INS_SECURE_MESSAGE  = 0xB6
_INS_CLOSE           = 0xB7

_CURVE = SECP256K1()
SUPPORTED_SECURE_CHANNEL_MODES = ("ss", "es", "ee")


def _parse_pubkey(data: bytes) -> EllipticCurvePublicKey:
    """Parse a 33- or 65-byte serialized secp256k1 public key."""
    return EllipticCurvePublicKey.from_encoded_point(_CURVE, data)


def _serialize_pubkey(pub: EllipticCurvePublicKey, compressed: bool = False) -> bytes:
    fmt = PublicFormat.CompressedPoint if compressed else PublicFormat.UncompressedPoint
    return pub.public_bytes(Encoding.X962, fmt)


def _ecdh(private_key, peer_pubkey: EllipticCurvePublicKey) -> bytes:
    """Return the 32-byte x-coordinate of the ECDH shared point."""
    return private_key.exchange(ECDH(), peer_pubkey)


def _verify_sig(pub: EllipticCurvePublicKey, sig_der: bytes, msg_hash: bytes) -> bool:
    """Verify a DER-encoded ECDSA signature over a pre-computed SHA-256 hash."""
    try:
        pub.verify(sig_der, msg_hash, ECDSA(Prehashed(SHA256())))
        return True
    except InvalidSignature:
        return False


class SecureError(Exception):
    """Raised when the card returns a non-9000 code inside the secure channel."""
    def __init__(self, code: str):
        self.code = code
        super().__init__(f"Secure channel error: {code}")


class SecureChannel:
    """
    Encrypted and authenticated channel to an applet derived from SecureApplet.

    Parameters
    ----------
    card :
        A :class:`~specter_card.connection.Card` or
        :class:`~specter_card.connection.Simulator` instance.
    mode : str
        ``"ss"``, ``"es"`` (default), or ``"ee"``.
    """

    def __init__(self, card, mode: str = "es"):
        self.card = card
        self.mode = mode
        self.iv = 0
        self.is_open = False
        self._host_static_private_key = None
        self._card_pubkey = None
        self._card_aes_key = None
        self._host_aes_key = None
        self._card_mac_key = None
        self._host_mac_key = None

    # ------------------------------------------------------------------
    # Key-exchange helpers
    # ------------------------------------------------------------------
    def _get_card_pubkey(self):
        sec = self.card.request(bytes([_CLA, _INS_GET_PUBKEY, 0x00, 0x00]))
        self._card_pubkey = _parse_pubkey(sec)
        return self._card_pubkey

    def _derive_keys(self, shared_secret: bytes):
        self._host_aes_key = hashlib.sha256(b"host_aes" + shared_secret).digest()
        self._card_aes_key = hashlib.sha256(b"card_aes" + shared_secret).digest()
        self._host_mac_key = hashlib.sha256(b"host_mac" + shared_secret).digest()
        self._card_mac_key = hashlib.sha256(b"card_mac" + shared_secret).digest()

    # ------------------------------------------------------------------
    # Open / close
    # ------------------------------------------------------------------
    def open(self, mode: str = None):
        """Establish the secure channel."""
        if mode is not None:
            self.mode = mode
        if self.mode not in SUPPORTED_SECURE_CHANNEL_MODES:
            raise ValueError(
                f"Unsupported secure channel mode: {self.mode!r}. "
                f"Expected one of {SUPPORTED_SECURE_CHANNEL_MODES!r}"
            )

        if self._card_pubkey is None:
            self._get_card_pubkey()

        if self.mode == "ss":
            if self._host_static_private_key is None:
                self._host_static_private_key = derive_private_key(
                    int.from_bytes(os.urandom(32), "big"), _CURVE
                )
            host_nonce = os.urandom(32)
            host_pub_bytes = _serialize_pubkey(self._host_static_private_key.public_key())
            res = self.card.request(
                bytes([_CLA, _INS_OPEN_SS, 0x00, 0x00]) + _encode(host_pub_bytes + host_nonce)
            )
            s = BytesIO(res)
            nonce_card = s.read(32)
            recv_hmac = s.read(HMAC_LEN)
            shared_x = _ecdh(self._host_static_private_key, self._card_pubkey)
            secret_with_nonces = hashlib.sha256(shared_x + host_nonce + nonce_card).digest()
            self._derive_keys(secret_with_nonces)
            h = hmac.new(self._card_mac_key, nonce_card, digestmod="sha256")
            if h.digest()[:HMAC_LEN] != recv_hmac:
                raise RuntimeError("HMAC mismatch during SS channel open")
            data_signed = nonce_card + recv_hmac
            raw_sig = s.read()
            if not _verify_sig(self._card_pubkey, raw_sig, hashlib.sha256(data_signed).digest()):
                raise RuntimeError("Invalid card signature during SS channel open")
        elif self.mode == "ee":
            host_prv = derive_private_key(int.from_bytes(os.urandom(32), "big"), _CURVE)
            host_pub_bytes = _serialize_pubkey(host_prv.public_key())
            res = self.card.request(
                bytes([_CLA, _INS_OPEN_EE, 0x00, 0x00]) + _encode(host_pub_bytes)
            )
            s = BytesIO(res)
            card_pub_bytes = s.read(65)
            card_ephemeral_pub = _parse_pubkey(card_pub_bytes)
            shared_x = _ecdh(host_prv, card_ephemeral_pub)
            shared_secret = hashlib.sha256(shared_x).digest()
            self._derive_keys(shared_secret)
            recv_hmac = s.read(HMAC_LEN)
            h = hmac.new(self._card_mac_key, card_pub_bytes, digestmod="sha256")
            if h.digest()[:HMAC_LEN] != recv_hmac:
                raise RuntimeError("HMAC mismatch during EE channel open")
            # verify card signature
            data_signed = card_pub_bytes + recv_hmac
            raw_sig = s.read()
            if not _verify_sig(self._card_pubkey, raw_sig, hashlib.sha256(data_signed).digest()):
                raise RuntimeError("Invalid card signature during EE channel open")
        elif self.mode == "es":
            # es mode (default)
            host_prv = derive_private_key(int.from_bytes(os.urandom(32), "big"), _CURVE)
            host_pub_bytes = _serialize_pubkey(host_prv.public_key())
            res = self.card.request(
                bytes([_CLA, _INS_OPEN_SE, 0x00, 0x00]) + _encode(host_pub_bytes)
            )
            s = BytesIO(res)
            nonce_card = s.read(32)
            recv_hmac = s.read(HMAC_LEN)
            shared_x = _ecdh(host_prv, self._card_pubkey)
            secret_with_nonce = hashlib.sha256(shared_x + nonce_card).digest()
            self._derive_keys(secret_with_nonce)
            h = hmac.new(self._card_mac_key, nonce_card, digestmod="sha256")
            if h.digest()[:HMAC_LEN] != recv_hmac:
                raise RuntimeError("HMAC mismatch during ES channel open")
            data_signed = nonce_card + recv_hmac
            raw_sig = s.read()
            if not _verify_sig(self._card_pubkey, raw_sig, hashlib.sha256(data_signed).digest()):
                raise RuntimeError("Invalid card signature during ES channel open")

        self.iv = 0
        self.is_open = True

    def close(self):
        """Ask the card to close the channel and mark it as closed locally."""
        self.card.request(bytes([_CLA, _INS_CLOSE, 0x00, 0x00]))
        self.is_open = False

    # ------------------------------------------------------------------
    # Encrypt / decrypt
    # ------------------------------------------------------------------
    def _encrypt(self, data: bytes) -> bytes:
        d = data + b"\x80"
        if len(d) % 16:
            d += b"\x00" * (16 - len(d) % 16)
        iv = self.iv.to_bytes(16, "big")
        cipher = Cipher(algorithms.AES(self._host_aes_key), modes.CBC(iv))
        enc = cipher.encryptor()
        ct = enc.update(d) + enc.finalize()
        h = hmac.new(self._host_mac_key, iv + ct, digestmod="sha256")
        return ct + h.digest()[:HMAC_LEN]

    def _decrypt(self, ct: bytes) -> bytes:
        recv_hmac = ct[-HMAC_LEN:]
        ct = ct[:-HMAC_LEN]
        iv = self.iv.to_bytes(16, "big")
        h = hmac.new(self._card_mac_key, iv + ct, digestmod="sha256")
        if h.digest()[:HMAC_LEN] != recv_hmac:
            raise RuntimeError("HMAC mismatch in card response")
        cipher = Cipher(algorithms.AES(self._card_aes_key), modes.CBC(iv))
        dec = cipher.decryptor()
        plain = dec.update(ct) + dec.finalize()
        pad_start = plain.rfind(b"\x80")
        if pad_start == -1 or plain[pad_start + 1:].replace(b"\x00", b""):
            raise RuntimeError("Invalid M2 padding in card response")
        return plain[:pad_start]

    # ------------------------------------------------------------------
    # Send / receive over secure channel
    # ------------------------------------------------------------------
    def request(self, data: bytes) -> bytes:
        """
        Send *data* encrypted over the secure channel.

        Automatically re-opens the channel if iv wraps or the channel is closed.
        Raises :exc:`SecureError` if the card returns a non-9000 status inside
        the encrypted envelope.
        """
        if self.iv >= MAX_IV or not self.is_open:
            self.open()
        ct = self._encrypt(data)
        res = self.card.request(
            bytes([_CLA, _INS_SECURE_MESSAGE, 0x00, 0x00]) + _encode(ct)
        )
        plaintext = self._decrypt(res)
        self.iv += 1
        if plaintext[:2] == b"\x90\x00":
            return plaintext[2:]
        raise SecureError(plaintext[:2].hex())
