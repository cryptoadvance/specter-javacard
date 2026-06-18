#!/usr/bin/env python3
import hashlib
import hmac
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    ECDSA,
    SECP256K1,
    EllipticCurvePublicKey,
    derive_private_key,
)
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "py"))

from specter_card.cli import _open_sc
from specter_card.securechannel import HMAC_LEN, SUPPORTED_SECURE_CHANNEL_MODES, SecureChannel

EXPECTED_SECURE_RANDOM = bytes(reversed(range(32)))


def _serialize_pubkey(pub):
    return pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def _parse_pubkey(data):
    return EllipticCurvePublicKey.from_encoded_point(SECP256K1(), data)


def _ecdh(private_key, peer_pubkey):
    return private_key.exchange(ECDH(), peer_pubkey)


def _pad(data):
    data += b"\x80"
    if len(data) % 16:
        data += b"\x00" * (16 - len(data) % 16)
    return data


def _unpad(data):
    pad_start = data.rfind(b"\x80")
    if pad_start == -1 or data[pad_start + 1:].replace(b"\x00", b""):
        raise RuntimeError("Invalid M2 padding")
    return data[:pad_start]


def _derive_keys(secret):
    return {
        "host_aes": hashlib.sha256(b"host_aes" + secret).digest(),
        "card_aes": hashlib.sha256(b"card_aes" + secret).digest(),
        "host_mac": hashlib.sha256(b"host_mac" + secret).digest(),
        "card_mac": hashlib.sha256(b"card_mac" + secret).digest(),
    }


class FakeSecureAppletCard:
    def __init__(self, fail_open_modes=None):
        self._curve = SECP256K1()
        self._static_private_key = derive_private_key(7, self._curve)
        self._iv = 0
        self._keys = None
        self._is_open = False
        self._fail_open_modes = set(fail_open_modes or ())
        self.connect_calls = 0
        self.disconnect_calls = 0

    def connect(self):
        self.connect_calls += 1

    def disconnect(self):
        self.disconnect_calls += 1
        self._is_open = False
        self._keys = None

    def request(self, apdu: bytes) -> bytes:
        cla, ins = apdu[0], apdu[1]
        if cla != 0xB0:
            raise RuntimeError(f"Unsupported CLA: {cla:02x}")
        payload = apdu[5:] if len(apdu) > 4 else b""

        if ins == 0xB2:
            return _serialize_pubkey(self._static_private_key.public_key())
        if ins == 0xB3:
            if "ss" in self._fail_open_modes:
                raise RuntimeError("ss mode failed")
            return self._open_ss(payload)
        if ins == 0xB4:
            if "es" in self._fail_open_modes:
                raise RuntimeError("es mode failed")
            return self._open_es(payload)
        if ins == 0xB5:
            if "ee" in self._fail_open_modes:
                raise RuntimeError("ee mode failed")
            return self._open_ee(payload)
        if ins == 0xB6:
            return self._secure_message(payload)
        if ins == 0xB7:
            self._is_open = False
            return b""
        raise RuntimeError(f"Unsupported INS: {ins:02x}")

    def _sign(self, data):
        digest = hashlib.sha256(data).digest()
        return self._static_private_key.sign(digest, ECDSA(Prehashed(SHA256())))

    def _open_ss(self, payload):
        host_pub = _parse_pubkey(payload[:65])
        host_nonce = payload[65:]
        card_nonce = bytes(range(32))
        shared_x = _ecdh(self._static_private_key, host_pub)
        secret = hashlib.sha256(shared_x + host_nonce + card_nonce).digest()
        self._keys = _derive_keys(secret)
        self._iv = 0
        self._is_open = True
        response = card_nonce
        response += hmac.new(self._keys["card_mac"], card_nonce, digestmod="sha256").digest()[:HMAC_LEN]
        return response + self._sign(response)

    def _open_es(self, payload):
        host_pub = _parse_pubkey(payload)
        card_nonce = bytes(range(32, 64))
        shared_x = _ecdh(self._static_private_key, host_pub)
        secret = hashlib.sha256(shared_x + card_nonce).digest()
        self._keys = _derive_keys(secret)
        self._iv = 0
        self._is_open = True
        response = card_nonce
        response += hmac.new(self._keys["card_mac"], card_nonce, digestmod="sha256").digest()[:HMAC_LEN]
        return response + self._sign(response)

    def _open_ee(self, payload):
        host_pub = _parse_pubkey(payload)
        ephemeral_private = derive_private_key(11, self._curve)
        card_pub = _serialize_pubkey(ephemeral_private.public_key())
        shared_x = _ecdh(ephemeral_private, host_pub)
        secret = hashlib.sha256(shared_x).digest()
        self._keys = _derive_keys(secret)
        self._iv = 0
        self._is_open = True
        response = card_pub
        response += hmac.new(self._keys["card_mac"], card_pub, digestmod="sha256").digest()[:HMAC_LEN]
        return response + self._sign(response)

    def _secure_message(self, payload):
        if not self._is_open:
            raise RuntimeError("Secure channel not open")

        iv = self._iv.to_bytes(16, "big")
        recv_hmac = payload[-HMAC_LEN:]
        ciphertext = payload[:-HMAC_LEN]
        expected_hmac = hmac.new(
            self._keys["host_mac"], iv + ciphertext, digestmod="sha256"
        ).digest()[:HMAC_LEN]
        if recv_hmac != expected_hmac:
            raise RuntimeError("Host MAC mismatch")

        decryptor = Cipher(algorithms.AES(self._keys["host_aes"]), modes.CBC(iv)).decryptor()
        command = _unpad(decryptor.update(ciphertext) + decryptor.finalize())

        if command == b"\x01\x00":
            response_plain = b"\x90\x00" + EXPECTED_SECURE_RANDOM
        elif command.startswith(b"\x00\x00"):
            response_plain = b"\x90\x00" + command[2:]
        else:
            raise RuntimeError(f"Unsupported secure command: {command.hex()}")

        encryptor = Cipher(algorithms.AES(self._keys["card_aes"]), modes.CBC(iv)).encryptor()
        response_ciphertext = encryptor.update(_pad(response_plain)) + encryptor.finalize()
        response_hmac = hmac.new(
            self._keys["card_mac"], iv + response_ciphertext, digestmod="sha256"
        ).digest()[:HMAC_LEN]
        self._iv += 1
        return response_ciphertext + response_hmac


class SecureChannelModesTest(unittest.TestCase):
    def test_all_modes_secure_random(self):
        for mode in SUPPORTED_SECURE_CHANNEL_MODES:
            with self.subTest(mode=mode):
                card = FakeSecureAppletCard()
                sc = SecureChannel(card, mode=mode)
                sc.open()
                self.assertEqual(sc.request(b"\x01\x00"), EXPECTED_SECURE_RANDOM)
                self.assertEqual(sc.is_open, True)

    def test_auto_mode_prefers_ee(self):
        card = FakeSecureAppletCard()
        sc = _open_sc(card, mode="auto")
        self.assertEqual(sc.mode, "ee")
        self.assertEqual(card.working_secure_channel_mode, "ee")
        sc.close()

    def test_auto_mode_falls_back_to_es(self):
        card = FakeSecureAppletCard(fail_open_modes={"ee"})
        sc = _open_sc(card, mode="auto")
        self.assertEqual(sc.mode, "es")
        self.assertEqual(card.working_secure_channel_mode, "es")
        self.assertGreaterEqual(card.disconnect_calls, 1)
        sc.close()

    def test_forced_mode_does_not_fallback(self):
        card = FakeSecureAppletCard(fail_open_modes={"ee"})
        with self.assertRaises(RuntimeError):
            _open_sc(card, mode="ee")


if __name__ == "__main__":
    unittest.main()
