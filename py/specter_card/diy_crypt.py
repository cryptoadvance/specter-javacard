"""Specter-DIY storage format decoder.

Implements the same crypto primitives used by the Specter-DIY firmware's
MemoryCard keystore (``src/keystore/memorycard.py`` in specter-diy) so that
blobs stored on a MemoryCard applet can be decrypted and parsed offline.

Two storage modes exist:

* **Encrypted** – key derived from the Specter-DIY device's internal secret:

  .. code-block:: python

      key        = tagged_hash("scenc", device_secret)
      fingerprint = tagged_hash("scid",  device_secret)[:4]

* **Unencrypted** – fixed public key (user opted to store in plain text):

  .. code-block:: python

      key        = b"\\xcc" * 32
      fingerprint = b"\\x00" * 4

Blob wire format (output of specter-diy's ``aead_encrypt``):

.. code-block:: text

    compact_varint(len(adata)) | adata | IV(16) | AES-CBC(padded_plaintext) | HMAC-SHA256(32)

TLV plaintext (single-byte key, single-byte length):

.. code-block:: text

    \\x01 <len> <enc_key>   – optional encryption-key field
    \\x02 <len> <entropy>   – BIP-39 entropy bytes (16–32 bytes)
"""
import hashlib
import hmac as _hmac
import struct
from io import BytesIO

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__all__ = [
    "tagged_hash",
    "aead_decrypt",
    "parse_sdiy_blob",
    "DecryptionError",
]

# ── constants ────────────────────────────────────────────────────────────────

_SDIY_MAGIC = b"sdiy\x00"
_FIXED_KEY  = b"\xcc" * 32   # key used for unencrypted storage
_FIXED_FP   = b"\x00" * 4    # fingerprint used for unencrypted storage
_IV_SIZE    = 16
_MAC_SIZE   = 32
_BLOCK      = 16


# ── exceptions ───────────────────────────────────────────────────────────────

class DecryptionError(Exception):
    """Raised when decryption or format validation fails."""


# ── low-level primitives ─────────────────────────────────────────────────────

def tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP-Schnorr style tagged hash: ``SHA256(SHA256(tag) || SHA256(tag) || data)``."""
    hashtag = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(hashtag + hashtag + data).digest()


def _compact_read(stream) -> int:
    """Read a Bitcoin CompactSize (varint) integer from *stream*."""
    first = stream.read(1)
    if not first:
        raise DecryptionError("Truncated compact varint")
    v = first[0]
    if v < 0xFD:
        return v
    if v == 0xFD:
        raw = stream.read(2)
        if len(raw) < 2:
            raise DecryptionError("Truncated compact varint (0xFD)")
        return struct.unpack_from("<H", raw)[0]
    if v == 0xFE:
        raw = stream.read(4)
        if len(raw) < 4:
            raise DecryptionError("Truncated compact varint (0xFE)")
        return struct.unpack_from("<I", raw)[0]
    raw = stream.read(8)
    if len(raw) < 8:
        raise DecryptionError("Truncated compact varint (0xFF)")
    return struct.unpack_from("<Q", raw)[0]


def _aes_cbc_decrypt(data: bytes, key: bytes) -> bytes:
    """AES-CBC decrypt; the first 16 bytes of *data* are the IV."""
    if len(data) < _IV_SIZE:
        raise DecryptionError("Ciphertext too short for IV")
    iv, ct = data[:_IV_SIZE], data[_IV_SIZE:]
    if len(ct) % _BLOCK != 0:
        raise DecryptionError("Ciphertext length is not a multiple of the AES block size")
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(ct) + dec.finalize()


def _remove_sdiy_padding(data: bytes) -> bytes:
    """Remove the ``0x80 + zero*`` padding added by specter-diy's ``encrypt()``."""
    idx = data.rfind(b"\x80")
    if idx < 0:
        raise DecryptionError("Padding byte 0x80 not found in decrypted data")
    tail = data[idx + 1:]
    if tail != b"\x00" * len(tail):
        raise DecryptionError("Invalid padding: non-zero bytes after 0x80")
    return data[:idx]


# ── public API ───────────────────────────────────────────────────────────────

def aead_decrypt(ciphertext: bytes, key: bytes):
    """Verify HMAC and decrypt a specter-diy AEAD blob.

    Parameters
    ----------
    ciphertext : bytes
        Raw blob as returned by ``MemoryCardApplet.get_data()``.
    key : bytes
        32-byte decryption key.

    Returns
    -------
    adata : bytes
        Associated data (unencrypted prefix – includes MAGIC + fingerprint).
    plaintext : bytes
        Decrypted TLV payload.

    Raises
    ------
    DecryptionError
        On HMAC mismatch or any format error.
    """
    if len(ciphertext) < _MAC_SIZE:
        raise DecryptionError("Ciphertext too short")

    mac_expected = ciphertext[-_MAC_SIZE:]
    body         = ciphertext[:-_MAC_SIZE]

    aes_key  = tagged_hash("aes",  key)
    hmac_key = tagged_hash("hmac", key)

    mac_actual = _hmac.new(hmac_key, body, digestmod="sha256").digest()
    if mac_actual != mac_expected:
        raise DecryptionError("HMAC verification failed – wrong key or corrupted data")

    stream    = BytesIO(body)
    adata_len = _compact_read(stream)
    adata     = stream.read(adata_len)
    if len(adata) != adata_len:
        raise DecryptionError("Truncated associated data")

    encrypted_payload = stream.read()
    if not encrypted_payload:
        return adata, b""

    raw       = _aes_cbc_decrypt(encrypted_payload, aes_key)
    plaintext = _remove_sdiy_padding(raw)
    return adata, plaintext


def _decode_tlv(data: bytes) -> dict:
    """Parse the specter-diy TLV plaintext into a dict with string keys.

    Known fields:

    * ``"enc"``     – optional encryption-key field (tag ``0x01``)
    * ``"entropy"`` – BIP-39 entropy bytes (tag ``0x02``)
    """
    KEY_MAP = {0x01: "enc", 0x02: "entropy"}
    result  = {}
    stream  = BytesIO(data)
    while True:
        k = stream.read(1)
        if not k:
            break
        l_byte = stream.read(1)
        if not l_byte:
            raise DecryptionError("Truncated TLV: missing length byte")
        length = l_byte[0]
        value  = stream.read(length)
        if len(value) != length:
            raise DecryptionError("Truncated TLV: value shorter than declared length")
        name = KEY_MAP.get(k[0])
        if name:
            result[name] = value
    return result


def parse_sdiy_blob(raw: bytes, device_secret: bytes = None) -> dict:
    """Decrypt and parse a Specter-DIY MemoryCard blob.

    Specter-DIY stores BIP-39 entropy on the card wrapped in an AEAD envelope.
    Two modes exist:

    * **Unencrypted** – ``device_secret`` is not needed; the fixed key
      ``b"\\xcc"*32`` is used.
    * **Encrypted** – the key is ``tagged_hash("scenc", device_secret)``.
      *device_secret* is the 32-byte internal secret stored in the
      Specter-DIY device's MCU flash (found at ``<storage_path>/secret``).

    Parameters
    ----------
    raw : bytes
        Raw bytes returned by ``MemoryCardApplet.get_data()``.
    device_secret : bytes, optional
        32-byte device secret.  Required for encrypted blobs; ignored for
        unencrypted blobs.

    Returns
    -------
    dict
        Keys:

        * ``"entropy"``   – :class:`bytes`: raw BIP-39 entropy (16–32 bytes)
        * ``"encrypted"`` – :class:`bool`: whether the blob was encrypted
        * ``"mnemonic"``  – :class:`str` or ``None``: BIP-39 mnemonic phrase
          (populated only when the ``embit`` package is available)

    Raises
    ------
    DecryptionError
        If decryption fails or the blob is not a valid Specter-DIY storage blob.
    """
    if len(raw) == 0:
        raise DecryptionError("Card returned empty data – no secret is stored")

    # Minimum blob: 0x09 (varint) + 9-byte adata + 32-byte HMAC = 42 bytes.
    # adata = MAGIC(5) + fingerprint(4)
    _MIN_LEN = 1 + len(_SDIY_MAGIC) + 4 + _MAC_SIZE
    if len(raw) < _MIN_LEN:
        raise DecryptionError("Blob too short to be a valid Specter-DIY storage blob")

    # Peek at the adata (without consuming the blob) to detect storage mode.
    peek = BytesIO(raw[:-_MAC_SIZE])
    adata_len  = _compact_read(peek)
    if adata_len < len(_SDIY_MAGIC) + 4:
        raise DecryptionError("Associated data is too short")
    adata_peek = peek.read(adata_len)
    if len(adata_peek) != adata_len:
        raise DecryptionError("Truncated associated data")

    if not adata_peek.startswith(_SDIY_MAGIC):
        raise DecryptionError(
            "Magic bytes not found – this does not appear to be a Specter-DIY blob"
        )

    fingerprint = adata_peek[len(_SDIY_MAGIC): len(_SDIY_MAGIC) + 4]

    if fingerprint == _FIXED_FP:
        # Unencrypted blob: fixed public key
        key       = _FIXED_KEY
        encrypted = False
    else:
        # Encrypted blob
        if device_secret is None:
            raise DecryptionError(
                "Blob is encrypted. Provide the 32-byte internal secret from the "
                "Specter-DIY device's MCU flash storage via --device-secret."
            )
        if len(device_secret) != 32:
            raise DecryptionError(
                f"device_secret must be exactly 32 bytes, got {len(device_secret)}"
            )
        expected_fp = tagged_hash("scid", device_secret)[:4]
        if fingerprint != expected_fp:
            raise DecryptionError(
                "Fingerprint mismatch – device_secret does not belong to the device "
                "that encrypted this blob."
            )
        key       = tagged_hash("scenc", device_secret)
        encrypted = True

    _, plaintext = aead_decrypt(raw, key)
    fields       = _decode_tlv(plaintext)

    if "entropy" not in fields:
        raise DecryptionError("No entropy field found in decrypted payload")

    entropy = fields["entropy"]

    # Convert entropy to a BIP-39 mnemonic when embit is available.
    mnemonic = None
    try:
        from embit import bip39 as _bip39  # optional dependency
        mnemonic = _bip39.mnemonic_from_bytes(entropy)
    except ImportError:
        pass

    return {
        "entropy":   entropy,
        "encrypted": encrypted,
        "mnemonic":  mnemonic,
    }
