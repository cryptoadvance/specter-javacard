"""
BlindOracleApplet – BIP-32 HD key storage, derivation, and signing.

All commands are PIN-protected and transmitted over a secure channel.
The card stores a root key derived from a seed or imported as xprv,
and can derive child keys and sign 32-byte message hashes.

xpub format used by the card: ``<chain_code (32 bytes)><compressed_pubkey (33 bytes)>``
"""
import re
from .secure import SecureApplet
from ..securechannel import SecureChannel

AID      = "B00B5111CE01"
APPLET   = "toys.BlindOracleApplet"
CLASSDIR = "BlindOracle"

# Secure-channel command bytes
_CMD_KEY_MGMT  = 0x10
_CMD_KEY_OPS   = 0x11

_SUBCMD_SET_SEED    = 0x00
_SUBCMD_SET_ROOT    = 0x01
_SUBCMD_GEN_RANDOM  = 0x7D

_SUBCMD_GET_ROOT   = 0x00
_SUBCMD_DERIVE     = 0x01
_SUBCMD_GET_CHILD  = 0x02
_SUBCMD_SIGN       = 0x03
_SUBCMD_DERIVE_SIGN = 0x04

KEYID_ROOT  = 0x00
KEYID_CHILD = 0x01


def _parse_path(path: str) -> bytes:
    """
    Convert a BIP-32 derivation path string to packed 4-byte big-endian indexes.

    Accepted formats::

        "m/44'/0'/1'/0/55"   apostrophe for hardened
        "44h/0h/1h/0/55"     'h' suffix for hardened
        "44'/0'/1'/0/55"     no leading 'm/'

    Parameters
    ----------
    path : str
        Human-readable BIP-32 path.

    Returns
    -------
    bytes
        Sequence of 4-byte big-endian encoded derivation indexes.
    """
    path = path.strip().lstrip("m").lstrip("/")
    if not path:
        return b""
    parts = path.split("/")
    result = b""
    for part in parts:
        part = part.strip()
        hardened = part.endswith("'") or part.lower().endswith("h")
        index = int(re.sub(r"[h'H]$", "", part))
        if hardened:
            index += 0x80000000
        result += index.to_bytes(4, "big")
    return result


class BlindOracleApplet(SecureApplet):
    """
    High-level interface to the BlindOracleApplet.

    Parameters
    ----------
    connection :
        A connected :class:`~specter_card.connection.Card` or
        :class:`~specter_card.connection.Simulator` instance.
    """

    AID      = AID
    APPLET   = APPLET
    CLASSDIR = CLASSDIR

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------
    def set_seed(self, sc: SecureChannel, seed: bytes) -> bytes:
        """
        Derive a BIP-32 root key from *seed* (16–64 bytes) and store it on the card.

        Returns the root xpub as ``chain_code (32) + compressed_pubkey (33)``.
        """
        if not (16 <= len(seed) <= 64):
            raise ValueError("Seed must be between 16 and 64 bytes")
        return sc.request(bytes([_CMD_KEY_MGMT, _SUBCMD_SET_SEED]) + seed)

    def set_root_key(self, sc: SecureChannel, root_key: bytes) -> bytes:
        """
        Import an existing xprv directly.

        *root_key* must be exactly 65 bytes: ``chain_code (32) + 0x00 + private_key (32)``.

        Returns the root xpub as ``chain_code (32) + compressed_pubkey (33)``.
        """
        if len(root_key) != 65:
            raise ValueError("root_key must be 65 bytes: chain_code + 0x00 + privkey")
        return sc.request(bytes([_CMD_KEY_MGMT, _SUBCMD_SET_ROOT]) + root_key)

    def generate_random_key(self, sc: SecureChannel) -> bytes:
        """
        Generate a random root key on the card (cannot be backed up).

        Returns the root xpub as ``chain_code (32) + compressed_pubkey (33)``.
        """
        return sc.request(bytes([_CMD_KEY_MGMT, _SUBCMD_GEN_RANDOM]))

    # ------------------------------------------------------------------
    # Key derivation and retrieval
    # ------------------------------------------------------------------
    def get_root_xpub(self, sc: SecureChannel) -> bytes:
        """
        Return the root xpub: ``chain_code (32) + compressed_pubkey (33)``.
        """
        return sc.request(bytes([_CMD_KEY_OPS, _SUBCMD_GET_ROOT]))

    def derive_child(self, sc: SecureChannel, path: str, from_root: bool = True) -> bytes:
        """
        Derive a child key and cache it on the card.

        Parameters
        ----------
        path : str
            BIP-32 path (e.g. ``"m/44'/0'/1'"``).
        from_root : bool
            If ``True`` (default) derive from the root key; otherwise continue
            from the previously derived child.

        Returns
        -------
        bytes
            Derived child xpub: ``chain_code (32) + compressed_pubkey (33)``.
        """
        keyid = KEYID_ROOT if from_root else KEYID_CHILD
        bpath = _parse_path(path)
        return sc.request(bytes([_CMD_KEY_OPS, _SUBCMD_DERIVE, keyid]) + bpath)

    def get_current_child(self, sc: SecureChannel) -> bytes:
        """
        Return the currently cached child xpub (from the last :meth:`derive_child`).
        """
        return sc.request(bytes([_CMD_KEY_OPS, _SUBCMD_GET_CHILD]))

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------
    def sign(self, sc: SecureChannel, msg_hash: bytes, use_root: bool = True) -> bytes:
        """
        Sign a 32-byte message hash.

        Parameters
        ----------
        msg_hash : bytes
            The 32-byte message hash to sign.
        use_root : bool
            If ``True`` (default) sign with the root key; otherwise sign with the
            currently cached child key.

        Returns
        -------
        bytes
            DER-encoded ECDSA signature.
        """
        if len(msg_hash) != 32:
            raise ValueError("msg_hash must be exactly 32 bytes")
        keyid = KEYID_ROOT if use_root else KEYID_CHILD
        return sc.request(bytes([_CMD_KEY_OPS, _SUBCMD_SIGN]) + msg_hash + bytes([keyid]))

    def derive_and_sign(
        self,
        sc: SecureChannel,
        msg_hash: bytes,
        path: str,
        from_root: bool = True,
    ) -> bytes:
        """
        Derive a temporary key and sign *msg_hash* without changing the cached child.

        Parameters
        ----------
        msg_hash : bytes
            The 32-byte message hash to sign.
        path : str
            BIP-32 path relative to the chosen key slot.
        from_root : bool
            If ``True`` (default) derive from the root key; otherwise continue
            from the currently cached child.

        Returns
        -------
        bytes
            DER-encoded ECDSA signature.
        """
        if len(msg_hash) != 32:
            raise ValueError("msg_hash must be exactly 32 bytes")
        keyid = KEYID_ROOT if from_root else KEYID_CHILD
        bpath = _parse_path(path)
        return sc.request(
            bytes([_CMD_KEY_OPS, _SUBCMD_DERIVE_SIGN]) + msg_hash + bytes([keyid]) + bpath
        )
