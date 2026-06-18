"""
SingleUseKeyApplet – generates a single-use key and can sign exactly once per key.

Supports both plaintext APDUs (no secure channel) and secure-channel commands.
"""
from .secure import SecureApplet
from ..securechannel import SecureChannel

AID      = "B00B5111CD01"
APPLET   = "toys.SingleUseKeyApplet"
CLASSDIR = "SingleUseKey"

# Plaintext APDU bytes
_CLA_PLAIN         = 0xB0
_INS_PLAIN         = 0xA0
_P1_GENERATE       = 0x00
_P1_GET_PUBKEY     = 0x01
_P1_SIGN           = 0x02

# Secure channel command bytes
_CMD_SINGLE_USE_KEY        = 0x20
_SUBCMD_GENERATE           = 0x00
_SUBCMD_GET_PUBKEY         = 0x01
_SUBCMD_SIGN               = 0x02


class SingleUseKeyApplet(SecureApplet):
    """
    High-level interface to the SingleUseKeyApplet.

    Each key can be used to sign **only one** message hash.  After signing,
    the key is overwritten with a new random key automatically.

    Both plaintext (no secure channel) and secure-channel variants are provided
    for every operation.  Prefer the secure-channel variants to protect against
    man-in-the-middle attacks.

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
    # Plaintext variants
    # ------------------------------------------------------------------
    def generate(self) -> bytes:
        """
        Generate a new single-use key (plaintext).

        Returns the corresponding compressed public key (33 bytes).
        """
        return self.conn.request(bytes([_CLA_PLAIN, _INS_PLAIN, _P1_GENERATE, 0x00]))

    def get_pubkey(self) -> bytes:
        """
        Return the current single-use public key (plaintext, compressed, 33 bytes).
        """
        return self.conn.request(bytes([_CLA_PLAIN, _INS_PLAIN, _P1_GET_PUBKEY, 0x00]))

    def sign(self, msg_hash: bytes) -> bytes:
        """
        Sign *msg_hash* with the current single-use key (plaintext).

        After signing, the key is automatically replaced with a new random key.

        Parameters
        ----------
        msg_hash : bytes
            Exactly 32 bytes.

        Returns
        -------
        bytes
            DER-encoded ECDSA signature.
        """
        if len(msg_hash) != 32:
            raise ValueError("msg_hash must be exactly 32 bytes")
        return self.conn.request(
            bytes([_CLA_PLAIN, _INS_PLAIN, _P1_SIGN, 0x00, len(msg_hash)]) + msg_hash
        )

    # ------------------------------------------------------------------
    # Secure-channel variants (PIN-protected)
    # ------------------------------------------------------------------
    def sc_generate(self, sc: SecureChannel) -> bytes:
        """Generate a new single-use key over the secure channel."""
        return sc.request(bytes([_CMD_SINGLE_USE_KEY, _SUBCMD_GENERATE]))

    def sc_get_pubkey(self, sc: SecureChannel) -> bytes:
        """Return the current single-use public key over the secure channel."""
        return sc.request(bytes([_CMD_SINGLE_USE_KEY, _SUBCMD_GET_PUBKEY]))

    def sc_sign(self, sc: SecureChannel, msg_hash: bytes) -> bytes:
        """
        Sign *msg_hash* over the secure channel.

        After signing, the key is automatically replaced with a new random key.

        Parameters
        ----------
        msg_hash : bytes
            Exactly 32 bytes.

        Returns
        -------
        bytes
            DER-encoded ECDSA signature.
        """
        if len(msg_hash) != 32:
            raise ValueError("msg_hash must be exactly 32 bytes")
        return sc.request(bytes([_CMD_SINGLE_USE_KEY, _SUBCMD_SIGN]) + msg_hash)
