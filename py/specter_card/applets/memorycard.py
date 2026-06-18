"""
MemoryCardApplet – secure storage for up to 220 bytes (seed / mnemonic / xprv).

Extends SecureApplet with get_data / store_data commands, both PIN-protected.
"""
from .secure import SecureApplet
from ..securechannel import SecureChannel
from ..diy_crypt import parse_sdiy_blob, DecryptionError  # noqa: F401 – re-exported

AID      = "B00B5111CB01"
APPLET   = "toys.MemoryCardApplet"
CLASSDIR = "MemoryCard"

_CMD_MEMORY    = 0x05
_SUBCMD_GET    = 0x00
_SUBCMD_STORE  = 0x01

MAX_DATA_LEN = 220


class MemoryCardApplet(SecureApplet):
    """
    High-level interface to the MemoryCardApplet.

    All data commands require an open, unlocked secure channel.

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
    def get_data(self, sc: SecureChannel) -> bytes:
        """
        Return the secret data stored on the card.

        The card must be unlocked (PIN-checked) before calling this.
        """
        return sc.request(bytes([_CMD_MEMORY, _SUBCMD_GET]))

    def decode_diy_data(self, sc: SecureChannel, device_secret: bytes = None) -> dict:
        """
        Retrieve and decrypt a Specter-DIY blob from the card.

        Reads the raw bytes via :meth:`get_data` and passes them to
        :func:`~specter_card.diy_crypt.parse_sdiy_blob`.

        Parameters
        ----------
        sc : SecureChannel
            An open, unlocked secure channel.
        device_secret : bytes, optional
            32-byte internal secret from the Specter-DIY device's MCU flash.
            Required when the stored blob is encrypted; not needed for
            plain-text blobs.

        Returns
        -------
        dict
            Keys:

            * ``"entropy"``   – :class:`bytes`: raw BIP-39 entropy
            * ``"encrypted"`` – :class:`bool`: whether the blob was encrypted
            * ``"mnemonic"``  – :class:`str` or ``None``: BIP-39 mnemonic
              (populated only when the ``embit`` package is available)

        Raises
        ------
        DecryptionError
            If decryption fails or the blob is not a valid Specter-DIY blob.
        """
        raw = self.get_data(sc)
        return parse_sdiy_blob(raw, device_secret=device_secret)

    def store_data(self, sc: SecureChannel, data: bytes) -> bytes:
        """
        Persist *data* on the card (up to 220 bytes) and return the stored value.

        Parameters
        ----------
        data : bytes
            Payload to store.  Maximum 220 bytes.
        """
        if len(data) > MAX_DATA_LEN:
            raise ValueError(f"Maximum data size is {MAX_DATA_LEN} bytes")
        return sc.request(bytes([_CMD_MEMORY, _SUBCMD_STORE]) + data)
