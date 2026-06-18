"""
TeapotApplet – simple plaintext key/value store (no PIN, no secure channel).
"""
from ..connection import ISOException

# APDU constants
_CLA   = 0xB0
_INS_GET   = 0xA1
_INS_STORE = 0xA2

AID      = "B00B5111CA01"
APPLET   = "toys.TeapotApplet"
CLASSDIR = "Teapot"


class TeapotApplet:
    """
    High-level interface to the TeapotApplet.

    Parameters
    ----------
    connection :
        A connected :class:`~specter_card.connection.Card` or
        :class:`~specter_card.connection.Simulator` instance.
    """

    AID      = AID
    APPLET   = APPLET
    CLASSDIR = CLASSDIR

    def __init__(self, connection):
        self.conn = connection

    # ------------------------------------------------------------------
    def get(self) -> bytes:
        """Return the bytes currently stored on the card."""
        return self.conn.request(bytes([_CLA, _INS_GET, 0x00, 0x00]))

    def store(self, data: bytes) -> bytes:
        """
        Write *data* (up to 254 bytes) to the card and return the stored value.

        Parameters
        ----------
        data : bytes
            Payload to persist.  Maximum 254 bytes.

        Raises
        ------
        ISOException
            If the card returns SW 0x6700 (wrong length) or another error.
        """
        if len(data) > 254:
            raise ValueError("Maximum storage is 254 bytes")
        payload = bytes([_CLA, _INS_STORE, 0x00, 0x00, len(data)]) + data
        return self.conn.request(payload)
