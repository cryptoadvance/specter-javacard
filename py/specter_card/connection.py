"""
Connection helpers: Card (real smartcard via pyscard) and Simulator (local Java simulator).
"""
import socket
import subprocess
import time
import os


def _is_card_reset_error(exc):
    """Return True if *exc* is a recoverable card-reset error.

    On Windows the WinSCard service resets the card when a T=1 transaction
    takes too long (e.g. during the ECDH+sign step of opening a secure
    channel).  The error is ``SCARD_W_RESET_CARD`` (0x80100068).  Other
    PC/SC implementations report similar "card reset" messages.
    """
    msg = str(exc)
    return "0x80100068" in msg or (
        "reset" in msg.lower() and ("card" in msg.lower() or "scard" in msg.lower())
    )

SIMULATOR_JAR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../simulator.jar")
)
CLASSES_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../build/classes")
)
SIMULATOR_HOST = "127.0.0.1"
SIMULATOR_PORT = 6666
MAX_RESPONSE_LEN = 256


class ISOException(Exception):
    """Raised when the card returns a non-9000 status word."""
    def __init__(self, code):
        self.code = code
        super().__init__(f"ISO error: {code}")


class Card:
    """
    Communicates with a real smartcard via pyscard.

    Parameters
    ----------
    aid : str
        Hex-encoded application identifier, e.g. ``"B00B5111CA01"``.
    """

    def __init__(self, aid: str):
        self.aid = aid
        self._conn = None

    # ------------------------------------------------------------------
    def connect(self):
        from smartcard.System import readers
        from smartcard.CardConnection import CardConnection
        rarr = readers()
        if not rarr:
            raise RuntimeError("No smartcard reader found")
        reader = rarr[0]
        self._conn = reader.createConnection()
        self._conn.connect(CardConnection.T1_protocol)
        # Select the applet
        aid_bytes = list(bytes.fromhex(self.aid))
        apdu = [0x00, 0xA4, 0x04, 0x00, len(aid_bytes)] + aid_bytes + [0x00]
        data, sw1, sw2 = self._conn.transmit(apdu)
        sw = bytes([sw1, sw2])
        if sw != b"\x90\x00":
            raise ISOException(sw.hex())

    def disconnect(self):
        if self._conn is not None:
            self._conn.disconnect()
            self._conn = None

    def _reconnect_and_reselect(self):
        """Re-establish the connection after a card reset.

        Calls :meth:`disconnect` then :meth:`connect` so that the full
        sequence (reader discovery → T1 connect → applet SELECT) is
        repeated with the same logic used on initial connection.
        """
        self.disconnect()
        self.connect()

    def transmit(self, apdu):
        try:
            data, sw1, sw2 = self._conn.transmit(list(apdu))
            return list(data), sw1, sw2
        except Exception as e:
            if not _is_card_reset_error(e):
                raise
            # The card was reset mid-transaction (e.g. Windows
            # SCARD_W_RESET_CARD 0x80100068 during long card-side crypto).
            # Re-establish the full session and retry the APDU once.
            self._reconnect_and_reselect()
            data, sw1, sw2 = self._conn.transmit(list(apdu))
            return list(data), sw1, sw2

    def request(self, apdu: bytes) -> bytes:
        """Send *apdu* and return response data, raising :exc:`ISOException` on error."""
        data, sw1, sw2 = self.transmit(list(apdu))
        sw = bytes([sw1, sw2])
        if sw != b"\x90\x00":
            raise ISOException(sw.hex())
        return bytes(data)


class Simulator:
    """
    Spawns the javacard simulator JAR and communicates over a local TCP socket.

    Parameters
    ----------
    aid : str
        Hex-encoded AID.
    applet : str
        Fully-qualified Java class name, e.g. ``"toys.TeapotApplet"``.
    classdir : str
        Sub-directory inside ``build/classes/`` where the compiled class lives.
    port : int
        TCP port the simulator will listen on (default: 6666).
    """

    def __init__(self, aid: str, applet: str, classdir: str, port: int = SIMULATOR_PORT):
        self.aid = aid
        self.applet = applet
        self.url = f"file://{CLASSES_PATH}/{classdir}/"
        self.port = port
        self._proc = None
        self._sock = None

    def connect(self):
        args = [
            "java", "-jar", SIMULATOR_JAR,
            "-p", str(self.port),
            "-a", self.aid,
            "-c", self.applet,
            "-u", self.url,
        ]
        self._proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((SIMULATOR_HOST, self.port))

    def disconnect(self):
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        if self._proc is not None:
            self._proc.kill()
            self._proc = None
            time.sleep(0.5)

    def transmit(self, apdu):
        self._sock.sendall(bytes(apdu))
        data = self._sock.recv(MAX_RESPONSE_LEN)
        sw = list(data[-2:])
        response = list(data[:-2])
        return response, sw[0], sw[1]

    def request(self, apdu: bytes) -> bytes:
        """Send *apdu* and return response data, raising :exc:`ISOException` on error."""
        data, sw1, sw2 = self.transmit(list(apdu))
        sw = bytes([sw1, sw2])
        if sw != b"\x90\x00":
            raise ISOException(sw.hex())
        return bytes(data)
