#!/usr/bin/env python3
"""
specter-card CLI
================

Command-line interface for all Specter JavaCard applets.

Usage
-----
::

    specter-card [--mode {card,simulator}] [--aid AID] [--pin PIN]
                 [--secure-channel-mode {auto,ee,es,ss}] <applet> <command> [args…]

Applets
-------
``discover``      Probe for installed Specter applets by trying known AIDs.
``teapot``        Simple plaintext key/value store.
``secure``        Base SecureApplet – random, pubkey, PIN management, mode probing.
``memorycard``    Secure byte-string storage (PIN-protected).
``blindoracle``   BIP-32 HD key storage, derivation and signing.
``singleusekey``  Single-use key generation and signing.

Run ``specter-card <applet> --help`` for per-applet options.

Examples
--------
::

    # Print the teapot's stored phrase
    specter-card teapot get

    # Store a custom phrase
    specter-card teapot store "hello world"

    # Get 32 random bytes from the card (hex)
    specter-card secure get-random

    # Set a PIN (auto-selects a working secure-channel mode, preferring ee)
    specter-card secure set-pin --pin mysecret

    # Force a specific secure-channel mode
    specter-card --secure-channel-mode es secure pin-status

    # Store secret data in MemoryCard after unlocking with PIN
    specter-card --pin mysecret memorycard store --hex deadbeef

    # Decrypt a Specter-DIY blob (unencrypted)
    specter-card --pin mysecret memorycard decode-diy

    # Decrypt a Specter-DIY blob (encrypted – supply the device's MCU secret)
    specter-card --pin mysecret memorycard decode-diy --device-secret <32-byte-hex>

    # Import a BIP-32 seed and sign a hash
    specter-card --pin mysecret blindoracle set-seed --hex ae361e...
    specter-card --pin mysecret blindoracle sign --hash 3132...20 --key root

    # Generate a single-use key
    specter-card singleusekey generate
"""
import argparse
import sys
import os

from .connection import Card, Simulator, ISOException
from .securechannel import SecureChannel, SecureError, SUPPORTED_SECURE_CHANNEL_MODES
from .applets.teapot import TeapotApplet
from .applets.secure import SecureApplet
from .applets.memorycard import MemoryCardApplet, DecryptionError
from .applets.blindoracle import BlindOracleApplet
from .applets.singleusekey import SingleUseKeyApplet
from .diy_crypt import parse_sdiy_blob

# ---------------------------------------------------------------------------
# Applet metadata (aid, applet class name, classdir)
# ---------------------------------------------------------------------------
APPLET_META = {
    "teapot":       (TeapotApplet.AID,       TeapotApplet.APPLET,       TeapotApplet.CLASSDIR),
    "secure":       (SecureApplet.AID,       SecureApplet.APPLET,       SecureApplet.CLASSDIR),
    "memorycard":   (MemoryCardApplet.AID,   MemoryCardApplet.APPLET,   MemoryCardApplet.CLASSDIR),
    "blindoracle":  (BlindOracleApplet.AID,  BlindOracleApplet.APPLET,  BlindOracleApplet.CLASSDIR),
    "singleusekey": (SingleUseKeyApplet.AID, SingleUseKeyApplet.APPLET, SingleUseKeyApplet.CLASSDIR),
}

APPLET_CLASSES = {
    "teapot":       TeapotApplet,
    "secure":       SecureApplet,
    "memorycard":   MemoryCardApplet,
    "blindoracle":  BlindOracleApplet,
    "singleusekey": SingleUseKeyApplet,
}

AUTO_SECURE_CHANNEL_MODE = "auto"
AUTO_SECURE_CHANNEL_MODE_PRIORITY = ("ee", "es", "ss")

# ---------------------------------------------------------------------------
# Error code descriptions
# ---------------------------------------------------------------------------

# SecureError codes are applet-level status words returned inside the
# encrypted channel (defined in SecureApplet.java).
_SECURE_ERROR_DESCRIPTIONS = {
    "0403": "invalid length",
    "0404": "invalid command",
    "0405": "invalid sub-command",
    "0406": "not implemented",
    "0501": "card locked",
    "0502": "wrong PIN",
    "0503": "no PIN attempts remaining",
    "0504": "already unlocked",
    "0505": "PIN not set",
    "0506": "PIN already set",
}

# ISOException codes are standard ISO 7816-4 status words returned at the
# transport level (outside the secure channel).
_ISO_ERROR_DESCRIPTIONS = {
    "6700": "wrong length",
    "6900": "command not allowed",
    "6982": "security status not satisfied",
    "6984": "reference data not usable",
    "6985": "conditions of use not satisfied",
    "6a80": "incorrect data in command field",
    "6a82": "file or application not found",
    "6a86": "incorrect parameters P1-P2",
    "6d00": "instruction not supported",
    "6e00": "class not supported",
    "6f00": "unknown error",
}


def _fmt_error(code: str, descriptions: dict) -> str:
    """Return 'XXXX (description)' if a description is known, else just 'XXXX'."""
    desc = descriptions.get(code.lower())
    return f"{code} ({desc})" if desc else code

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bytes_arg(value: str, hex_flag: bool) -> bytes:
    """Return bytes from *value*, interpreting it as hex when *hex_flag* is set."""
    if hex_flag:
        try:
            return bytes.fromhex(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"Invalid hex string: {value!r}")
    return value.encode()


def _print_bytes(data: bytes, label: str = None):
    """Pretty-print *data* as hex with an optional *label*."""
    if label:
        print(f"{label}: {data.hex()}")
    else:
        print(data.hex())


def _parse_device_secret_hex(device_secret_hex: str):
    """Parse optional --device-secret hex into bytes."""
    if not device_secret_hex:
        return None
    try:
        return bytes.fromhex(device_secret_hex)
    except ValueError:
        print("[error] --device-secret must be a hex string", file=sys.stderr)
        sys.exit(1)


def _connect_once(args, applet_name: str, aid: str = None):
    """Connect once to a specific applet entry (or explicit AID)."""
    meta = APPLET_META[applet_name]
    aid = aid if aid else meta[0]
    if args.mode == "simulator":
        conn = Simulator(aid, meta[1], meta[2], port=getattr(args, "port", 6666))
    else:
        conn = Card(aid)
    conn.connect()
    return conn


def _compatible_applets(applet_name: str):
    """Return applet names that can serve commands for *applet_name*."""
    base_cls = APPLET_CLASSES[applet_name]
    derived = [
        name
        for name, cls in APPLET_CLASSES.items()
        if name != applet_name and issubclass(cls, base_cls)
    ]
    return [applet_name] + derived


def _make_connection(args, applet_name: str):
    """
    Build and connect the appropriate connection object.

    On card mode without --aid override, tries all compatible applet AIDs in order.
    """
    if args.aid:
        return _connect_once(args, applet_name, aid=args.aid), applet_name
    if args.mode == "simulator":
        return _connect_once(args, applet_name), applet_name

    last_iso = None
    candidates = _compatible_applets(applet_name)
    for candidate in candidates:
        try:
            conn = _connect_once(args, candidate)
            if candidate != applet_name:
                print(
                    f"[info] {applet_name} command matched installed '{candidate}' applet "
                    f"(AID {APPLET_META[candidate][0]})."
                )
            return conn, candidate
        except ISOException as e:
            if e.code == "6a82":
                last_iso = e
                continue
            raise

    if last_iso is not None:
        raise last_iso
    raise RuntimeError(f"Could not connect to any compatible applet for '{applet_name}'")


def _secure_mode_candidates(requested_mode, cached_mode=None):
    """Return secure-channel modes to try in priority order."""
    if requested_mode != AUTO_SECURE_CHANNEL_MODE:
        return (requested_mode,)
    candidates = []
    if cached_mode in AUTO_SECURE_CHANNEL_MODE_PRIORITY:
        candidates.append(cached_mode)
    for mode in AUTO_SECURE_CHANNEL_MODE_PRIORITY:
        if mode not in candidates:
            candidates.append(mode)
    return tuple(candidates)


def _open_sc(conn, mode=AUTO_SECURE_CHANNEL_MODE):
    """Open a secure channel, auto-probing secure-random when mode selection is automatic."""
    cached_mode = getattr(conn, "working_secure_channel_mode", None)
    candidates = _secure_mode_candidates(mode, cached_mode=cached_mode)
    app = SecureApplet(conn)
    failures = []

    for index, candidate in enumerate(candidates):
        sc = None
        try:
            if index > 0:
                conn.disconnect()
                conn.connect()
            sc = app.open_secure_channel(mode=candidate)
            if mode == AUTO_SECURE_CHANNEL_MODE:
                data = app.secure_random(sc)
                if len(data) != 32:
                    raise RuntimeError(f"secure-random returned {len(data)} bytes instead of 32")
            conn.working_secure_channel_mode = candidate
            if mode == AUTO_SECURE_CHANNEL_MODE:
                print(f"[info] using secure channel mode '{candidate}'.")
            return sc
        except Exception as e:
            failures.append((candidate, e))
            if sc is not None:
                try:
                    sc.close()
                except Exception:
                    pass

    if mode != AUTO_SECURE_CHANNEL_MODE and failures:
        raise failures[-1][1]

    details = ", ".join(f"{candidate}: {error}" for candidate, error in failures)
    raise RuntimeError(
        "No working secure channel mode found "
        f"(tried {', '.join(candidates)}). Details: {details}"
    )


def _open_sc_and_unlock(conn, pin_arg, mode=AUTO_SECURE_CHANNEL_MODE):
    """Open a secure channel and optionally unlock with a PIN."""
    sc = _open_sc(conn, mode=mode)
    if pin_arg:
        app = SecureApplet(conn)
        status = app.pin_status(sc)
        if status.get("status") == "disabled":
            print("[info] PIN is disabled; ignoring provided --pin and continuing without unlock.")
            return sc
        if status.get("status") == "unlocked":
            return sc
        pin = pin_arg.encode() if isinstance(pin_arg, str) else pin_arg
        try:
            app.unlock(sc, pin)
        except SecureError as e:
            if e.code == "0505":
                print(
                    "[error] Failed to unlock: PIN is not set on this card. "
                    "Use 'secure set-pin --pin <value>' to enable it.",
                    file=sys.stderr,
                )
            else:
                print(
                    f"[error] Failed to unlock with provided PIN: "
                    f"{_fmt_error(e.code, _SECURE_ERROR_DESCRIPTIONS)}",
                    file=sys.stderr,
                )
            sys.exit(1)
    return sc


# ---------------------------------------------------------------------------
# Teapot commands
# ---------------------------------------------------------------------------

def cmd_teapot_get(args, conn):
    app = TeapotApplet(conn)
    data = app.get()
    try:
        print(data.decode())
    except UnicodeDecodeError:
        _print_bytes(data, "data (hex)")


def cmd_teapot_store(args, conn):
    data = _bytes_arg(args.data, args.hex)
    app = TeapotApplet(conn)
    stored = app.store(data)
    print("Stored successfully.")
    try:
        print(stored.decode())
    except UnicodeDecodeError:
        _print_bytes(stored, "stored (hex)")


# ---------------------------------------------------------------------------
# Secure commands
# ---------------------------------------------------------------------------

def cmd_secure_get_random(args, conn):
    app = SecureApplet(conn)
    _print_bytes(app.get_random(), "random")


def cmd_secure_get_pubkey(args, conn):
    app = SecureApplet(conn)
    _print_bytes(app.get_pubkey(), "pubkey")


def cmd_secure_pin_status(args, conn):
    app = SecureApplet(conn)
    sc = _open_sc_and_unlock(conn, None, mode=args.secure_channel_mode)
    status = app.pin_status(sc)
    sc.close()
    raw_status = status["status"]
    if raw_status == "no_pin":
        status_line = "no_pin  (PIN is disabled — no unlock required)"
    elif raw_status == "unlocked":
        status_line = "unlocked  (PIN is enabled and the card is currently unlocked for this session)"
    elif raw_status == "locked":
        status_line = "locked  (PIN is enabled; use --pin <value> or 'secure unlock' to unlock)"
    else:
        status_line = raw_status
    print(f"Status:          {status_line}")
    print(f"Attempts left:   {status['attempts_left']}")
    print(f"Max attempts:    {status['max_attempts']}")


def cmd_secure_set_pin(args, conn):
    pin = args.pin.encode() if args.pin else None
    if not pin:
        print("[error] --pin is required for set-pin", file=sys.stderr)
        sys.exit(1)
    app = SecureApplet(conn)
    sc = _open_sc_and_unlock(conn, None, mode=args.secure_channel_mode)
    app.set_pin(sc, pin)
    sc.close()
    print("PIN set successfully.")


def cmd_secure_unset_pin(args, conn):
    pin = args.pin.encode() if args.pin else None
    if not pin:
        print("[error] --pin is required for unset-pin", file=sys.stderr)
        sys.exit(1)
    app = SecureApplet(conn)
    sc = _open_sc_and_unlock(conn, pin, mode=args.secure_channel_mode)
    app.unset_pin(sc, pin)
    sc.close()
    print("PIN unset successfully.")


def cmd_secure_unlock(args, conn):
    pin = args.pin.encode() if args.pin else None
    if not pin:
        print("[error] --pin is required for unlock", file=sys.stderr)
        sys.exit(1)
    app = SecureApplet(conn)
    sc = _open_sc(conn, mode=args.secure_channel_mode)
    app.unlock(sc, pin)
    sc.close()
    print("Card unlocked (this session only — unlock state is cleared when the applet is deselected).")


def cmd_secure_lock(args, conn):
    app = SecureApplet(conn)
    sc = _open_sc_and_unlock(conn, args.pin.encode() if args.pin else None, mode=args.secure_channel_mode)
    app.lock(sc)
    sc.close()
    print("Card locked.")


def cmd_secure_change_pin(args, conn):
    if not args.old_pin or not args.new_pin:
        print("[error] --old-pin and --new-pin are required", file=sys.stderr)
        sys.exit(1)
    old = args.old_pin.encode()
    new = args.new_pin.encode()
    app = SecureApplet(conn)
    sc = _open_sc_and_unlock(conn, old, mode=args.secure_channel_mode)
    app.change_pin(sc, old, new)
    sc.close()
    print("PIN changed successfully.")


def cmd_secure_echo(args, conn):
    data = _bytes_arg(args.data, args.hex)
    app = SecureApplet(conn)
    sc = _open_sc_and_unlock(conn, args.pin.encode() if args.pin else None, mode=args.secure_channel_mode)
    result = app.echo(sc, data)
    sc.close()
    try:
        print(result.decode())
    except UnicodeDecodeError:
        _print_bytes(result, "echo (hex)")


def cmd_secure_secure_random(args, conn):
    app = SecureApplet(conn)
    sc = _open_sc_and_unlock(conn, args.pin.encode() if args.pin else None, mode=args.secure_channel_mode)
    _print_bytes(app.secure_random(sc), "random")
    sc.close()


def cmd_secure_probe_modes(args, conn):
    app = SecureApplet(conn)
    failures = []

    for index, mode in enumerate(SUPPORTED_SECURE_CHANNEL_MODES):
        sc = None
        try:
            if index > 0:
                # Start each mode probe from a fresh transport/app selection so
                # one failed or stale secure-channel session does not taint the next.
                conn.disconnect()
                conn.connect()
            sc = app.open_secure_channel(mode=mode)
            data = app.secure_random(sc)
            if len(data) != 32:
                raise RuntimeError(f"secure-random returned {len(data)} bytes instead of 32")
            print(f"[ok] {mode}: opened secure channel and fetched 32 secure random bytes")
        except Exception as e:
            failures.append(mode)
            print(f"[fail] {mode}: {e}")
        finally:
            if sc is not None:
                try:
                    sc.close()
                except Exception:
                    pass

    succeeded = len(SUPPORTED_SECURE_CHANNEL_MODES) - len(failures)
    total = len(SUPPORTED_SECURE_CHANNEL_MODES)
    print(f"Summary: {succeeded}/{total} modes succeeded.")
    if failures:
        sys.exit(1)


# ---------------------------------------------------------------------------
# MemoryCard commands
# ---------------------------------------------------------------------------

def cmd_memorycard_get(args, conn):
    app = MemoryCardApplet(conn)
    sc = _open_sc_and_unlock(conn, args.pin.encode() if args.pin else None, mode=args.secure_channel_mode)
    data = app.get_data(sc)
    sc.close()
    if not data:
        print("[info] No data stored on card.")
        return
    _print_bytes(data, "data (hex)")

    device_secret = _parse_device_secret_hex(args.device_secret)
    try:
        result = parse_sdiy_blob(data, device_secret=device_secret)
    except DecryptionError:
        return

    print("specter-diy decode:")
    print(f"  encrypted: {result['encrypted']}")
    print(f"  entropy:   {result['entropy'].hex()}")
    if result["mnemonic"] is not None:
        print(f"  mnemonic:  {result['mnemonic']}")
    else:
        print("  mnemonic:  (install 'embit' to decode entropy to BIP-39 words)")


def cmd_memorycard_store(args, conn):
    data = _bytes_arg(args.data, args.hex)
    app = MemoryCardApplet(conn)
    sc = _open_sc_and_unlock(conn, args.pin.encode() if args.pin else None, mode=args.secure_channel_mode)
    stored = app.store_data(sc, data)
    sc.close()
    print("Stored successfully.")
    try:
        print(stored.decode())
    except UnicodeDecodeError:
        _print_bytes(stored, "stored (hex)")


def cmd_memorycard_decode_diy(args, conn):
    device_secret = _parse_device_secret_hex(args.device_secret)
    app = MemoryCardApplet(conn)
    sc  = _open_sc_and_unlock(conn, args.pin.encode() if args.pin else None, mode=args.secure_channel_mode)
    try:
        result = app.decode_diy_data(sc, device_secret=device_secret)
    except DecryptionError as e:
        print(f"[error] {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        sc.close()
    print(f"encrypted: {result['encrypted']}")
    print(f"entropy:   {result['entropy'].hex()}")
    if result["mnemonic"] is not None:
        print(f"mnemonic:  {result['mnemonic']}")
    else:
        print("mnemonic:  (install 'embit' to decode entropy to BIP-39 words)")


# ---------------------------------------------------------------------------
# BlindOracle commands
# ---------------------------------------------------------------------------

def cmd_blindoracle_set_seed(args, conn):
    seed = _bytes_arg(args.seed, args.hex)
    app = BlindOracleApplet(conn)
    sc = _open_sc_and_unlock(conn, args.pin.encode() if args.pin else None, mode=args.secure_channel_mode)
    xpub = app.set_seed(sc, seed)
    sc.close()
    _print_bytes(xpub, "root xpub")


def cmd_blindoracle_set_xprv(args, conn):
    xprv = _bytes_arg(args.xprv, args.hex)
    app = BlindOracleApplet(conn)
    sc = _open_sc_and_unlock(conn, args.pin.encode() if args.pin else None, mode=args.secure_channel_mode)
    xpub = app.set_root_key(sc, xprv)
    sc.close()
    _print_bytes(xpub, "root xpub")


def cmd_blindoracle_gen_key(args, conn):
    app = BlindOracleApplet(conn)
    sc = _open_sc_and_unlock(conn, args.pin.encode() if args.pin else None, mode=args.secure_channel_mode)
    xpub = app.generate_random_key(sc)
    sc.close()
    _print_bytes(xpub, "root xpub")


def cmd_blindoracle_get_root_xpub(args, conn):
    app = BlindOracleApplet(conn)
    sc = _open_sc_and_unlock(conn, args.pin.encode() if args.pin else None, mode=args.secure_channel_mode)
    xpub = app.get_root_xpub(sc)
    sc.close()
    _print_bytes(xpub, "root xpub")


def cmd_blindoracle_derive(args, conn):
    app = BlindOracleApplet(conn)
    sc = _open_sc_and_unlock(conn, args.pin.encode() if args.pin else None, mode=args.secure_channel_mode)
    from_root = args.from_key != "child"
    xpub = app.derive_child(sc, args.path, from_root=from_root)
    sc.close()
    _print_bytes(xpub, "child xpub")


def cmd_blindoracle_get_child(args, conn):
    app = BlindOracleApplet(conn)
    sc = _open_sc_and_unlock(conn, args.pin.encode() if args.pin else None, mode=args.secure_channel_mode)
    xpub = app.get_current_child(sc)
    sc.close()
    _print_bytes(xpub, "child xpub")


def cmd_blindoracle_sign(args, conn):
    msg_hash = bytes.fromhex(args.hash)
    if len(msg_hash) != 32:
        print("[error] --hash must be exactly 32 bytes (64 hex chars)", file=sys.stderr)
        sys.exit(1)
    app = BlindOracleApplet(conn)
    sc = _open_sc_and_unlock(conn, args.pin.encode() if args.pin else None, mode=args.secure_channel_mode)
    use_root = args.key != "child"
    sig = app.sign(sc, msg_hash, use_root=use_root)
    sc.close()
    _print_bytes(sig, "signature (DER)")


def cmd_blindoracle_derive_sign(args, conn):
    msg_hash = bytes.fromhex(args.hash)
    if len(msg_hash) != 32:
        print("[error] --hash must be exactly 32 bytes (64 hex chars)", file=sys.stderr)
        sys.exit(1)
    app = BlindOracleApplet(conn)
    sc = _open_sc_and_unlock(conn, args.pin.encode() if args.pin else None, mode=args.secure_channel_mode)
    from_root = args.from_key != "child"
    sig = app.derive_and_sign(sc, msg_hash, args.path, from_root=from_root)
    sc.close()
    _print_bytes(sig, "signature (DER)")


# ---------------------------------------------------------------------------
# SingleUseKey commands
# ---------------------------------------------------------------------------

def cmd_singleusekey_generate(args, conn):
    app = SingleUseKeyApplet(conn)
    if args.secure:
        sc = _open_sc_and_unlock(conn, args.pin.encode() if args.pin else None, mode=args.secure_channel_mode)
        pub = app.sc_generate(sc)
        sc.close()
    else:
        pub = app.generate()
    _print_bytes(pub, "pubkey")


def cmd_singleusekey_get_pubkey(args, conn):
    app = SingleUseKeyApplet(conn)
    if args.secure:
        sc = _open_sc_and_unlock(conn, args.pin.encode() if args.pin else None, mode=args.secure_channel_mode)
        pub = app.sc_get_pubkey(sc)
        sc.close()
    else:
        pub = app.get_pubkey()
    _print_bytes(pub, "pubkey")


def cmd_singleusekey_sign(args, conn):
    msg_hash = bytes.fromhex(args.hash)
    if len(msg_hash) != 32:
        print("[error] --hash must be exactly 32 bytes (64 hex chars)", file=sys.stderr)
        sys.exit(1)
    app = SingleUseKeyApplet(conn)
    if args.secure:
        sc = _open_sc_and_unlock(conn, args.pin.encode() if args.pin else None, mode=args.secure_channel_mode)
        sig = app.sc_sign(sc, msg_hash)
        sc.close()
    else:
        sig = app.sign(msg_hash)
    _print_bytes(sig, "signature (DER)")


def cmd_discover(args):
    if args.mode == "simulator":
        print("[error] discover is only supported with --mode card", file=sys.stderr)
        sys.exit(1)

    found = []
    for name, (aid, _, _) in APPLET_META.items():
        conn = Card(aid)
        try:
            conn.connect()
            found.append((name, aid))
        except ISOException as e:
            if e.code != "6a82":
                print(f"{name:12} AID {aid} -> error {e.code}")
        except Exception as e:
            print(f"{name:12} AID {aid} -> error {e}")
        finally:
            try:
                conn.disconnect()
            except Exception:
                pass

    if not found:
        print("No known Specter applets found on card.")
        return

    print("Detected applets:")
    for name, aid in found:
        print(f"- {name:12} {aid}")


# ---------------------------------------------------------------------------
# Argument parser construction
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="specter-card",
        description="CLI for Specter JavaCard applets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Global options
    parser.add_argument(
        "--mode", choices=["card", "simulator"], default="card",
        help="Connection mode: 'card' (real smartcard, default) or 'simulator' (local Java simulator).",
    )
    parser.add_argument(
        "--aid", default=None,
        help="Override the applet AID (hex string). Uses applet default if not provided.",
    )
    parser.add_argument(
        "--pin", default=None,
        help="PIN code to unlock the card before executing a command (string).",
    )
    parser.add_argument(
        "--port", type=int, default=6666,
        help="Simulator TCP port (default: 6666, only used with --mode simulator).",
    )
    parser.add_argument(
        "--secure-channel-mode",
        dest="secure_channel_mode",
        choices=(AUTO_SECURE_CHANNEL_MODE,) + AUTO_SECURE_CHANNEL_MODE_PRIORITY,
        default=AUTO_SECURE_CHANNEL_MODE,
        help=(
            "Secure-channel mode to use for encrypted commands. "
            "Default: auto (probe a working mode, preferring ee)."
        ),
    )

    subparsers = parser.add_subparsers(dest="applet", metavar="<applet>")
    subparsers.required = True

    subparsers.add_parser(
        "discover",
        help="Probe the card for known Specter applet AIDs.",
    )

    # ------------------------------------------------------------------ teapot
    tp = subparsers.add_parser("teapot", help="Simple plaintext data store (no PIN).")
    tp_sub = tp.add_subparsers(dest="command", metavar="<command>")
    tp_sub.required = True

    tp_sub.add_parser("get", help="Print the data currently stored on the card.")

    tp_store = tp_sub.add_parser("store", help="Write data to the card.")
    tp_store.add_argument("data", help="Data to store (string or hex).")
    tp_store.add_argument(
        "--hex", action="store_true", help="Interpret DATA as a hex string."
    )

    # ------------------------------------------------------------------ secure
    sec = subparsers.add_parser("secure", help="SecureApplet – random, pubkey, PIN.")
    sec_sub = sec.add_subparsers(dest="command", metavar="<command>")
    sec_sub.required = True

    sec_sub.add_parser("get-random", help="Return 32 random bytes (plaintext APDU).")
    sec_sub.add_parser("get-pubkey", help="Return the card static public key (65 bytes).")
    sec_sub.add_parser("pin-status", help="Show PIN status (attempts left, locked/unlocked).")

    sp = sec_sub.add_parser("set-pin", help="Enable and set the PIN code.")
    sp.add_argument("--pin", required=True, help="New PIN value (string).")

    up = sec_sub.add_parser("unset-pin", help="Disable PIN. Card must be unlocked first.")
    up.add_argument("--pin", required=True, help="Current PIN to confirm.")

    sec_sub.add_parser(
        "unlock",
        help=(
            "Unlock the card for the current session using the global --pin option. "
            "This does NOT remove the PIN; the card will return to a locked state after "
            "the next power-cycle or explicit 'lock'. "
            "To permanently disable the PIN, use 'unset-pin'."
        ),
    )
    sec_sub.add_parser("lock",   help="Lock the card.")

    cp = sec_sub.add_parser("change-pin", help="Change the PIN code.")
    cp.add_argument("--old-pin", required=True, help="Current PIN.")
    cp.add_argument("--new-pin", required=True, help="New PIN.")

    echo_p = sec_sub.add_parser("echo", help="Send data through the secure channel and receive it back.")
    echo_p.add_argument("data", help="Data to echo (string or hex).")
    echo_p.add_argument("--hex", action="store_true", help="Interpret DATA as hex.")

    sec_sub.add_parser("secure-random", help="Return 32 random bytes over the secure channel.")
    sec_sub.add_parser(
        "probe-modes",
        help="Try ss/es/ee secure-channel modes and run secure-random in each.",
    )

    # ------------------------------------------------------------------ memorycard
    mc = subparsers.add_parser("memorycard", help="Secure byte-string storage (PIN-protected).")
    mc_sub = mc.add_subparsers(dest="command", metavar="<command>")
    mc_sub.required = True

    mc_get = mc_sub.add_parser(
        "get",
        help="Retrieve raw card bytes (hex) and attempt Specter-DIY decode.",
    )
    mc_get.add_argument(
        "--device-secret", default=None, metavar="HEX",
        help=(
            "Optional 32-byte internal secret from the Specter-DIY device's MCU flash "
            "(hex string). Used when decoding encrypted Specter-DIY blobs."
        ),
    )

    mc_store = mc_sub.add_parser("store", aliases=["set"], help="Write a secret to the card (up to 220 bytes).")
    mc_store.add_argument("data", help="Data to store (string or hex).")
    mc_store.add_argument("--hex", action="store_true", help="Interpret DATA as hex.")

    mc_diy = mc_sub.add_parser(
        "decode-diy",
        help=(
            "Decrypt and decode a Specter-DIY blob stored on the card. "
            "For encrypted blobs, supply the 32-byte device secret via "
            "--device-secret (hex). Unencrypted blobs need no secret."
        ),
    )
    mc_diy.add_argument(
        "--device-secret", default=None, metavar="HEX",
        help=(
            "32-byte internal secret from the Specter-DIY device's MCU flash "
            "(hex string). Required for encrypted blobs."
        ),
    )

    # ------------------------------------------------------------------ blindoracle
    bo = subparsers.add_parser(
        "blindoracle",
        help="BIP-32 HD key storage, derivation, and signing."
    )
    bo_sub = bo.add_subparsers(dest="command", metavar="<command>")
    bo_sub.required = True

    ss = bo_sub.add_parser("set-seed", help="Import a BIP-32 seed (16-64 bytes) as the root key.")
    ss.add_argument("seed", help="Seed bytes (string or hex).")
    ss.add_argument("--hex", action="store_true", help="Interpret SEED as hex.")

    sx = bo_sub.add_parser("set-xprv", help="Import an existing xprv (chain_code + 0x00 + privkey, 65 bytes).")
    sx.add_argument("xprv", help="xprv bytes (hex).")
    sx.add_argument("--hex", action="store_true", default=True, help="Interpret XPRV as hex (default).")

    bo_sub.add_parser("gen-key",      help="Generate a random root key on the card (no backup possible!).")
    bo_sub.add_parser("get-root-xpub", help="Return the root xpub (chain_code + pubkey, 65 bytes).")
    bo_sub.add_parser("get-child",    help="Return the currently cached child xpub.")

    dv = bo_sub.add_parser("derive", help="Derive a child key and cache it on the card.")
    dv.add_argument("path", help="BIP-32 derivation path, e.g. \"m/44'/0'/0'\".")
    dv.add_argument(
        "--from", dest="from_key", choices=["root", "child"], default="root",
        help="Derive from 'root' (default) or the previously cached 'child'.",
    )

    sg = bo_sub.add_parser("sign", help="Sign a 32-byte hash with the root or cached child key.")
    sg.add_argument("--hash", required=True, help="32-byte message hash (64 hex chars).")
    sg.add_argument(
        "--key", choices=["root", "child"], default="root",
        help="Key to sign with: 'root' (default) or 'child'.",
    )

    ds = bo_sub.add_parser(
        "derive-sign",
        help="Derive a key, sign a hash, and discard the temporary key (card state unchanged).",
    )
    ds.add_argument("--hash", required=True, help="32-byte message hash (64 hex chars).")
    ds.add_argument("path", help="BIP-32 derivation path.")
    ds.add_argument(
        "--from", dest="from_key", choices=["root", "child"], default="root",
        help="Derive from 'root' (default) or currently cached 'child'.",
    )

    # ------------------------------------------------------------------ singleusekey
    suk = subparsers.add_parser(
        "singleusekey",
        help="Single-use key: generate, get pubkey, sign once."
    )
    suk_sub = suk.add_subparsers(dest="command", metavar="<command>")
    suk_sub.required = True

    for cmd_name, help_text in [
        ("generate",   "Generate a new single-use key and return its public key."),
        ("get-pubkey", "Return the current single-use public key."),
    ]:
        p = suk_sub.add_parser(cmd_name, help=help_text)
        p.add_argument(
            "--secure", action="store_true",
            help="Use the secure channel (PIN-protected).",
        )

    sign_p = suk_sub.add_parser(
        "sign",
        help="Sign a 32-byte hash. The key is replaced after signing.",
    )
    sign_p.add_argument("--hash", required=True, help="32-byte message hash (64 hex chars).")
    sign_p.add_argument(
        "--secure", action="store_true",
        help="Use the secure channel (PIN-protected).",
    )

    return parser


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

COMMANDS = {
    ("teapot",       "get"):            cmd_teapot_get,
    ("teapot",       "store"):          cmd_teapot_store,
    ("secure",       "get-random"):     cmd_secure_get_random,
    ("secure",       "get-pubkey"):     cmd_secure_get_pubkey,
    ("secure",       "pin-status"):     cmd_secure_pin_status,
    ("secure",       "set-pin"):        cmd_secure_set_pin,
    ("secure",       "unset-pin"):      cmd_secure_unset_pin,
    ("secure",       "unlock"):         cmd_secure_unlock,
    ("secure",       "lock"):           cmd_secure_lock,
    ("secure",       "change-pin"):     cmd_secure_change_pin,
    ("secure",       "echo"):           cmd_secure_echo,
    ("secure",       "secure-random"):  cmd_secure_secure_random,
    ("secure",       "probe-modes"):    cmd_secure_probe_modes,
    ("memorycard",   "get"):            cmd_memorycard_get,
    ("memorycard",   "store"):          cmd_memorycard_store,
    ("memorycard",   "set"):            cmd_memorycard_store,
    ("memorycard",   "decode-diy"):     cmd_memorycard_decode_diy,
    ("blindoracle",  "set-seed"):       cmd_blindoracle_set_seed,
    ("blindoracle",  "set-xprv"):       cmd_blindoracle_set_xprv,
    ("blindoracle",  "gen-key"):        cmd_blindoracle_gen_key,
    ("blindoracle",  "get-root-xpub"): cmd_blindoracle_get_root_xpub,
    ("blindoracle",  "derive"):         cmd_blindoracle_derive,
    ("blindoracle",  "get-child"):      cmd_blindoracle_get_child,
    ("blindoracle",  "sign"):           cmd_blindoracle_sign,
    ("blindoracle",  "derive-sign"):    cmd_blindoracle_derive_sign,
    ("singleusekey", "generate"):       cmd_singleusekey_generate,
    ("singleusekey", "get-pubkey"):     cmd_singleusekey_get_pubkey,
    ("singleusekey", "sign"):           cmd_singleusekey_sign,
}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.applet == "discover":
        cmd_discover(args)
        return

    # Build connection
    try:
        conn, _ = _make_connection(args, args.applet)
    except Exception as e:
        print(f"[error] Could not connect: {e}", file=sys.stderr)
        sys.exit(1)

    # Dispatch
    key = (args.applet, args.command)
    handler = COMMANDS.get(key)
    if handler is None:
        print(f"[error] Unknown command: {args.applet} {args.command}", file=sys.stderr)
        sys.exit(1)

    try:
        handler(args, conn)
    except ISOException as e:
        print(f"[error] ISO error: {_fmt_error(e.code, _ISO_ERROR_DESCRIPTIONS)}", file=sys.stderr)
        sys.exit(1)
    except SecureError as e:
        if e.code == "0501" and not getattr(args, "pin", None):
            print(
                "[error] Card is locked. Provide a PIN with --pin to unlock it.",
                file=sys.stderr,
            )
        elif e.code == "0502":
            print(
                "[error] Wrong PIN. Check your PIN value and run 'secure pin-status' to see attempts remaining.",
                file=sys.stderr,
            )
        else:
            print(f"[error] Secure channel error: {_fmt_error(e.code, _SECURE_ERROR_DESCRIPTIONS)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[error] {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    main()
