# specter-card Python module and CLI

A Python library and command-line tool for interacting with all
[Specter JavaCard](https://github.com/3rdIteration/specter-javacard) applets.

## Installation

```bash
cd py/
pip install -r requirements.txt
# Optional: install as a package with CLI entry point
pip install -e .
```

## Run directly from source (dev / testing)

You can skip the package install step and run the CLI straight from the checked-out
source tree.  `cli.py` is a thin launcher that delegates to the single canonical
implementation in `specter_card/cli.py`:

```bash
cd py/
pip install -r requirements.txt
python3 cli.py --help
```

Example commands:

```bash
cd py/
python3 cli.py teapot get
python3 cli.py --mode simulator memorycard get
python3 cli.py --pin mysecret memorycard decode-diy
```

If you install the package, the equivalent commands use the `specter-card`
entry point instead of `python3 cli.py` — both call the same `specter_card/cli.py`
implementation.

> **libsecp256k1** – the secure-channel and BlindOracle features require
> `libsecp256k1`.  The pre-built binaries shipped in
> `tests/tests/util/prebuilt/` are used automatically as a fallback if the
> library is not installed system-wide.

## Library usage

```python
from specter_card import Card, Simulator
from specter_card import TeapotApplet, SecureApplet, MemoryCardApplet
from specter_card import BlindOracleApplet, SingleUseKeyApplet

# --- Teapot (no PIN, no secure channel) ---
conn = Card("B00B5111CA01")
conn.connect()
app = TeapotApplet(conn)
print(app.get())          # b"I am a teapot gimme some tea plz"
app.store(b"my secret")
conn.disconnect()

# --- MemoryCard (PIN + secure channel) ---
conn = Card("B00B5111CB01")
conn.connect()
app = MemoryCardApplet(conn)
sc  = app.open_secure_channel()
app.set_pin(sc, b"mysecret")
app.store_data(sc, b"super secret mnemonic")
sc.close()
conn.disconnect()

# --- BlindOracle (BIP-32 key management) ---
conn = Card("B00B5111CE01")
conn.connect()
app = BlindOracleApplet(conn)
sc  = app.open_secure_channel()
app.unlock(sc, b"mysecret")
seed = bytes.fromhex("ae361e712e3fe66c8f1d57192d80abe0...")
xpub = app.set_seed(sc, seed)        # 65 bytes: chain_code + compressed_pubkey
child_xpub = app.derive_child(sc, "m/44'/0'/0'")
sig = app.sign(sc, b"\x35" * 32, use_root=False)  # sign with child key
sc.close()
conn.disconnect()
```

## CLI usage

```
specter-card [--mode {card,simulator}] [--aid AID] [--pin PIN] <applet> <command> [args…]
```

### Global options

| Option | Description |
|--------|-------------|
| `--mode card` | Use a real smartcard via pyscard (default). |
| `--mode simulator` | Use the local Java simulator. |
| `--aid <hex>` | Override the applet AID. |
| `--pin <string>` | PIN to unlock the card before executing the command. |
| `--port <n>` | Simulator TCP port (default 6666). |

Without `--aid` in `--mode card`, the CLI now tries all compatible applet AIDs for the selected command
(for example, `secure` commands can run against `secure`, `memorycard`, `blindoracle`, or `singleusekey`).

### `teapot`

| Command | Description |
|---------|-------------|
| `teapot get` | Print data stored on the card. |
| `teapot store <data> [--hex]` | Write up to 254 bytes to the card. |

```bash
specter-card teapot get
specter-card teapot store "hello world"
specter-card teapot store --hex deadbeef
```

### `discover`

Probe the card for known Specter applet AIDs:

```bash
specter-card discover
```

### `secure`

| Command | Description |
|---------|-------------|
| `secure get-random` | Print 32 random bytes (hex). |
| `secure get-pubkey` | Print the card's static public key. |
| `secure pin-status` | Show PIN status (enabled/disabled, locked/unlocked, attempts left). |
| `secure set-pin --pin <pin>` | Enable and set a PIN. |
| `secure unset-pin --pin <pin>` | Permanently disable the PIN. |
| `secure unlock` | Unlock the card for the current session using global `--pin`. Does **not** remove the PIN. |
| `secure lock` | Lock the card (requires PIN on next access). |
| `secure change-pin --old-pin <old> --new-pin <new>` | Change the PIN. |
| `secure echo <data> [--hex]` | Echo data over the secure channel. |
| `secure secure-random` | Return 32 random bytes over the secure channel. |
| `secure probe-modes` | Try `ss`, `es`, and `ee` secure-channel modes and run `secure-random` in each. |

Encrypted commands automatically probe for a working secure-channel mode (trying `ee`, `es`, `ss` in order) and print an `[info]` line showing which mode was selected. To force a specific mode, use `--secure-channel-mode auto|ee|es|ss`.

> **Note — unlock vs unset-pin**
> `secure unlock --pin <value>` authenticates the card for the *current session only*. The card returns to a locked state after the next power-cycle or an explicit `secure lock` call. The PIN remains set.
> To *permanently remove* the PIN requirement, use `secure unset-pin --pin <value>`.

> **Note — Specter-DIY cross-compatibility**
> The PIN is transmitted as `sha256(pin_bytes)` so that the wire payload is always 32 bytes.
> This matches the convention used by the Specter-DIY firmware, ensuring PINs set on a
> Specter-DIY device work with this tool and vice versa.

```bash
specter-card secure get-random
specter-card secure get-random   # also works if only a derived secure applet is installed
specter-card secure get-pubkey
specter-card secure set-pin --pin mysecret
specter-card --pin mysecret secure pin-status
specter-card --secure-channel-mode ee secure pin-status
specter-card --pin mysecret secure unlock   # unlock for this session only; PIN stays set
specter-card --pin mysecret secure lock
specter-card --pin mysecret secure unset-pin --pin mysecret   # permanently remove the PIN
specter-card --pin mysecret secure change-pin --old-pin mysecret --new-pin newpin
specter-card secure probe-modes
```

### `memorycard`

| Command | Description |
|---------|-------------|
| `memorycard get [--device-secret <hex>]` | Read raw secret data as hex, then attempt Specter-DIY decode. |
| `memorycard store <data> [--hex]` | Write up to 220 bytes (PIN-protected). |

```bash
specter-card --pin mysecret memorycard get
specter-card --pin mysecret memorycard get --device-secret <32-byte-hex>
specter-card --pin mysecret memorycard store "my mnemonic phrase"
specter-card --pin mysecret memorycard store --hex deadbeef
```

### `blindoracle`

| Command | Description |
|---------|-------------|
| `blindoracle set-seed <seed> [--hex]` | Load a BIP-32 seed (16-64 bytes). |
| `blindoracle set-xprv <xprv_hex>` | Load a root key directly (65 bytes). |
| `blindoracle gen-key` | Generate a random root key (no backup!). |
| `blindoracle get-root-xpub` | Print the root xpub. |
| `blindoracle derive <path> [--from root\|child]` | Derive and cache a child key. |
| `blindoracle get-child` | Print the cached child xpub. |
| `blindoracle sign --hash <hex> [--key root\|child]` | Sign a 32-byte hash. |
| `blindoracle derive-sign --hash <hex> <path> [--from root\|child]` | Derive + sign (temporary key). |

xpub format: `chain_code (32 bytes) + compressed_pubkey (33 bytes)` = 65 bytes total.

```bash
specter-card --pin mysecret blindoracle set-seed --hex ae361e...
specter-card --pin mysecret blindoracle get-root-xpub
specter-card --pin mysecret blindoracle derive "m/44'/0'/0'"
specter-card --pin mysecret blindoracle sign --hash $(python3 -c "print('35'*32)") --key child
specter-card --pin mysecret blindoracle derive-sign --hash $(python3 -c "print('35'*32)") "m/0/1"
```

### `singleusekey`

| Command | Description |
|---------|-------------|
| `singleusekey generate [--secure]` | Generate a new key; returns the pubkey. |
| `singleusekey get-pubkey [--secure]` | Return the current pubkey. |
| `singleusekey sign --hash <hex> [--secure]` | Sign a 32-byte hash (key is replaced after). |

```bash
specter-card singleusekey generate
specter-card singleusekey get-pubkey
specter-card singleusekey sign --hash 3535...3535
# Using the secure channel:
specter-card --pin mysecret singleusekey sign --hash 3535...3535 --secure
```

## Using the simulator

Start the simulator first (or pass `--mode simulator` to have the CLI start it automatically):

```bash
# Manually start the simulator
python run_sim.py Teapot

# Then use the CLI against it
specter-card --mode simulator teapot get
specter-card --mode simulator --pin mysecret memorycard get
```
