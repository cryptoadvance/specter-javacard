# `BlindOracle`

Allows storage of bitcoin secrets on the card, deriving keys according to bip32 and signing arbitrary messages with these keys.

Applet can:
- import bip32 seed or master private key
- generate a unique xprv internally (careful with this mode, no backup possible)
- derive child keys from the root key and return corresponding xpubs
- sign arbitrary messages with a derived key

Instead of the full hd key serialization we use a stripped-down version where only `chain code` and the `public key` is transmitted. Because for the full hd key you need ripemd160 hash function to calculate parent fingerprint. This hash function is not available on javacards and software implementation requires plenty of storage space. But the host can calculate the parent fingerprint by asking for the parent xpub first.

# APDUs

Applet ID: `B00B5111CE01`

To select applet use `SELECT` APDU: `00A4040006B00B5111CE0100`

# SC commands

All commands defined in the [`SecureApplet`](./SecureApplet.md) are available. On top of that we have two more commands:

All commands are **PIN protected** - the card should be unlocked first.

## Key management

Loads or generates the root key on the card.

### Set seed

Calculates root key from bip32 seed (64 bytes)

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CMD    | `0x10`                                   |
| SUBCMD | `0x00`                                   |
| DATA   | 64-byte seed                             |
| RETURN | Responce code: `0x9000`, `DATA`: root xpub: `<chain_code><pubkey>` |

### Set root key

Sets root key directly, format: `<chain_code><00><private_key>`

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CMD    | `0x10`                                   |
| SUBCMD | `0x01`                                   |
| DATA   | 65-byte root key: `<chain_code><00><private_key>` |
| RETURN | Responce code: `0x9000`, `DATA`: root xpub: `<chain_code><pubkey>` |

### Generate random key

Generates a random key, this key never leaves the device so it can't be backed up. Be careful with it - add some kind of backup mechanism to your script, otherwise if the card dies you will lose your funds.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CMD    | `0x10`                                   |
| SUBCMD | `0x7D`                                   |
| DATA   | ignored                                  |
| RETURN | Responce code: `0x9000`, `DATA`: root xpub: `<chain_code><pubkey>` |

## Key derivation and signing

### Get root xpub

Returns xpub of the root key stored on the card.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CMD    | `0x11`                                   |
| SUBCMD | `0x00`                                   |
| DATA   | ignored                                  |
| RETURN | Responce code: `0x9000`, `DATA`: root xpub: `<chain_code><pubkey>` |

### Derive child

Derives a child from root and temporary stores it in RAM. This cached child is available until reset or next call of this method.

You can derive a child from the root (`keyid = 0x00`) or from currently derived child (`keyid = 0x01`). Currently derived child is replaced by the result of the function for all subsequent commands.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CMD    | `0x11`                                   |
| SUBCMD | `0x01`                                   |
| DATA   | 1-byte keyid, derivation path: sequence of 4-byte big endian encoded indexes. `<keyid><index><index><index>` |
| RETURN | Responce code: `0x9000`, `DATA`: xpub of the derived child: `<chain_code><pubkey>` |

### Get current child

Returns currently derived xpub.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CMD    | `0x11`                                   |
| SUBCMD | `0x02`                                   |
| DATA   | ignored                                  |
| RETURN | Responce code: `0x9000`, `DATA`: current child xpub: `<chain_code><pubkey>` |

### Sign

Signs a 32-byte message hash with one of current keys - root or derived.

Use `keyid = 0x00` to sign with root and `keyid = 0x01` to sign with current child.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CMD    | `0x11`                                   |
| SUBCMD | `0x03`                                   |
| DATA   | 32-byte message, keyid                   |
| RETURN | Responce code: `0x9000`, `DATA`: der-encoded ecdsa signature |


### Derive and sign

Derives a key, signs a message hash with this key. Doesn't store the key in the `01` slot, so the card state is unchanged.

Use `keyid = 0x00` to derive from root and `keyid = 0x01` to derive from current child.

Derivation path is a sequence of 4-byte big-endian indexes of the derivation paths.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CMD    | `0x11`                                   |
| SUBCMD | `0x04`                                   |
| DATA   | 32-byte message, keyid, derivation path  |
| RETURN | Responce code: `0x9000`, `DATA`: der-encoded ecdsa signature |
