# `MemoryCard`

Can store arbitrary sequence of bytes up to `220` bytes. It is enough to store bip39 recovery phrase (max word length in bip39 is 8 letters, 24 words max + spaces), bip32 seed or root xprv.

## APDUs

Applet ID: `B00B5111CB01`

To select applet use `SELECT` APDU: `00A4040006B00B5111CB0100`

## SC commands

We encode data in secure message in the following form:

```
<2-byte command><data>
```

Response coming from the card has the structure:

```
<2-byte response code><data>
```

In total payload should be at most `222` bytes, otherwise it will not fit in a single packet. So data part is limited to `220` byte. It should be enough even for the largest possible mnemonic phrase that is `24*9-1 = 215` bytes.

Success status code is `0x9000`, just to be consistent.

Commands marked with `PIN protected` can be used only if the card is unlocked.

All commands defined in the [`SecureApplet`](./SecureApplet.md) are available. On top of that we have two more commands:

### Get data

**PIN protected** - the card should be unlocked first.

Simple command that sends back the same responce. Useful to test secure communication as the payload is decrypted and re-encrypted on the card.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CMD    | `0x05`                                   |
| SUBCMD | `0x00`                                   |
| DATA   | ignored                                  |
| RETURN | Responce code: `0x9000`, `DATA`: data stored on the card |

### Store data

**PIN protected** - the card should be unlocked first.

Simple command that sends back the same responce. Useful to test secure communication as the payload is decrypted and re-encrypted on the card.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CMD    | `0x05`                                   |
| SUBCMD | `0x01`                                   |
| DATA   | data to store                            |
| RETURN | Responce code: `0x9000`, `DATA`: new data stored on the card |

