# `SecureApplet`

A base class used by all applets in this repo. Provides PIN code and secure communication functionalities. Most commands of the applets are only accessible over secure channel.

# APDUs

## Unsecure Get Random

Plaintext command. Provides 32 random bytes to the host.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CLA    | `0xB0`                                   |
| INS    | `0xB1`                                   |
| P0, P1 | ignored, use for example `0x00` for both |
| DATA   | ignored                                  |
| RETURN | `SW`: `0x9000`, `DATA`: 32 random bytes |

Example: `B0B10000` -> returns 32 random bytes

## Get card's static public key

This key is generated when the applet is installed. It will remain the same whenever you insert the card, but when applet is updated it will be re-generated.

Once you know the card's static public key you can use it to establish secure communication channel. You can also verify that the card is the same next time you start talking to it.

Corresponding private key is used to sign return message from the card when openning a secure channel.

This APDU returns 65-byte sequence with serialized uncompressed public key (`0x04<x><y>`)

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CLA    | `0xB0`                                   |
| INS    | `0xB2`                                   |
| P0, P1 | ignored, use for example `0x00` for both |
| DATA   | ignored                                  |
| RETURN | `SW`: `0x9000`, `DATA`: 65 bytes with serialized static pubkey |

Example: `B0B20000` -> returns 65 bytes with static public key of the card, for example `045879312CB80C51B6FF53EF946603E64CCA37C9E06D96E7FB7BB798F822117D89FB537A4F53EA59802946AB4532BCD403EFA20518360411C262C010B1A496B39C`.

## Establish secure channel

For secure communication we need to establish shared secrets. For this we use ECDH key agreement. We use `AES_CBC` for encryption with `M2` padding (add `0x8000..00` to round to 16-byte blocks). Truncated to 14 bytes HMAC-SHA256 is used for authentication and applied to the ciphertext (encrypt-then-hmac).

There are 3 different modes you can use - `ss`, `es` and `ee`.
- In `ss` mode both card and host use static public keys and 32-byte random nonces. Shared secret is derived as `sha256(ecdh(s,s) | host_nonce | card_nonce)`.
- In `es` mode the host uses a random key, card uses a static key and a random nonce. Shared secret is derived as `sha256(ecdh(e,s) | card_nonce)`.
- In `ee` mode both use random keys, secret is calculated as `sha256(ecdh(e,e))`.

This shared secret is used to derive 4 keys for encryption and authentication for each side:

- `host_aes_key=SHA256('host_aes'|secret)` - symmetric key for data from the host
- `card_aes_key=SHA256('card_eas'|secret)` - symmetric key for data coming from the card
- `host_mac_key=SHA256('host_mac'|secret)` - authentication key for data from the host
- `card_mac_key=SHA256('card_mac'|secret)` - authentication key for data coming from the card

When secure channel is established `iv` for the `AES` cypher is set to `0` and incremented on every message. We can use the same `iv` both for incoming and outgoing data because we use different keys on each side. `iv` is not transmitted but is used in `hmac` authentication.

If you are out of sync for some reason just re-establish secure channel. If `iv` is hitting the limit of 16 bytes - also re-establish secure channel.

## Establish secure channel in SS mode

Returns `< 32-byte card nonce > | <14 byte HMAC-SHA256(card_key, data)> | ECDSA_SIGNATURE`.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CLA    | `0xB0`                                   |
| INS    | `0xB3`                                   |
| P0, P1 | ignored, use for example `0x00` for both |
| DATA   | `<host_pubkey><host_nonce>`: 65-byte public key of the host serialized in uncompressed form followed by the 32-byte host nonce |
| RETURN | `SW`: `0x9000`, `DATA`: `< 32-byte card nonce > | < 14 byte HMAC-SHA256(card_key, data)> | ECDSA_SIGNATURE`  |

## Establish secure channel in ES mode

Returns `< 32-byte card nonce > | < 14 byte HMAC-SHA256(card_key, data)> | ECDSA_SIGNATURE`.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CLA    | `0xB0`                                   |
| INS    | `0xB4`                                   |
| P0, P1 | ignored, use for example `0x00` for both |
| DATA   | 65-byte public key of the host serialized in uncompressed form |
| RETURN | `SW`: `0x9000`, `DATA`: `< 32-byte card nonce > | < 14 byte HMAC-SHA256(card_key, data)> | ECDSA_SIGNATURE` |

## Establish secure channel in EE mode

Returns `< card ephemeral pubkey > | < 14 byte HMAC-SHA256(card_key, data)> | ECDSA_SIG(card_pubkey, data incl HMAC)`.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CLA    | `0xB0`                                   |
| INS    | `0xB5`                                   |
| P0, P1 | ignored, use for example `0x00` for both |
| DATA   | 65-byte public key of the host serialized in uncompressed form |
| RETURN | `SW`: `0x9000`, `DATA`: 65-byte cards fresh pubkey followed by `HMAC-SHA256(card_key, data)` (first 14 bytes), then ECDSA signature signing all previous data |

## Secure message

All commands via secure channel are sent with this APDU. If decryption or authentication check failed the card will throw an error and close the channel. Otherwise it will always return `0x9000`, but inside the payload it will send the actual data or error code.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CLA    | `0xB0`                                   |
| INS    | `0xB6`                                   |
| P0, P1 | ignored, use for example `0x00` for both |
| DATA   | encrypted payload                        |
| RETURN | `SW`: `0x9000`, `DATA`: encrypted responce |

Maximum size of the encrypted payload is `255` bytes. Even though we could use extended APDU, but we don't really need this. We have very strict RAM limits anyways, so we can always work with 255 bytes or less.

Message is formed as follows:
- All messages coming from the host should be encrypted using `host_aes_key` and authenticated with `host_mac_key`
- All responces from card are encrypted with `card_aes_key` and authenticated with `card_mac_key`
- `AES-CBC` with `M2` padding (`0x8000...00`) is used to round data to 16-byte AES blocks.
- For authentication we use first `14` bytes of `HMAC-SHA256(key, iv | ciphertext)`
- You need to increase `iv` after every request to the card.

Encrypted packet format: `< ciphertext > < hmac_sha256(key, iv|ciphertext)[:15] >`

## Close channel

Closes secure communication channel. Internally overwrites all session keys with random junk, so nobody will be able to communicate with the card. I have no idea what's the reason to do that...

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CLA    | `0xB0`                                   |
| INS    | `0xB7`                                   |
| P0, P1 | ignored, use for example `0x00` for both |
| DATA   | ignored                                  |
| RETURN | `SW`: `0x9000`, `DATA`: empty            |

# Secure channel commands

All secure channel commands are transmitted encrypted and authenticated using a Secure Message APDU.

Each command starts with two command bytes (`CMD` and `SUBCMD`) and followed by the payload.

Error codes are transmitted over secure channel as well. Here are the common errorcodes we use:

| Code              | Value | Comment                          |
| ----------------- | ------|--------------------------------- |
| `SUCCESS`         |`9000` | Everything is fine               |
| `INVALID_LEN`     |`0403` | Payload has wrong length         |
| `INVALID_CMD`     |`0404` | Command is unknown               |
| `INVALID_SUBCMD`  |`0405` | Subcommand is unknown            |
| `NOT_IMPLEMENTED` |`0406` | Functionality is not available   |
| `CARD_LOCKED`     |`0501` | Card is locked, but request requires unlocked card |
| `INVALID_PIN`     |`0502` | Provided PIN code is incorrect   |
| `NO_ATTEMPTS_LEFT`|`0503` | Card is blocked - number of PIN attempts reached 0 |
| `ALREADY_UNLOCKED`|`0504` | Card is already unlocked |
| `NOT_INITIALIZED` |`0505` | Card is not set up yet |
| `PIN_ALREADY_SET` |`0506` | PIN code already exists, unset PIN first |

## Echo

Simple command that sends back the same responce. Useful to test secure communication as the payload is decrypted and re-encrypted on the card.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CMD    | `0x00`                                   |
| SUBCMD | `0x00`                                   |
| DATA   | data to echo                             |
| RETURN | Responce code: `0x9000`, `DATA`: same as incoming data |

## Get random

Returns 32 bytes of random data over secure channel

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CMD    | `0x01`                                   |
| SUBCMD | `0x00`                                   |
| DATA   | ignored                                  |
| RETURN | Responce code: `0x9000`, `DATA`: 32 bytes of random data |

## Pin commands

PIN code can be any sequence of bytes up to 32 bytes long.
Number of PIN attempts is limited to 10.
By default PIN code is not set. Use **Set PIN** command to initialize it.

### Pin status

Returns current status of the card, 3 bytes long:
- Number of attempts left
- Max number of attempts
- Current card status:
  - `0x00` if PIN is disabled
  - `0x01` if PIN is set but the card is locked
  - `0x02` if PIN is set and the card is unlocked
  - `0x03` if the card is bricked (number of attempts reached zero)

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CMD    | `0x03`                                   |
| SUBCMD | `0x00`                                   |
| DATA   | ignored                                  |
| RETURN | Responce code: `0x9000`, `DATA`: 3-byte status    |

### Unlock with PIN

Unlock the card with the PIN code.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CMD    | `0x03`                                   |
| SUBCMD | `0x01`                                   |
| DATA   | PIN code                                 |
| RETURN | Responce code: `0x9000` on success, error code otherwise |

### Lock the card

Lock the card.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CMD    | `0x03`                                   |
| SUBCMD | `0x02`                                   |
| DATA   | Ignored                                  |
| RETURN | Responce code: `0x9000` on success, error code otherwise |

### Change PIN

Changes the PIN code. Requires both old and new PIN codes in the payload.
In this case PIN codes should be encoded as len-value pairs

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CMD    | `0x03`                                   |
| SUBCMD | `0x03`                                   |
| DATA   | `<len_old><pin_old><len_new><pin_new>`   |
| RETURN | Responce code: `0x9000` on success, error code otherwise |

### Set PIN

Enables PIN code and sets it to the value in the payload.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CMD    | `0x03`                                   |
| SUBCMD | `0x04`                                   |
| DATA   | PIN code                                 |
| RETURN | Responce code: `0x9000` on success, error code otherwise |

### Unset PIN

Disables PIN code. Requires PIN code in the payload.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CMD    | `0x03`                                   |
| SUBCMD | `0x05`                                   |
| DATA   | PIN code                                 |
| RETURN | Responce code: `0x9000` on success, error code otherwise |
