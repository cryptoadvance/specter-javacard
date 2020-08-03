# `SingleUseKey`

This applet generates a single-use private key on a secure element (JavaCard) and can sign only one message.

The key is overwritten just before the signature is sent back to the host.

Applet ID is `B00B5111CD01` by default.<br>
To select this applet send `00A4040006B00B5111CD0100` to the card.

Currently the applet is tested on [NXP JCOP3 J3H145 card](https://www.smartcardfocus.com/shop/ilp/id~879/nxp-j3h145-dual-interface-java-card-144k/p/index.shtml), but we plan to add support of `Infineon SLE78` and `G&D SmartCafe 7.0` at some point.

## Plaintext commands

- `B0A0000000` - generate new key. Returns corresponding public key.
- `B0A0010000` - get public key. Key will remain the same until you request the signature (next command) or regenerate the key (previous command).
- `B0A0020020<32-byte-hash>` - sign hash with the key. Can be called only once per key. If you try running this again - you will get a signature from a new random key.

## Establishing secure communication

See [`MemoryCard`](./MemoryCard.md) applet description on how to do it, or just use `SecureApplet` class in `py/applets/core.py` (requires libsecp256k1 installed).

## Secure channel commands

- `2000` - generate new key
- `2001` - get public key
- `2002<32-byte-hash>` - sign hash with private key
