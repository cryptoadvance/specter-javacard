# Applets

## `Teapot`

A very simple "Hello world" class that doesn't use any PIN protection or secure communication. It can only store up to `255` bytes of data and give it back on request. Perfect for testing communication with the card.

By default the phrase is `I am a teapot gimme some tea plz`.

[API docs](./Teapot.md)

## `SecureApplet`

Base class that takes care of the secure communication with the host and PIN management. It's not very useful by itself, but all other applets in the collection use it as a base.

[API docs](./SecureApplet.md)

## `MemoryCard`

Extends `SecureApplet`, stores arbitrary data that can be read after the card is unlocked with the PIN code.

[API docs](./MemoryCard.md)

## `BlindOracle`

Can store a master private key imported from seed or xprv, or generated on the card itself. Uses [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) to derive child keys, can return corresponding xpubs and sign arbitrary messages.

[API docs](./BlindOracle.md)
