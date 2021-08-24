# Specter-Javacard

This is a collection of JavaCardOS applets for [Specter-DIY](https://github.com/cryptoadvance/specter-diy) secrets storage.

Documentation for classes and applets is in the [`docs/`](./docs) folder.

Currently all the applets are tested on [NXP JCOP3 J3H145 card](https://www.smartcardfocus.com/shop/ilp/id~879/nxp-j3h145-dual-interface-java-card-144k/p/index.shtml), but we plan to add support of `Infineon SLE78` and `G&D SmartCafe 7.0` soon.

## Applets

- [`Teapot`](./docs/Teapot.md) — a very simple "Hello world" class that doesn't use any PIN protection or secure communication. It can only store up to `255` bytes of data and give it back on request. Perfect for testing communication with the card.
- [`SecureApplet`](./docs/SecureApplet.md) — base class with PIN protection and secure communication.
- [`MemoryCard`](./docs/MemoryCard.md) — extends `SecureApplet`, allows arbitrary data storage.
- [`BlindOracle`](./docs/BlindOracle.md) — extends `SecureApplet`, stores root xprv and supports bip32 key derivation and signing.
- [`SingleUseKey`](./docs/SingleUseKey.md) — extends `SecureApplet`, generates a temporary key on the card that can be used only once to sign a single hash. After that the key is deleted. Can be used for proposals like Bob's and Bryan's presigned transactions stuff.

# Toolchain installation

JDK8 works. The most recent one doesn't.

Big thanks to https://adoptopenjdk.net/ for all old versions of jdk!

Install deps:

## MacOS

```sh
brew tap adoptopenjdk/openjdk
brew cask install adoptopenjdk/openjdk/adoptopenjdk8
brew install ant@1.9
```

Add to your path (maybe put into `.bash_profile`):

```sh
export PATH="/Library/Java/JavaVirtualMachines/adoptopenjdk-8.jdk/Contents/Home/bin/:$PATH"
export PATH="/usr/local/opt/ant@1.9/bin:$PATH"
export JAVA_HOME="/Library/Java/JavaVirtualMachines/adoptopenjdk-8.jdk/Contents/Home"
```

## Linux

```sh
sudo apt install openjdk-8-jdk
sudo apt install ant
```

Install the smartcard service:

```sh
sudo apt install pcscd
```

# Tools

- `gp.jar` - a working and easy to use tool for applets management, by [martinpaljak](https://github.com/martinpaljak/GlobalPlatformPro) (LGPL3)
- `ant-javacard.jar` - ant task to build javacard applet, by [martinpaljak](https://github.com/martinpaljak/ant-javacard) (MIT)
- `sdks` folder - submodule with JavaCard SDKs of different versions (Oracle-owns-you-and-your-grandma license)

It's convenient to make an alias for `gp.jar`:

```sh
alias gp="java -jar $PWD/gp.jar"
```

# How to build

Make sure to clone recursively or run `git submodule update --init --recursive` if you have an error "No usable JavaCard SDK referenced"

Run to compile all applets:

```sh
ant all
```

You should get `.cap` files for all the applets in the `build/cap` folder.

Run to compile a specific applet:

```sh
ant Teapot
```

To see the build targets:

```sh
ant -projecthelp
```

Now upload applet to the card:

```sh
gp --install build/cap/MemoryCardApplet.cap
```

Check that it appeared in the list of applets (should appear with aid `B00B5111CB01`):

```sh
gp -l
```

Now you can communicate with the applet.

Check out [tests](./tests/tests) folder to get an idea how to communicate with the card.

# Simulator

A simple way to run simulator with a particular applet (MemoryCard for example):

```sh
python3 run_sim.py MemoryCard
```

It will spawn the simulator on port `21111` and restart it on every disconnect.

To run `BlindOracle` on port `21111` with AID `B00B5111CE01` directly with `simulator.jar`:

```sh
java -jar "simulator.jar" -p 21111 -a "B00B5111CE01" -c "toys.BlindOracleApplet" -u "file://$PWD/build/classes/BlindOracle/"
```

# Useful links

- https://github.com/OpenCryptoProject/JCMathLib - library for arbitrary elliptic curve operations on javacard
- https://opencryptojc.org/ - making JavaCards open
- https://pyscard.sourceforge.io/ - python tool to talk to smartcards
- https://smartcard-atr.apdu.fr/ - ATR (Answer To Reset) parser
- [keycard.tech](https://keycard.tech/) - JavaCard applet with BIP-32 support
- https://www.youtube.com/watch?v=vd0-Uhx2OoQ - nice talk about JavaCards and open-source ecosystem

# Cards that make sense

Compatibility table: https://www.fi.muni.cz/~xsvenda/jcalgtest/table.html

## Algorithms

`ALG_EC_SVDP_DH_PLAIN` should be there. Many cards support it. Not necessarily `ALG_EC_SVDP_DH_PLAIN_XY`. Required for point multiplication (other than G, i.e. for Schnorr)

`ALG_EC_PACE_GM` is a nice one - allows point addition. AFAIK available only on NXP JCOP3 J3H145 and NXP JCOP4 series.

`TYPE_EC_FP_PRIVATE_TRANSIENT` - useful for bip32 derivation.
Available on: 
- Infineon SLE78 JCard
- G&D Smartcafe 7.0
- NXP JCOP4 P71D321
- NXP JCOP4 J3R200
- Taisys SIMoME Vault

`ALG_HMAC_SHA512` - useful for fast PBKDF2 in BIP-39. Available only on Taisys SIMoME Vault

# Don't write your own crypto

But sometimes we have to... 
Here we have modulo addition for bip32 key derivation, this one is critical.
For public key uncompression we can use fast functions as no secrets are involved there.

For finite field ariphmetics we are abusing `RSA` encryption coprocessor where we set modulo to `FP` or `N` of `secp256k1` curve and public key to the exponent we need.

Point addition is implemented using `ALG_EC_PACE_GM`, but can be also done manually with a few simple equations over `FP`.

## Rules for crypto

- No branching - `if/switch` statements can leak information through side channels
- Don't do case-via-offset - access time to elements with different indexes can be different
- Use transient arrays when possible - it's orders of magnitude faster than EEPROM
- Use `Key` class when possible, JC platforms secures them better than simple arrays
- Encrypt-then-hmac is the right way to build the secure communiaction channel
- Use ephimerial keys or random nonces when possible, they help against replay attacks
