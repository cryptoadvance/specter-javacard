package toys;

// import using java card API interface.
import javacard.framework.*;
import javacard.security.*;

/* 
 * Package: toys
 * Filename: BlindOracleApplet.java 
 * Class: BlindOracleApplet
 */
public class BlindOracleApplet extends SecureApplet{

    // commands transmitted over secure channel
    // 0x00 - 0x04 are reserved
    // key management
    protected static final byte CMD_ROOT                = (byte)0x10;
    // bip32 keys - derivation and signing
    protected static final byte CMD_BIP32               = (byte)0x11;

    /************ key management *********/

    // set seed - 64 bytes, 
    // data format: <64 bytes seed>
    protected static final byte SUBCMD_ROOT_SET_SEED    = (byte)0x00;
    // set xprv - 65 bytes
    // data format: <32-byte chain code><00><32-byte prv>
    protected static final byte SUBCMD_ROOT_SET_KEY     = (byte)0x01;
    // generate random key
    // WARNING: doesn't return the seed, so it always stays only on this card
    //          add some backup mechanism in a script to recover if card breaks
    // data: ignored
    protected static final byte SUBCMD_ROOT_SET_RANDOM  = (byte)0x7D;

    /************ master private key management *********/

    // returns 65-byte root xpub <chain_code><pubkey>
    // data: ignored
    protected static final byte SUBCMD_BIP32_GET_ROOT    = (byte)0x00;
    // pass array of 4-byte indexes for derivation path
    // max derivation len is ~50, should be enough in most cases
    // sets result to temporary storage, so you can use it for 
    // faster signing afterwards
    // data: <keyid><4-byte index><4-byte index>...<4-byte index>
    // keyid is 00 if derive from root, 01 if derive from current child
    // saves derived key as current (id 01)
    protected static final byte SUBCMD_BIP32_GET_DERIVE   = (byte)0x01;
    // returns an xpub of the key currently stored in memory
    protected static final byte SUBCMD_BIP32_GET_CURRENT  = (byte)0x02;
    // sign using currently derived child key or root key
    // data format: <32-byte message hash>00 to use root key
    //              <32-byte message hash>01 to use current key
    protected static final byte SUBCMD_BIP32_SIGN         = (byte)0x03;
    // pass 32-byte hash to sign, then key id 
    // and array of 4-byte indexes for derivation
    // key that is signing is not saved as current
    // data: <32-byte message hash>00<4-byte index>...<4-byte index> for root
    //       <32-byte message hash>01<4-byte index>...<4-byte index> for current
    protected static final byte SUBCMD_BIP32_DERIVE_AND_SIGN = (byte)0x04;
    // it's not full bip32 key, only chain code and the key 
    protected static final short BIP32_LEN         = (short)65;
    protected static final short CHAINCODE_OFFSET  = (short)0;
    protected static final short PUBKEY_OFFSET     = (short)32;
    protected static final short FLAG_OFFSET       = (short)32;
    protected static final short PRVKEY_OFFSET     = (short)33;
    protected static final short CHAINCODE_LEN     = (short)32;
    protected static final short PUBKEY_LEN        = (short)33;
    protected static final short PRVKEY_LEN        = (short)32;
    protected static final short SEED_LEN_MIN      = (short)16;
    protected static final short SEED_LEN_MAX      = (short)64;
    protected static final short MSG_LEN           = (short)32;
    public static final byte[] HDKEY_SEED_KEY    = {'B','i','t','c','o','i','n',' ','s','e','e','d'};

    protected static final short ERR_INVALID_DATA  = (short)0x0700;

    protected boolean isInitialized = false;
    // root key
    protected byte[] rootPrv;
    protected byte[] rootXpub; // 65 bytes, <chain code><pubkey>
    // child key
    protected byte[] childPrv;
    protected byte[] childXpub; // 65 bytes, <chain code><pubkey>

    // Create an instance of the Applet subclass using its constructor, 
    // and to register the instance.
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        if(bArray!=null && bArray.length > 0){
            // the line below works on the card, but not in the simulator
            new BlindOracleApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
        }else{
            // keep the simulator happy and register without arguments
            new BlindOracleApplet().register();
        }
    }
    /**
     * Class constructor. 
     * Allocates memory for root key in EEPROM and for child key in RAM
     */
    public BlindOracleApplet(){
        super();
        rootPrv  = new byte[PRVKEY_LEN];
        rootXpub = new byte[BIP32_LEN];
        childPrv = JCSystem.makeTransientByteArray(PRVKEY_LEN, JCSystem.CLEAR_ON_DESELECT);
        childXpub = JCSystem.makeTransientByteArray(BIP32_LEN, JCSystem.CLEAR_ON_DESELECT);
    }
    /**
     * Handles secure message (decrypted by SecureChannel)
     * 
     * @param buf - buffer with the decrypted payload
     * @param len - length of the data in the buffer
     */
    protected short processSecureMessage(byte[] buf, short len){
        // you need to unlock the card with the PIN first
        if(isLocked()){
            ISOException.throwIt(ERR_CARD_LOCKED);
        }
        switch(buf[OFFSET_CMD]){
            case CMD_ROOT:
                return processRootCommand(buf, len);
            case CMD_BIP32:
                return processBip32Command(buf, len);
            default:
                ISOException.throwIt(ERR_INVALID_CMD);
        }
        return LENGTH_RESPONSE_CODE;
    }
    /**
     * Generates a key from 64-byte seed
     * 
     * @param seed - buffer with the seed
     * @param seefOff - offset of the seed in the buffer
     * @param seedLen - length of the seed
     */
    protected void genKeyFromSeed(byte[] seed, short seedOff, short seedLen){
        // check it's between 16 and 64 bytes
        if( (seedLen < SEED_LEN_MIN) || (seedLen > SEED_LEN_MAX))
        {
            ISOException.throwIt(ERR_INVALID_LEN);
        }
        // set depth, child number and fingerprint to zero
        short len = (short)64;
        short off = heap.allocate(len);
        // do hmac_sha512("Bitcoin seed", seed)
        Crypto.hmacSha512.init(HDKEY_SEED_KEY, (short)0, (short)(HDKEY_SEED_KEY.length));
        Crypto.hmacSha512.doFinal(seed, seedOff, seedLen, heap.buffer, off);
        // copy first 32 bytes to private key
        Util.arrayCopyNonAtomic(heap.buffer, off, rootPrv, (short)0, PRVKEY_LEN);
        // copy last 32 bytes to chain code
        Util.arrayCopyNonAtomic(
                    heap.buffer, (short)(off+PRVKEY_LEN), 
                    rootXpub, CHAINCODE_OFFSET, 
                    CHAINCODE_LEN);
        heap.free(len);
        // get public key
        Secp256k1.getPublicKey(rootPrv, (short)0,
                               true,
                               rootXpub, PUBKEY_OFFSET);
        copyRootToChild();
        isInitialized = true;
    }
    /**
     * Handles key management command
     * 
     * @param buf - buffer with the data
     * @param len - length of the data in the buffer
     */
    protected short processRootCommand(byte[] buf, short len){
        byte subcmd = buf[OFFSET_SUBCMD];
        short lenOut = setResponseCode(RESPONSE_SUCCESS, buf);
        switch (subcmd){
            // set key from seed
            case SUBCMD_ROOT_SET_SEED:
                // copy to defaulSeed
                genKeyFromSeed(buf, OFFSET_SECURE_PAYLOAD,
                               (short)(len-LENGTH_CMD_SUBCMD));
                Util.arrayCopyNonAtomic(rootXpub, (short)0,
                                        buf, OFFSET_SECURE_PAYLOAD,
                                        BIP32_LEN);
                lenOut += BIP32_LEN;
                return lenOut;
            // import key directly
            case SUBCMD_ROOT_SET_KEY:
                // check it's 65 bytes
                if(len!=(short)(BIP32_LEN+LENGTH_CMD_SUBCMD)){
                    ISOException.throwIt(ERR_INVALID_LEN);
                }
                // check that it's prv
                if(buf[(short)(OFFSET_SECURE_PAYLOAD+FLAG_OFFSET)]!=(byte)0){
                    ISOException.throwIt(ERR_INVALID_DATA);
                }
                Util.arrayCopyNonAtomic(buf, (short)(OFFSET_SECURE_PAYLOAD+CHAINCODE_OFFSET),
                                        rootXpub, CHAINCODE_OFFSET,
                                        CHAINCODE_LEN);
                Util.arrayCopyNonAtomic(buf, (short)(OFFSET_SECURE_PAYLOAD+PRVKEY_OFFSET), 
                                        rootPrv, (short)0, PRVKEY_LEN);
                Secp256k1.getPublicKey(rootPrv, (short)0, true, rootXpub, PUBKEY_OFFSET);
                copyRootToChild();
                Util.arrayCopyNonAtomic(rootXpub, (short)0,
                                        buf, OFFSET_SECURE_PAYLOAD,
                                        BIP32_LEN);
                isInitialized = true;
                lenOut += BIP32_LEN;
                return lenOut;
            // generate random key
            case SUBCMD_ROOT_SET_RANDOM:
                Crypto.random.generateData(rootXpub, (short)0, BIP32_LEN);
                Util.arrayCopyNonAtomic(rootXpub, PRVKEY_OFFSET,
                                        rootPrv, (short)0,
                                        PRVKEY_LEN);
                Secp256k1.getPublicKey(rootPrv, (short)0, true, rootXpub, PUBKEY_OFFSET);
                copyRootToChild();
                isInitialized = true;
                Util.arrayCopyNonAtomic(rootXpub, (short)0,
                                        buf, OFFSET_SECURE_PAYLOAD,
                                        BIP32_LEN);
                lenOut += BIP32_LEN;
                return lenOut;
            default:
                ISOException.throwIt(ERR_INVALID_SUBCMD);
        }
        return lenOut;
    }
    /**
     * Helper function to copy root key to child.
     * This is called when new root key is imported.
     */
    protected void copyRootToChild(){
        Util.arrayCopyNonAtomic(rootPrv, (short)0,
                                childPrv, (short)0,
                                PRVKEY_LEN);
        Util.arrayCopyNonAtomic(rootXpub, (short)0,
                                childXpub, (short)0,
                                BIP32_LEN);
    }
    /**
     * Generates a child xprv from the parent xprv
     * 
     * @param xprv    - buffer with xprv in the form <chain code><00><private key>
     * @param xprvOff - offset of the xprv
     * @param idx     - buffer with the derivation index
     * @param idxOff  - offset in index buffer
     * @param out     - output buffer to write data to
     * @param outOff  - offset in the output buffer
     */
    protected void xprvChild(byte[] xprv, short xprvOff,
                           byte[] idx,  short idxOff,
                           byte[] out,  short outOff)
    {
        // 64 hmac, 32 random tweak
        short len = (short)96;
        short off = heap.allocate(len);
        byte[] buf = heap.buffer;

        Crypto.hmacSha512.init(xprv, xprvOff, (short)32);
        // check if hardened
        if((idx[idxOff]&0x80)!=0){
            Crypto.hmacSha512.update(xprv, (short)(xprvOff+32), (short)33);            
        }else{
            Secp256k1.getPublicKey(xprv, (short)(xprvOff+33), true, buf, off);
            Crypto.hmacSha512.update(buf, off, (short)33);
        }
        // add index
        Crypto.hmacSha512.doFinal(idx, idxOff, (short)4, buf, off);
        if(FiniteField.isGreaterOrEqual(buf, off, Secp256k1.SECP256K1_R, (short)0) > 0){
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // tweaking by random number helps against DPA
        // generate random number
        FiniteField.getRandomElement(Secp256k1.SECP256K1_R, (short)0,
                                     buf, (short)(off+64));
        // add it to tweak
        FiniteField.addMod(buf, (short)(off+64), 
               buf, off,
               Secp256k1.SECP256K1_R, (short)0,
               buf, off);
        // tweak private key modulo N
        FiniteField.addMod(xprv, (short)(xprvOff+33), 
               buf, off,
               Secp256k1.SECP256K1_R, (short)0,
               buf, off);
        // negate random number
        FiniteField.subtract(Secp256k1.SECP256K1_R, (short)0,
                             buf, (short)(off+64),
                             buf, (short)(off+64));
        // add negative of the random
        FiniteField.addMod(buf, (short)(off+64), 
               buf, off,
               Secp256k1.SECP256K1_R, (short)0,
               out, (short)(outOff+33));
        // copy chaincode
        Util.arrayCopyNonAtomic(buf, (short)(off+32), out, outOff, (short)32);
        // set xprv flag
        out[(short)(outOff+32)] = (byte)0;
        heap.free(len);
    }
    /**
     * Derives a child key from parent using multiple derivation indexes.
     * 
     * @param keyid      - 00 for root and 01 for current child
     * @param derivation - buffer with the list of derivation indexes
     * @param derOff     - offset in the derivation buffer
     * @param derLen     - length of the derivation data, should be mod 4
     * @param out        - output buffer to write the xprv to
     * @param outOff     - offset in the output buffer
     */
    protected void derive(byte keyid,
                        byte[] derivation, short derOff, short derLen,
                        byte[] out, short outOff)
    {
        if(derLen % 4 != (short)0){
            ISOException.throwIt(ERR_INVALID_DATA);
        }
        // fill current xprv
        if(keyid == (byte)0x00){
            Util.arrayCopyNonAtomic(rootXpub, CHAINCODE_OFFSET,
                                    out, (short)(outOff+CHAINCODE_OFFSET),
                                    CHAINCODE_LEN);
            Util.arrayCopyNonAtomic(rootPrv, (short)0,
                                    out, (short)(outOff+PRVKEY_OFFSET),
                                    PRVKEY_LEN);
        }else{
            Util.arrayCopyNonAtomic(childXpub, CHAINCODE_OFFSET,
                                    out, (short)(outOff+CHAINCODE_OFFSET),
                                    CHAINCODE_LEN);
            Util.arrayCopyNonAtomic(childPrv, (short)0,
                                    out, (short)(outOff+PRVKEY_OFFSET),
                                    PRVKEY_LEN);
        }
        for(short i=derOff; i<(short)(derOff+derLen); i+=4){
            // derive child in place
            xprvChild(out, outOff, derivation, i, out, outOff);
        }
    }
    /**
     * Handles bip32 command - key derivation and signing
     * 
     * @param buf - buffer with the data
     * @param len - length of the data in the buffer
     */
    protected short processBip32Command(byte[] buf, short bufLen){
        if(!isInitialized){
            ISOException.throwIt(ERR_INVALID_CMD);
        }
        byte subcmd = buf[OFFSET_SUBCMD];
        short lenOut = setResponseCode(RESPONSE_SUCCESS, buf);
        // check if child key is initialized
        // and initialize if not
        if(childXpub[32]==0){
            copyRootToChild();
        }
        short len = 0;
        short off = 0;
        byte keyid = 0;
        switch (subcmd){
            // returns root xpub
            case SUBCMD_BIP32_GET_ROOT:
                Util.arrayCopyNonAtomic(rootXpub, (short)0,
                                        buf, OFFSET_SECURE_PAYLOAD,
                                        BIP32_LEN);
                lenOut += BIP32_LEN;
                return lenOut;
            // returns current child xpub
            case SUBCMD_BIP32_GET_CURRENT:
                Util.arrayCopyNonAtomic(childXpub, (short)0,
                                        buf, OFFSET_SECURE_PAYLOAD,
                                        BIP32_LEN);
                lenOut += BIP32_LEN;
                return lenOut;
            // derives child and return xpub
            case SUBCMD_BIP32_GET_DERIVE:
                len = BIP32_LEN;
                off = heap.allocate(len);
                keyid = buf[OFFSET_SECURE_PAYLOAD];
                derive(keyid,
                       buf, (short)(OFFSET_SECURE_PAYLOAD+1),
                            (short)(bufLen-OFFSET_SECURE_PAYLOAD-1),
                       heap.buffer, off);
                Util.arrayCopyNonAtomic(heap.buffer, (short)(off+PRVKEY_OFFSET),
                                        childPrv, (short)0,
                                        PRVKEY_LEN);
                Util.arrayCopyNonAtomic(heap.buffer, (short)(off+CHAINCODE_OFFSET),
                                        childXpub, CHAINCODE_OFFSET,
                                        CHAINCODE_LEN);
                Secp256k1.getPublicKey(childPrv, (short)0, true, childXpub, PUBKEY_OFFSET);
                heap.free(len);
                Util.arrayCopyNonAtomic(childXpub, (short)0,
                                        buf, OFFSET_SECURE_PAYLOAD,
                                        BIP32_LEN);
                lenOut += BIP32_LEN;
                return lenOut;
            // derives child and signs a message
            case SUBCMD_BIP32_DERIVE_AND_SIGN:
                len = BIP32_LEN;
                off = heap.allocate(len);
                keyid = buf[(short)(OFFSET_SECURE_PAYLOAD+MSG_LEN)];
                derive(keyid,
                       buf, (short)(OFFSET_SECURE_PAYLOAD+MSG_LEN+1),
                            (short)(bufLen-OFFSET_SECURE_PAYLOAD-1-MSG_LEN),
                       heap.buffer, off);
                lenOut += Secp256k1.sign(heap.buffer, (short)(off+PRVKEY_OFFSET),
                                         buf, OFFSET_SECURE_PAYLOAD,
                                         buf, OFFSET_SECURE_PAYLOAD);
                heap.free(len);
                return lenOut;
            // just signs a message with root or current child key
            case SUBCMD_BIP32_SIGN:
                // 32-byte message and keyid
                if(bufLen != (short)(OFFSET_SECURE_PAYLOAD+MSG_LEN+1)){
                    ISOException.throwIt(ERR_INVALID_DATA);
                }
                keyid = buf[(short)(OFFSET_SECURE_PAYLOAD+MSG_LEN)];
                if(keyid == (byte)0){
                    lenOut += Secp256k1.sign(rootPrv, (short)0,
                                             buf, OFFSET_SECURE_PAYLOAD,
                                             buf, OFFSET_SECURE_PAYLOAD);
                }else{
                    lenOut += Secp256k1.sign(childPrv, (short)0,
                                             buf, OFFSET_SECURE_PAYLOAD,
                                             buf, OFFSET_SECURE_PAYLOAD);
                }
                return lenOut;
            default:
                ISOException.throwIt(ERR_INVALID_SUBCMD);
        }
        return lenOut;
    }
}