package toys;

// import using java card API interface.
import javacard.framework.*;
import javacard.security.*;

/* 
 * Package: toys
 * Filename: SingleUseKeyApplet.java 
 * Class: SingleUseKeyApplet
 */
public class SingleUseKeyApplet extends SecureApplet{

    // commands transmitted over secure channel
    // 0x00 - 0x04 are reserved
    protected static final byte CMD_SINGLE_USE_KEY      = (byte)0x20;
    // instructions for plaintext
    protected static final byte INS_SINGLE_USE_KEY      = (byte)0xA0;

    /************ key management *********/

    // generates a new random key
    // can be used for signing only once
    protected static final byte SUBCMD_SINGLE_USE_KEY_GENERATE   = (byte)0x00;
    // get corresponding public key
    // use this key to construct the transaction
    protected static final byte SUBCMD_SINGLE_USE_KEY_GET_PUBKEY = (byte)0x01;
    // sign hash with private key
    // instantly deletes the key after usage
    protected static final byte SUBCMD_SINGLE_USE_KEY_SIGN       = (byte)0x02;

    protected KeyPair singleUseKeyPair;
    protected byte[] tempBuf;

    // Create an instance of the Applet subclass using its constructor, 
    // and to register the instance.
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        if(bArray!=null && bArray.length > 0){
            // the line below works on the card, but not in the simulator
            new SingleUseKeyApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
        }else{
            // keep the simulator happy and register without arguments
            new SingleUseKeyApplet().register();
        }
    }
    public SingleUseKeyApplet(){
        super();
        tempBuf = JCSystem.makeTransientByteArray(Secp256k1.LENGTH_PUBLIC_KEY_UNCOMPRESSED, JCSystem.CLEAR_ON_DESELECT);
        singleUseKeyPair = Secp256k1.newKeyPair();
        generateRandomKey();
    }
    // ok, if you want to use it without secure communication 
    // - you should be able to, even though it might be an issue with MITM
    // if you don't - comment out this function
    @SuppressWarnings("fallthrough")
    protected short processPlainMessage(byte[] buf, short len){
        // ugly copy-paste for now
        switch (buf[ISO7816.OFFSET_INS]){
            case INS_SINGLE_USE_KEY:
                switch (buf[ISO7816.OFFSET_P1]){
                    case SUBCMD_SINGLE_USE_KEY_GENERATE:
                        generateRandomKey();
                    case SUBCMD_SINGLE_USE_KEY_GET_PUBKEY:
                        // serialize pubkey in compressed form
                        return Secp256k1.serialize((ECPublicKey)singleUseKeyPair.getPublic(), true, buf, OFFSET_PLAIN_PAYLOAD);
                    case SUBCMD_SINGLE_USE_KEY_SIGN:
                        len = Secp256k1.sign((ECPrivateKey)singleUseKeyPair.getPrivate(), buf, ISO7816.OFFSET_CDATA, buf, OFFSET_PLAIN_PAYLOAD);
                        // when done - overwrite key with new random values
                        generateRandomKey();
                        return len;
                    default:
                        ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                }
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        return 0;
    }
    protected short processSecureMessage(byte[] buf, short len){
        if(buf[OFFSET_CMD] == CMD_SINGLE_USE_KEY){
            return processSingleUseKeyCommand(buf, len);
        }else{
            ISOException.throwIt(ERR_INVALID_CMD);
        }
        return 0;
    }
    @SuppressWarnings("fallthrough")
    protected short processSingleUseKeyCommand(byte[] buf, short len){
        if(isLocked()){
            ISOException.throwIt(ERR_CARD_LOCKED);
        }
        byte subcmd = buf[OFFSET_SUBCMD];
        short lenOut = setResponseCode(RESPONSE_SUCCESS, buf);
        switch (subcmd){
            case SUBCMD_SINGLE_USE_KEY_GENERATE:
                generateRandomKey();
            case SUBCMD_SINGLE_USE_KEY_GET_PUBKEY:
                // serialize pubkey in compressed form
                lenOut += Secp256k1.serialize((ECPublicKey)singleUseKeyPair.getPublic(), true, buf, OFFSET_SECURE_PAYLOAD);
                return lenOut;
            case SUBCMD_SINGLE_USE_KEY_SIGN:
                lenOut += Secp256k1.sign((ECPrivateKey)singleUseKeyPair.getPrivate(), buf, OFFSET_SECURE_PAYLOAD, buf, OFFSET_SECURE_PAYLOAD);
                // when done - overwrite key with new random values
                generateRandomKey();
                return lenOut;
            default:
                ISOException.throwIt(ERR_INVALID_SUBCMD);
        }
        return lenOut;
    }
    protected void generateRandomKey(){
        Secp256k1.generateRandomSecret(tempBuf, (short)0);
        ECPrivateKey prv = (ECPrivateKey)singleUseKeyPair.getPrivate();
        prv.setS(tempBuf, (short)0, (short)32);
        
        ECPublicKey pub = (ECPublicKey)singleUseKeyPair.getPublic();
        Secp256k1.getPublicKey(prv, false,
                                tempBuf, (short)0);
        pub.setW(tempBuf, (short)0, (short)65);
    }
}