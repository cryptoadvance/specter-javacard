package toys;

// import using java card API interface.
import javacard.framework.*;

/**
 * A base secure applet that includes a PIN code and secure communication channel.
 * <p>
 * It registeres a set of APDU commands to establish secure channel,
 * to receive secure message and to manage the PIN code.
 * <p>
 * In derived applet define the following functions:
 * <ul>
 * <li> {@code processPlainMessage}  - to process any non-encrypted messages
 * <li> {@code processSecureMessage} - to process any encrypted message 
 *                             (data passed to this function is already decrypted and verified)
 * <li> TODO: {@code postUnlock(PIN)} and {@code preUnlock(PIN)} - methods is called before and after PIN is verified.
 * <li> TODO: {@code postChangePIN(oldPIN, newPIN)} - method is called when PIN is changed
 * <li> TODO: {@code postLock()} - method is called when card is locked.
 * <p>
 * Plaintext instruction codes INS from 0xB1 to 0xB7 are reserved for secure channel:
 * <ul>
 * <li>{@code B1} - returns 32 bytes of random data from built-in RNG
 * <li>{@code B2} - returns a static public key for key agreement. 
 *                        Serialized, uncompressed (65-bytes, {@code <04><x><y>})
 * <li>TODO: {@code B3} - Establishes secure channel in SS mode.
 * <li>{@code B4} - Establishes secure channel in ES mode. 
 *                  Card uses static key, host should send ephemeral key.
 * <li>{@code B5} - Establishes secure channel in EE mode. 
 *                  Both the card and the host use ephemeral key.
 * <li>{@code B6} - Process secure message.
 * <li>{@code B7} - Close secure channel.
 * <p>
 * Encrypted command codes CMD from 0x00 to 0x04 are reserved 
 * for PIN code management and a few other commands:
 * <ul>
 * <li>{@code 00} - echo back what was sent to the card. Useful to check secure channel.
 * <li>{@code 01} - send 32 bytes of random data over secure channel. 
 *                  Useful to get some extra entropy for key generation on the host.
 * <li>TODO: {@code 02} - authenticate data with internal secret.
 *                  Can be used to generate anti-phishing byte sequence while user is entering 
 *                  the PIN code to proof to the user that the card was not replaced.
 * <li>{@code 03} - PIN management commands.
 * <li>TODO: {@code 04} - Reestablish channel without locking the card (just rotate keys).
 * <li>TODO: {@code 05} - Wipe everything on the card. 
 */
public class SecureApplet extends Applet{

    /** Class code for secure applet */
    protected static final byte SECURE_CLA                      = (byte)0xB0;

    /** Instruction to get 32 random bytes, without secure channel */
    protected static final byte  INS_GET_RANDOM                 = (byte)0xB1;

    /* Secure channel stuff */
    /** Instruction to get static card's public key for ECDH key agreement */
    protected static final byte INS_GET_CARD_PUBKEY             = (byte)0xB2;
    /** Instruction to establish secure channel in ES mode - 
     *  ephemeral key from the host, static key from the card. */
    protected static final byte INS_OPEN_SECURE_CHANNEL_SS_MODE = (byte)0xB3;
    /** Instruction to establish secure channel in ES mode - 
     *  ephemeral keys are used both on the host and on the card. */
    protected static final byte INS_OPEN_SECURE_CHANNEL_ES_MODE = (byte)0xB4;
    /** Instruction to establish secure channel in EE mode - 
     *  ephemeral keys are used both on the host and on the card. */
    protected static final byte INS_OPEN_SECURE_CHANNEL_EE_MODE = (byte)0xB5;
    protected static final byte INS_SECURE_MESSAGE              = (byte)0xB6;
    protected static final byte INS_CLOSE_CHANNEL               = (byte)0xB7;

    /* Commands transmitted over secure channel */
    protected static final byte CMD_ECHO                  = (byte)0x00;
    protected static final byte CMD_RAND                  = (byte)0x01;
    protected static final byte CMD_AUTH                  = (byte)0x02;
    protected static final byte CMD_PIN                   = (byte)0x03;
    protected static final byte CMD_REESTABLISH_SC        = (byte)0x04;
    protected static final byte CMD_WIPE                  = (byte)0x05;

    protected static final byte SUBCMD_DEFAULT          = (byte)0x00;
    // pin
    protected static final byte SUBCMD_PIN_STATUS         = (byte)0x00;
    protected static final byte SUBCMD_PIN_UNLOCK         = (byte)0x01;
    protected static final byte SUBCMD_PIN_LOCK           = (byte)0x02;
    protected static final byte SUBCMD_PIN_CHANGE         = (byte)0x03;
    protected static final byte SUBCMD_PIN_SET            = (byte)0x04;
    protected static final byte SUBCMD_PIN_UNSET          = (byte)0x05;

    // status
    protected static final byte STATUS_PIN_NOT_SET      = (byte)0x00;
    protected static final byte STATUS_CARD_LOCKED      = (byte)0x01;
    protected static final byte STATUS_CARD_UNLOCKED    = (byte)0x02;
    protected static final byte STATUS_CARD_BRICKED     = (byte)0x03;

    // errorcodes
    protected static final short ERR_INVALID_LEN        = (short)0x0403;
    protected static final short ERR_INVALID_CMD        = (short)0x0404;
    protected static final short ERR_INVALID_SUBCMD     = (short)0x0405;
    protected static final short ERR_NOT_IMPLEMENTED    = (short)0x0406;
    protected static final short ERR_CARD_LOCKED        = (short)0x0501;
    protected static final short ERR_INVALID_PIN        = (short)0x0502;
    protected static final short ERR_NO_ATTEMPTS_LEFT   = (short)0x0503;
    protected static final short ERR_ALREADY_UNLOCKED   = (short)0x0504;
    protected static final short ERR_NOT_INITIALIZED    = (short)0x0505;
    protected static final short ERR_PIN_ALREADY_SET    = (short)0x0506;
    protected static final short RESPONSE_SUCCESS       = (short)0x9000;

    /* Generic constants */
    /** length of random data for CMD_RAND command */
    private static final short LENGTH_RANDOM_DATA       = (short)32;
    /** offset of non-secure responce payload */
    public  static final short OFFSET_PLAIN_PAYLOAD     = (short)0;
    /** length of CMD+SUBCMD */
    public  static final short LENGTH_CMD_SUBCMD        = (short)2;
    /** offset of CMD byte */
    public  static final short OFFSET_CMD               = (short)0;
    /** offset of SUBCMD byte */
    public  static final short OFFSET_SUBCMD            = (short)1;
    /** length of the responce code, should be 
     * the same as LENGTH_CMD_SUBCMD for echo to work */
    public  static final short LENGTH_RESPONSE_CODE     = LENGTH_CMD_SUBCMD;
    /** offset for the response code */
    public  static final short OFFSET_RESPONSE_CODE     = (short)0;
    /** offset of the response payload */
    public  static final short OFFSET_SECURE_PAYLOAD    = LENGTH_RESPONSE_CODE;
    
    /** offset of the complete decrypted message */
    public  static final short OFFSET_SECURE_MESSAGE    = (short)0;
    /** length of transient heap */
    public  static final short LENGTH_TRANSIENT_HEAP    = (short)1024;

    /* PIN constants */
    protected static final byte PIN_MAX_LENGTH            = (byte)32;
    protected static final byte PIN_MAX_COUNTER           = (byte)10;
    
    protected PinCode pin;
    // mb better to do via GP somehow?
    protected boolean pinIsSet = false;

    protected TransientHeap heap;
    protected SecureChannel sc;

    // Create an instance of the Applet subclass using its constructor, 
    // and to register the instance.
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        if(bArray!=null && bArray.length > 0){
            // the line below works on the card, but not in the simulator
            new SecureApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);;
        }else{
            // keep the simulator happy and register without arguments
            new SecureApplet().register();
        }
    }
    public SecureApplet(){
        // maybe should be a parameter in the constructor?
        heap = new TransientHeap(LENGTH_TRANSIENT_HEAP);
        // Crypto primitives. 
        // Keep it in this order.
        FiniteField.init(heap);
        Secp256k1.init(heap);
        Crypto.init(heap);
        sc = new SecureChannel(heap);
        // maybe also should be a parameter in the constructor?
        pin = new PinCode(PIN_MAX_COUNTER, PIN_MAX_LENGTH);
    }
    /** Redefine this function in your applet to process secure message
     *  return number of bytes written in the buffer
     *  you can write starting from offset 0 */
    protected short processSecureMessage(byte[] buf, short len){
        ISOException.throwIt(ERR_INVALID_CMD);
        return LENGTH_RESPONSE_CODE;
    }
    /** Redefine this function in your applet to handle plaintext message
     *  return number of bytes written in the buffer
     *  you can write starting from offset 0
     *  WARNING: no secure channel means MITM attack possibility */
    protected short processPlainMessage(byte[] buf, short len){
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        // keep IDE happy...
        return 0;
    }

    // Process the command APDU, 
    // All APDUs are received by the JCRE and preprocessed. 
    public void process(APDU apdu){
        // Select the Applet, through the select method, this applet is selectable, 
        // After successful selection, all APDUs are delivered to the currently selected applet
        // via the process method.
        if (selectingApplet()){
            return;
        }
        // Receive incoming data
        // might be limited by the apdu buffer
        // but should work fine with messages up to 255 bytes
        byte[] buf = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        short dataLen = Util.makeShort((byte)0, buf[ISO7816.OFFSET_LC]);
        short dataOff = ISO7816.OFFSET_CDATA;

        short len = 0;
        // check CLA
        if(buf[ISO7816.OFFSET_CLA] == SECURE_CLA){
            // Dispatch INS in APDU.
            switch (buf[ISO7816.OFFSET_INS]){
            case INS_GET_CARD_PUBKEY:
                len = fillCardPubkey(buf, OFFSET_PLAIN_PAYLOAD);
                break;
            case INS_OPEN_SECURE_CHANNEL_SS_MODE:
                // first - lock the card to avoid active MITM
                lock();
                len = openChannelSS(buf, dataOff, dataLen, buf, OFFSET_PLAIN_PAYLOAD);
                break;
            case INS_OPEN_SECURE_CHANNEL_ES_MODE:
                // first - lock the card to avoid active MITM
                lock();
                len = openChannelES(buf, dataOff, dataLen, buf, OFFSET_PLAIN_PAYLOAD);
                break;
            case INS_OPEN_SECURE_CHANNEL_EE_MODE:
                // first - lock the card to avoid active MITM
                lock();
                len = openChannelEE(buf, dataOff, dataLen, buf, OFFSET_PLAIN_PAYLOAD);
                break;
            case INS_SECURE_MESSAGE:
                // Try to handle secure message
                // Only secure channel exceptions will get here
                // as internal exceptions are caught and transmitted
                // over secure channel
                try {
                    len = handleSecureMessage(buf, dataOff, dataLen);
                } catch (ISOException e){
                    // something is wrong with secure channel
                    // so we close channel and lock the card
                    sc.closeChannel();
                    lock();
                    ISOException.throwIt(e.getReason());
                } catch (Exception e) {
                    // all other exceptions - replace reason with general error
                    sc.closeChannel();
                    lock();
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                }
                break;
            case INS_GET_RANDOM:
                len = fillRandom(buf, OFFSET_PLAIN_PAYLOAD, LENGTH_RANDOM_DATA);
                break;
            case INS_CLOSE_CHANNEL:
                // lock the card
                lock();
                // close secure channel
                sc.closeChannel();
                break;
            default:
                len = processPlainMessage(buf, dataLen);
            }
        }else{
            len = processPlainMessage(buf, dataLen);
        }

        apdu.setOutgoing();
        apdu.setOutgoingLength(len);
        apdu.sendBytesLong(buf, (short)0, len);
    }
    /** Puts unique public key of the card to the message buffer */
    private short fillCardPubkey(byte[] buf, short off){
        return sc.serializeStaticPublicKey(buf, off);
    }
    /**
     * Open a secure channel using SS (static-static) mode.
     * Message should have a form: {@code uncompressed_host_pubkey | host_nonce} 
     * This function writes card nonce to the output buffer, adds MAC and signature to it.
     * @param msg    - buffer containing message with host pubkey and host nonce
     * @param msgOff - offset in the buffer
     * @param msgLen - length of the message
     * @param out    - output buffer to write responce to (can be the same as input)
     * @param outOff - offset in the output buffer
     * @return number of bytes written into the output buffer 
     */
    private short openChannelSS(byte[] msg, short msgOff, short msgLen, byte[] out, short outOff){
        // check if data length is ok
        if(msgLen != (short)(SecureChannel.LENGTH_NONCE + Secp256k1.LENGTH_PUBLIC_KEY_UNCOMPRESSED)){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // will put nonce there
        short nonceOff = (short)(msgOff + Secp256k1.LENGTH_PUBLIC_KEY_UNCOMPRESSED);
        short len = sc.openChannelSS(msg, msgOff, msg, nonceOff, out, outOff);
        // add hmac using shared secret
        len += sc.authenticateData(out, outOff, len, out, (short)(outOff+len));
        // add signature with static pubkey
        len += sc.signData(out, outOff, len, out, (short)(outOff+len));
        return len;
    }
    /**
     * Open a secure channel using ES (ephemeral-static) mode.
     * Message should have a form: {@code uncompressed_host_pubkey} 
     * This function writes card nonce to the output buffer, adds MAC and signature to it.
     * @param msg    - buffer containing message with host pubkey
     * @param msgOff - offset in the buffer
     * @param msgLen - length of the message
     * @param out    - output buffer to write responce to (can be the same as input)
     * @param outOff - offset in the output buffer
     * @return number of bytes written into the output buffer 
     */
    private short openChannelES(byte[] msg, short msgOff, short msgLen, byte[] out, short outOff){
        // check if data length is ok
        if(msgLen != Secp256k1.LENGTH_PUBLIC_KEY_UNCOMPRESSED){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // will put nonce there
        short len = sc.openChannelES(msg, msgOff, out, outOff);
        // add hmac using shared secret
        len += sc.authenticateData(out, outOff, len, out, (short)(outOff+len));
        // add signature with static pubkey
        len += sc.signData(out, outOff, len, out, (short)(outOff+len));
        return len;
    }
    /**
     * Open a secure channel using EE (ephemeral-ephemeral) mode.
     * Message should have a form: {@code uncompressed_host_pubkey} 
     * This function writes card ephemeral key to the output buffer, adds MAC and signature to it.
     * @param msg    - buffer containing message with host pubkey
     * @param msgOff - offset in the buffer
     * @param msgLen - length of the message
     * @param out    - output buffer to write responce to (can be the same as input)
     * @param outOff - offset in the output buffer
     * @return number of bytes written into the output buffer 
     */
    private short openChannelEE(byte[] msg, short msgOff, short msgLen, byte[] out, short outOff){
        // check if data length is ok
        if(msgLen != Secp256k1.LENGTH_PUBLIC_KEY_UNCOMPRESSED){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // for consistency with se mode
        short len = sc.openChannelEE(msg, msgOff, out, outOff);
        // add hmac using shared secret
        len += sc.authenticateData(out, outOff, len, out, (short)(outOff+len));
        // add signature with static pubkey
        len += sc.signData(out, outOff, len, out, (short)(outOff+len));
        return len;
    }
    private short handleSecureMessage(byte[] msg, short msgOff, short msgLen){
        short len = sc.decryptMessage(msg, (short)(msgOff+OFFSET_SECURE_MESSAGE), msgLen,
                                      msg, OFFSET_SECURE_MESSAGE);
        try{
            // processes message and returns len of the responce to send back to host
            // responce is placed back to the same buffer
            len = preprocessSecureMessage(msg, len);
        // code can throw an exception and 
        // it will be transmitted over secure channel
        }catch(ISOException e){
            len = setResponseCode(e.getReason(), msg);
        }catch(Exception e){
            len = setResponseCode(ISO7816.SW_UNKNOWN, msg);
        }
        // encrypt buffer and send to the host
        return sc.encryptMessage(msg, OFFSET_SECURE_MESSAGE, len, msg, OFFSET_SECURE_MESSAGE);
    }
    private short preprocessSecureMessage(byte[] buf, short len){
        if(len < LENGTH_CMD_SUBCMD){
            ISOException.throwIt(ERR_INVALID_LEN);
        }
        switch (buf[OFFSET_CMD]){
            case CMD_ECHO:
                if(buf[OFFSET_SUBCMD] == SUBCMD_DEFAULT){
                    return setEcho(buf, len);
                }else{
                    ISOException.throwIt(ERR_INVALID_SUBCMD);
                }
                break;
            case CMD_RAND:
                if(buf[OFFSET_SUBCMD] == SUBCMD_DEFAULT){
                    short lenOut = setResponseCode(RESPONSE_SUCCESS, buf);
                    lenOut += fillRandom(buf, OFFSET_SECURE_PAYLOAD, LENGTH_RANDOM_DATA);
                    return lenOut;
                }else{
                    ISOException.throwIt(ERR_INVALID_SUBCMD);
                }
                break;
            case CMD_PIN:
                return processPinCommand(buf, len);
            default:
                return processSecureMessage(buf, len);
        }
        // keep IDE happy...
        return 0;
    }
    /**
     * Set error code in the secure response
     * @param errorcode - code to set
     * @param buf       - buffer with response
     * @return number of bytes written to buffer
     */
    protected short setResponseCode(short errorcode, byte[] buf){
        Util.setShort(buf, OFFSET_RESPONSE_CODE, errorcode);
        return LENGTH_RESPONSE_CODE;
    }
    /**
     * Sets echo of the same payload. Just replaces CMD with SUCCESS.
     * @param buf    - buffer with the command
     * @param offset - offset of the buffer
     * @param len    - length of the command
     * @return number of bytes to send
     */
    private short setEcho(byte[] buf, short len){
        // just replace CMD and keep the data the same
        setResponseCode(RESPONSE_SUCCESS, buf);
        return len;
    }
    private short processPinCommand(byte[] buf, short len){
        byte subcmd = buf[OFFSET_SUBCMD];
        short lenOut = setResponseCode(RESPONSE_SUCCESS, buf);
        switch(subcmd){
            case SUBCMD_PIN_STATUS:
                lenOut += fillPinStatus(buf, OFFSET_SECURE_PAYLOAD);
                return lenOut;
            case SUBCMD_PIN_UNLOCK:
                // check if PIN is set
                if(!pinIsSet){
                    ISOException.throwIt(ERR_NOT_INITIALIZED);
                }
                if(len > (short)(PIN_MAX_LENGTH+LENGTH_CMD_SUBCMD)){
                    ISOException.throwIt(ERR_INVALID_LEN);
                }
                // check if any attempts left
                if(pin.getTriesRemaining() == 0){
                    ISOException.throwIt(ERR_NO_ATTEMPTS_LEFT);
                }
                // check PIN
                if(!pin.check(buf, OFFSET_SECURE_PAYLOAD, (byte)(len-LENGTH_CMD_SUBCMD))){
                    ISOException.throwIt(ERR_INVALID_PIN);
                }
                return LENGTH_RESPONSE_CODE;
            case SUBCMD_PIN_LOCK:
                lock();
                return LENGTH_RESPONSE_CODE;
            case SUBCMD_PIN_CHANGE:
                // check data lengths: at least two empty elements
                if(len < (short)(LENGTH_CMD_SUBCMD+2)){
                    ISOException.throwIt(ERR_INVALID_LEN);
                }
                byte  oldPinLen = buf[OFFSET_SECURE_PAYLOAD];
                short oldPinOff = (short)(OFFSET_SECURE_PAYLOAD+1);
                byte  newPinLen = buf[(short)(oldPinOff+oldPinLen)];
                short newPinOff = (short)(oldPinOff+oldPinLen+1);
                if(len != (short)(newPinOff+newPinLen) || oldPinLen > PIN_MAX_LENGTH || newPinLen > PIN_MAX_LENGTH){
                    ISOException.throwIt(ERR_INVALID_LEN);
                }
                if(!pinIsSet){
                    ISOException.throwIt(ERR_NOT_INITIALIZED);
                }
                if(!pin.check(buf, oldPinOff, oldPinLen)){
                    ISOException.throwIt(ERR_INVALID_PIN);
                }else{
                    // change pin and unlock
                    pin.update(buf, newPinOff, newPinLen);
                    pin.check(buf, newPinOff, newPinLen);
                }
                return LENGTH_RESPONSE_CODE;
            case SUBCMD_PIN_SET:
                if(pinIsSet){
                    ISOException.throwIt(ERR_PIN_ALREADY_SET);
                }
                if(len > (short)(PIN_MAX_LENGTH+LENGTH_CMD_SUBCMD)){
                    ISOException.throwIt(ERR_INVALID_LEN);
                }
                byte pinLen = (byte)(len-LENGTH_CMD_SUBCMD);
                JCSystem.beginTransaction();
                    pin.update(buf, OFFSET_SECURE_PAYLOAD, pinLen);
                    pinIsSet = true;
                JCSystem.commitTransaction();
                // should never throw
                if(!pin.check(buf, OFFSET_SECURE_PAYLOAD, (byte)(len-LENGTH_CMD_SUBCMD))){
                    ISOException.throwIt(ERR_INVALID_PIN);
                }
                return LENGTH_RESPONSE_CODE;
            case SUBCMD_PIN_UNSET:
                if(pinIsSet){
                    // check len
                    if(len > (short)(PIN_MAX_LENGTH+LENGTH_CMD_SUBCMD)){
                        ISOException.throwIt(ERR_INVALID_LEN);
                    }
                    // verify PIN
                    if(!pin.check(buf, OFFSET_SECURE_PAYLOAD, (byte)(len-LENGTH_CMD_SUBCMD))){
                        ISOException.throwIt(ERR_INVALID_PIN);
                    }
                    // unset PIN
                    JCSystem.beginTransaction();
                        pin.resetAndUnblock();
                        pinIsSet = false;
                    JCSystem.commitTransaction();
                }
                return LENGTH_RESPONSE_CODE;
            default:
                ISOException.throwIt(ERR_INVALID_SUBCMD);
        }
        return LENGTH_RESPONSE_CODE;
    }
    /** Locks the card */
    protected void lock(){
        if(pinIsSet && pin.isValidated()){
            pin.reset();
        }
    }
    private short fillPinStatus(byte[] buf, short offset){
        short out = offset;
        if(!pinIsSet){
            buf[out++] = PIN_MAX_COUNTER;
            buf[out++] = PIN_MAX_COUNTER;
            buf[out++] = STATUS_PIN_NOT_SET;
        }else{
            buf[out++] = pin.getTriesRemaining();
            buf[out++] = PIN_MAX_COUNTER;
            if(pin.getTriesRemaining() == 0){
                buf[out++] = STATUS_CARD_BRICKED;
            }else{
                if(pin.isValidated()){
                    buf[out++] = STATUS_CARD_UNLOCKED;
                }else{
                    buf[out++] = STATUS_CARD_LOCKED;
                }
            }
        }
        return (short)(out-offset);
    }
    // check if card is currently locked
    protected boolean isLocked(){
        if(!pinIsSet){
            return false;
        }
        if(pin.getTriesRemaining() == 0){
            return true;
        }
        return !pin.isValidated();
    }
    protected boolean isPinSet(){
        return pinIsSet;
    }
    /**
     * Places random data in the buffer
     * @param buf - buffer to put random data to
     * @param off - offset in the buffer
     * @param len - length of random data
     * @return number of bytes written to the buffer
     */
    private short fillRandom(byte[] buf, short off, short len){
        // fill buffer with 32 bytes of random data
        Crypto.random.generateData(buf, off, len);
        return len;
    }
    public void deselect() {
        pin.reset();
    }
}