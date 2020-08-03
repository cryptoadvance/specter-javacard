package toys;

// import using java card API interface.
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 * Secure channel class to manage secure communication with the host.
 * <p>
 * When class instance is initiated it creates a static key pair
 * that can be used to make sure the card is the same.
 * <p>
 * This key pair is also used to establish a shared secret using
 * EE (ephemeral keys on both sides), ES (ephemeral key on the card) 
 * or SS (both keys are static) mode for key agreement algorithm.
 */
public class SecureChannel{
    /** Nonce size for ES and SS modes */
    static final public short LENGTH_NONCE      = (short)32;
    /** Key size for AES */
    static final public short LENGTH_AES_KEY    = (short)32;
    /** Size of a single AES block */
    static final public short LENGTH_AES_BLOCK  = (short)16;
    /** Key size for HMAC */
    static final public short LENGTH_MAC_KEY    = (short)32;
    /** Max of AES, HMAC and EC key sizes for efficient heap allocations */
    static final public short MAX_LENGTH_KEY    = (short)32;
    /** Size of the HMAC code used in messages. 
     *  We reduce it to 15 bytes to increase data capacity. */
    static final public short LENGTH_MAC        = (short)15;
    /** Size of the IV for AES */
    static final public short LENGTH_IV         = (short)16;
    /** Maximum size of the cyphertext including MAC */
    static final public short MAX_LENGTH_CT     = (short)255;
    /** Maximum size of plaintext message we can encrypt. 
     *  We need to add at least 1 byte of padding and MAC */
    static final public short MAX_LENGTH_PLAIN  = (short)(MAX_LENGTH_CT-LENGTH_MAC_KEY-1);

    /** Static key pair generated when class instance is created */
    private KeyPair staticKeyPair;
    /** Ephemeral private key for channel establishment */
    private ECPrivateKey ephemeralPrivateKey;

    /** Prefix to derive card keys from shared secret */
    static final private byte PREFIX_CARD[] = { 'c', 'a', 'r', 'd' };
    /** Prefix to derive host keys from shared secret */
    static final private byte PREFIX_HOST[] = { 'h', 'o', 's', 't' };
    /** Prefix to derive AES keys from shared secret */
    static final private byte PREFIX_AES[] = { '_', 'a', 'e', 's' };
    /** Prefix to derive HMAC keys from shared secret */
    static final private byte PREFIX_MAC[] = { '_', 'm', 'a', 'c' };
    
    /** AES card key, used to encrypt messages returned from the card */
    private AESKey cardAESKey;
    /** AES host key, used to decrypt messages coming from the host */
    private AESKey hostAESKey;
    /** HMAC card key, used to authenticate data returned from the card */
    private byte cardMACKey[];
    /** HMAC host key, used to check authentication of incoming data */
    private byte hostMACKey[];
    /** Initialization vector for AES encryption/decryption.
     *  Used in a counter mode - increased by 1 on every message. */
    private byte iv[];
    /** TransientHeap instance that is used to temporarly allocate memory
     *  for some internal operations. */
    private TransientHeap heap;

    /** Constructor for SecureChannel.
     *  @param hp - TransientHeap instance to use for internal temporary memory allocations. */
    public SecureChannel(TransientHeap hp){
        heap = hp;
        // generate random secret key for secure communication
        staticKeyPair = Secp256k1.newKeyPair();
        staticKeyPair.genKeyPair();
        // generate random session key pair 
        ephemeralPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(ephemeralPrivateKey);
        iv = JCSystem.makeTransientByteArray(LENGTH_IV, JCSystem.CLEAR_ON_DESELECT);

        cardAESKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
        hostAESKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
        hostMACKey = JCSystem.makeTransientByteArray(LENGTH_MAC_KEY, JCSystem.CLEAR_ON_DESELECT);
        cardMACKey = JCSystem.makeTransientByteArray(LENGTH_MAC_KEY, JCSystem.CLEAR_ON_DESELECT);
        // even though the channel is not open yet, we close it
        // that overwrites all keys with random junk
        closeChannel();
    }
    /** Get static public key of the channel generated in the constructor.
     *  @return static public key as ECPublicKey instance */
    public ECPublicKey getStaticPublicKey(){
        return (ECPublicKey)staticKeyPair.getPublic();
    }
    /** Get static public key of the secure channel generated in the constructor
     *  in uncompressed serialized format (65 bytes, {@code <04><x><y>})
     *  @param buf - bytearray to put public key in
     *  @param offset - position where to start
     *  @return number of bytes written to the buffer (65) */
    public short serializeStaticPublicKey(byte[] buf, short offset){
        ECPublicKey pub = getStaticPublicKey();
        return pub.getW(buf, offset);
    }
    /**
     * Open secure channel in Static-Static mode.
     * <p>
     * Both the host and the card use a static key.
     * <p>
     * Shared secret is calculated as {@code sha256(ecdh(e,s)|host_nonce|card_nonce)}
     * 
     * @param hostPubkey    - buffer containing uncompressed host pubkey
     * @param hostPubkeyOff - offset where host pubkey starts
     * @param hostNonce     - buffer containing host nonce
     * @param hostNonceOff  - offset of the host nonce
     * @param cardNonce     - buffer to write card nonce
     * @param cardNonceOff  - offset for the card nonce
     * @return number of bytes written to the nonce buffer
     */
    public short openChannelSS(byte[] hostPubkey, short hostPubkeyOff,
                               byte[] hostNonce,  short hostNonceOff,
                               byte[] cardNonce,  short cardNonceOff)
    {
        short len = MAX_LENGTH_KEY;
        short off = heap.allocate(len);
        short ecdhLen = Secp256k1.ecdh( (ECPrivateKey)staticKeyPair.getPrivate(), 
                        hostPubkey, hostPubkeyOff, 
                        heap.buffer, off);
        // calculating shared secret
        Crypto.sha256.reset();
        Crypto.sha256.update(heap.buffer, off, ecdhLen);
        // add host nonce
        Crypto.sha256.update(hostNonce, hostNonceOff, LENGTH_NONCE);
        // add card nonce
        Crypto.random.generateData(cardNonce, cardNonceOff, LENGTH_NONCE);
        Crypto.sha256.doFinal(cardNonce, cardNonceOff, LENGTH_NONCE, heap.buffer, off);
        openChannel(heap.buffer, off, (short)Crypto.sha256.getLength());
        heap.free(len);
        return LENGTH_NONCE;
    }
    /**
     * Open secure channel in Ephemeral-Static mode.
     * <p>
     * Host uses an ephemeral key, card uses a static key.
     * <p>
     * Shared secret is calculated as {@code sha256(ecdh(e,s)|card_nonce)}
     * 
     * @param hostPubkey    - buffer containing uncompressed host pubkey
     * @param hostPubkeyOff - offset where host pubkey starts
     * @param cardNonce     - buffer to write card nonce
     * @param cardNonceOff  - offset for the card nonce
     * @return number of bytes written to the nonce buffer
     */
    public short openChannelES(byte[] hostPubkey, short hostPubkeyOff,
                               byte[] cardNonce,  short cardNonceOff)
    {
        short len = MAX_LENGTH_KEY;
        short off = heap.allocate(len);
        short ecdhLen = Secp256k1.ecdh( (ECPrivateKey)staticKeyPair.getPrivate(), 
                        hostPubkey, hostPubkeyOff, 
                        heap.buffer, off);
        // calculating shared secret
        Crypto.sha256.reset();
        Crypto.sha256.update(heap.buffer, off, ecdhLen);
        // add card nonce
        Crypto.random.generateData(cardNonce, cardNonceOff, LENGTH_NONCE);
        Crypto.sha256.doFinal(cardNonce, cardNonceOff, LENGTH_NONCE, heap.buffer, off);
        openChannel(heap.buffer, off, (short)Crypto.sha256.getLength());
        heap.free(len);
        return LENGTH_NONCE;
    }
    /**
     * Open secure channel in Ephemeral-Ephemeral mode.
     * <p>
     * Both the host and the card use an ephemeral key.
     * <p>
     * Shared secret is calculated as {@code sha256(ecdh(e,e))}
     * 
     * @param hostPubkey    - buffer containing uncompressed host pubkey
     * @param hostPubkeyOff - offset where host pubkey starts
     * @param cardPubkey    - buffer to write ephemeral public key of the card to
     * @param cardPubkeyOff - offset where to start writing
     * @return number of bytes written to the nonce buffer
     */
    public short openChannelEE(
                    byte[] hostPubkey, short hostPubkeyOff,
                    byte[] cardPubkey, short cardPubkeyOff)
    {
        short len = MAX_LENGTH_KEY;
        short off = heap.allocate(len);
        Secp256k1.generateRandomSecret(heap.buffer, off);
        ephemeralPrivateKey.setS(heap.buffer, off, Secp256k1.LENGTH_PRIVATE_KEY);
        short ecdhLen = Secp256k1.ecdh( ephemeralPrivateKey, 
                        hostPubkey, hostPubkeyOff, 
                        heap.buffer, off);
        // calculating shared secret
        Crypto.sha256.reset();
        Crypto.sha256.doFinal(heap.buffer, off, ecdhLen, heap.buffer, off);
        openChannel(heap.buffer, off, (short)Crypto.sha256.getLength());
        heap.free(len);
        // pubkey is just ECDH of private key with G
        return Secp256k1.getPublicKey( ephemeralPrivateKey, false,
                        cardPubkey, cardPubkeyOff);
    }
    /**
     * Opens a secure channel based on shared secret.
     * <p>
     * Derives AES and MAC keys, fills IV with zeroes
     * 
     * @param secret    - buffer containing shared secret 
     * @param secretOff - offset of the secret in the buffer
     * @param secretLen - length of the shared secret
     */
    private void openChannel(byte[] secret, short secretOff, short secretLen){
        // derive AES and MAC keys
        short len = LENGTH_AES_KEY;
        short off = heap.allocate(len);

        // card AES key
        Crypto.sha256.reset();
        Crypto.sha256.update(PREFIX_CARD, (short)0, (short)PREFIX_CARD.length);
        Crypto.sha256.update(PREFIX_AES, (short)0, (short)PREFIX_AES.length);
        Crypto.sha256.doFinal(secret, secretOff, secretLen, heap.buffer, off);
        cardAESKey.setKey(heap.buffer, off);

        // host AES key
        Crypto.sha256.reset();
        Crypto.sha256.update(PREFIX_HOST, (short)0, (short)PREFIX_HOST.length);
        Crypto.sha256.update(PREFIX_AES, (short)0, (short)PREFIX_AES.length);
        Crypto.sha256.doFinal(secret, secretOff, secretLen, heap.buffer, off);
        hostAESKey.setKey(heap.buffer, off);

        heap.free(len);

        // card MAC key
        Crypto.sha256.reset();
        Crypto.sha256.update(PREFIX_CARD, (short)0, (short)PREFIX_CARD.length);
        Crypto.sha256.update(PREFIX_MAC, (short)0, (short)PREFIX_MAC.length);
        Crypto.sha256.doFinal(secret, secretOff, secretLen, cardMACKey, (short)0);

        // host MAC key
        Crypto.sha256.reset();
        Crypto.sha256.update(PREFIX_HOST, (short)0, (short)PREFIX_HOST.length);
        Crypto.sha256.update(PREFIX_MAC, (short)0, (short)PREFIX_MAC.length);
        Crypto.sha256.doFinal(secret, secretOff, secretLen, hostMACKey, (short)0);

        // now we can set iv counter to zero
        Util.arrayFillNonAtomic(iv, (short)0, (short)iv.length, (byte)0);
    }
    /**
     * Authenticates data with card's session MAC key.
     * @param data - buffer containing data to authenticate
     * @param dataOffset - offset of the data in the buffer
     * @param dataLen - length of the data in the buffer
     * @param out - output buffer to write authentication to
     * @param outOffset - offset of the output buffer where to start
     * @return number of bytes written to the buffer
     */
    public short authenticateData(byte[] data, short dataOffset, short dataLen, 
                                  byte[] out, short outOffset)
    {
        short len = Crypto.hmacSha256.getLength();
        short off = heap.allocate(len);
        Crypto.hmacSha256.init(cardMACKey, (short)0, (short)cardMACKey.length);
        Crypto.hmacSha256.doFinal(data, dataOffset, dataLen, heap.buffer, off);
        Util.arrayCopyNonAtomic(heap.buffer, off, out, outOffset, LENGTH_MAC);
        heap.free(len);
        return LENGTH_MAC;
    }
    /** 
     * Signs arbitrary data with unique keypair
     * AFAIK signing process is deterministic so this method
     * can be used for anti-phishing words generation
     * like ColdCard's double-PIN technique
     * <br>
     * Better to hash incoming data with a prefix,
     * for example "KeyCheck" to narrow down signing
     * to a particular action
     * @param data - buffer with data to sign
     * @param dataOffset - offset of the data in the buffer
     * @param dataLen - length of the data to sign
     * @param out - output buffer to put a signature
     * @param outOffset - offset in the output buffer
     * @return number of bytes written to the output buffer
     */
    public short signData(byte[] data, short dataOffset, short dataLen, 
                          byte[] out, short outOffset)
    {
        short len = (short)Crypto.sha256.getLength();
        short off = heap.allocate(len);

        Crypto.sha256.reset();
        Crypto.sha256.doFinal(data, dataOffset, dataLen, heap.buffer, off);
        short sigLen = Secp256k1.sign((ECPrivateKey)staticKeyPair.getPrivate(), heap.buffer, off, out, outOffset);
        heap.free(len);
        return sigLen;
    }
    /**
     * Dectypts message, also checks authentication code.
     * @param ct - buffer with the cyphertext to decrypt
     * @param ctOffset - offset of the cyphertext in the buffer
     * @param ctLen - length of the cyphertext including MAC
     * @param out - output buffer to put decrypted message to
     * @param outOffset - offest in the output buffer
     * @return number of bytes of the resulting plaintext message
     */
    public short decryptMessage(byte[] ct, short ctOffset, short ctLen, 
                                byte[] out, short outOffset)
    {
        // message should contain at least one block
        // and cyphertext without MAC should be % LENGTH_AES_BLOCK
        if( (ctLen < (short)(LENGTH_AES_BLOCK+LENGTH_MAC)) || 
            ((short)(ctLen - LENGTH_MAC) % LENGTH_AES_BLOCK != (short)0 )){
            closeChannel();
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        short len = (short)(ctLen - LENGTH_MAC);
        short off = heap.allocate(len);
        short dataLen = (short)(ctLen - LENGTH_MAC);
        // calculate expected hmac
        Crypto.hmacSha256.init(hostMACKey, (short)0, (short)hostMACKey.length);
        Crypto.hmacSha256.update(iv, (short)0, (short)iv.length);
        Crypto.hmacSha256.doFinal(ct, ctOffset, dataLen, heap.buffer, off);
        // check hmac is correct
        if(Util.arrayCompare(heap.buffer, off, ct, (short)(ctOffset+dataLen),LENGTH_MAC)!=(byte)0){
            closeChannel();
            heap.free(len);
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        // decrypt using current iv value
        Crypto.cipher.init(hostAESKey, Cipher.MODE_DECRYPT, iv, (short)0, (short)iv.length);
        short plainLen = Crypto.cipher.doFinal(ct, ctOffset, dataLen, heap.buffer, off);
        Util.arrayCopyNonAtomic(heap.buffer, off, out, outOffset, plainLen);
        heap.free(len);
        return plainLen;
    }
    /**
     * Encrypts message and appends authentication code
     * @param data - buffer containing data to encrypt
     * @param offset - offset of the data in the input buffer
     * @param dataLen - length of the data
     * @param cyphertext - buffer to put cyphertext to
     * @param ctOffset - offset of the output buffer
     * @return number of bytes written to the output buffer
     */
    public short encryptMessage(byte[] data, short offset, short dataLen, 
                                byte[] cyphertext, short ctOffset)
    {
        // check that plaintext will fit in max cyphertext length
        if(dataLen > MAX_LENGTH_PLAIN){
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        // allocate memory for iv and cyphertext
        short len = (short)(iv.length+MAX_LENGTH_CT);
        short ivOffOld = heap.allocate(len);
        short off = (short)(ivOffOld + iv.length);
        // copy IV value to temp buffer and increase IV
        Util.arrayCopyNonAtomic(iv, (short)0, heap.buffer, ivOffOld, (short)iv.length);
        increaseIV();
        // init cypher with old IV
        Crypto.cipher.init(cardAESKey, Cipher.MODE_ENCRYPT, heap.buffer, ivOffOld, (short)iv.length);
        // encrypt to heap
        short ctLen = Crypto.cipher.doFinal(data, offset, dataLen, heap.buffer, off);
        // copy encrypted text to output
        Util.arrayCopyNonAtomic(heap.buffer, off, cyphertext, ctOffset, ctLen);
        // add MAC to output
        ctLen += authenticateData(heap.buffer, ivOffOld, (short)(ctLen+(short)iv.length), 
                                  cyphertext, (short)(ctOffset+ctLen));
        // free used memory
        heap.free(len);
        return ctLen;
    }
    /** Increases IV by 1 */
    private void increaseIV(){
        short carry = 1;
        for(short i=(short)(iv.length-1); i>=0; i--){
            carry += (iv[i]&0xFF);
            iv[i] = (byte)carry;
            carry >>= 8;
        }
        if(carry!=0){
            closeChannel();
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }
    /**
     * Close secure channel.
     * <p>
     * Overwrites all secret keys with random data.
     */
    public void closeChannel(){
        // fill with random data to make sure that
        // nobody can talk to the card anymore
        Crypto.random.generateData(iv, (short)0, (short)iv.length);
        Crypto.random.generateData(hostMACKey,   (short)0, (short)hostMACKey.length);
        Crypto.random.generateData(cardMACKey,   (short)0, (short)cardMACKey.length);

        // we generate random data to the heap temp buffer and
        // reuse this buffer to set this random data as AES keys
        short len = LENGTH_AES_KEY;
        short off = heap.allocate(len);
        Crypto.random.generateData(heap.buffer, off, LENGTH_AES_KEY);
        cardAESKey.setKey(heap.buffer, off);
        Crypto.random.generateData(heap.buffer, off, LENGTH_AES_KEY);
        hostAESKey.setKey(heap.buffer, off);
        // free heap
        heap.free(len);
    }
}