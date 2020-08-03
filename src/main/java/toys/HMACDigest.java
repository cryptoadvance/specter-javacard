package toys;

import javacard.framework.*;
import javacard.security.*;

/**
 * HMAC for any MessageDigest instance.
 */
public class HMACDigest {

    static final public byte IPAD = (byte) 0x36;
    static final public byte OPAD = (byte) 0x5c;

    static final public short ALG_SHA_256_BLOCK_SIZE = (short)64;
    static final public short ALG_SHA_512_BLOCK_SIZE = (short)128;

    private MessageDigest hash; // hash function
    private byte[] key;         // buffer to store the HMAC key
    private byte[] intBuf;      // temp buffer for internal usage
    private short blockSize;    // block size of the hash function

    /**
     * Constructor. Allocates stuff.
     *
     * @param digestAlgo instance of hash function (MessageDigest)
     * @param blocksize  length of the block, for example:
     *                   HMACDigest.ALG_SHA_256_BLOCK_SIZE
     *                   HMACDigest.ALG_SHA_512_BLOCK_SIZE 
     *                   or any other depending on your hash function
     */
    HMACDigest(MessageDigest digestAlgo, short blocksize) {
        hash = digestAlgo;
        blockSize = blocksize;
        intBuf = JCSystem.makeTransientByteArray(hash.getLength(), JCSystem.CLEAR_ON_DESELECT);
        key = JCSystem.makeTransientByteArray(blockSize, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Initializes HMAC with a key
     * @param hmacKey - buffer with the key for HMAC
     * @param offset  - offset position of the key in the buffer
     * @param len     - length of the key
     */
    public void init(byte[] hmacKey, short offset, short len){
        // fill key with zeroes
        Util.arrayFillNonAtomic(key, (short)0, blockSize, (byte)0x00);
        if(len > blockSize) {
            hash.reset();
            hash.doFinal(hmacKey, offset, len, key, (short)0);
        }else{
            Util.arrayCopyNonAtomic(hmacKey, offset, key, (short)0, len);
        }
        for(short i = (short)0; i < blockSize; i++) {
            key[i] ^= IPAD;
        }
        hash.reset();
        hash.update(key, (short)0, blockSize);
    }

    /**
     * Updates HMAC with a message
     * @param msg     - buffer with the message
     * @param offset  - offset position of the msg in the buffer
     * @param len     - length of the msg
     */
    public void update(byte[] msg, short offset, short len){
        hash.update(msg, offset, len);
    }

    /**
     * Expected length of the HMAC output.
     * 
     * @return number of bytes will be produced by .doFinal()
     */  
    public short getLength(){
        return hash.getLength();
    }

    /**
     * Finalizes HMAC with a message
     * @param msg       - buffer with the message
     * @param offset    - offset position of the msg in the buffer
     * @param len       - length of the msg
     * @param outBuf    - buffer to put result in
     * @param outOffset - offset for the output buffer
     *
     * @return number of bytes written to outBuf
     */
    public short doFinal(byte[] msg, short offset, short len, byte[] outBuf, short outOffset){
        hash.doFinal(msg, offset, len, intBuf, (short)0);
        short i = (short)0;
        for(i = (short)0; i < blockSize; i++) {
            key[i] ^= (IPAD^OPAD); // undo IPAD
        }
        hash.update(key, (short)0, blockSize);
        return hash.doFinal(intBuf, (short)0, hash.getLength(), outBuf, outOffset);
    }

    /**
     * Clean up. No real need in it - .init() will reset everything anyways.
     */
    public void reset(){
        hash.reset();
        Util.arrayFillNonAtomic(key, (short)0, blockSize, (byte)0);
        Util.arrayFillNonAtomic(intBuf, (short)0, hash.getLength(), (byte)0);
    }
}
