package toys;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 * All instances of crypto primitives are here.
 * <p>
 * Call .init() once in the applet.
 * <p>
 * All functions are static, so they can be used from other classes.
 * This approach saves RAM
 */
public class Crypto{
    static public RandomData random;
    static public MessageDigest sha256;
    static public MessageDigest sha512;
    static public HMACDigest hmacSha256;
    static public HMACDigest hmacSha512;
    static public Cipher cipher;
    static private TransientHeap heap;

    static public void init(TransientHeap hp){
        heap = hp;
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
        hmacSha256 = new HMACDigest(sha256, HMACDigest.ALG_SHA_256_BLOCK_SIZE);
        hmacSha512 = new HMACDigest(sha512, HMACDigest.ALG_SHA_512_BLOCK_SIZE);
        cipher = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2,false);
    }
    /**
     * One-line PBKDF2 algorithm for Bitcoin stuff. Outputs 64 bytes.
     * 
     * @param pass - buffer with the password
     * @param pOff - offset of the password
     * @param pLen - length of the password
     * @param salt - buffer with the salt
     * @param sOff - offset of the salt
     * @param sLen - length of the salt
     * @param iterations - number of iterations to run pbkdf2 (use 2048 for bip39)
     * @param out  - output buffer
     * @param outOff - output offset
     * @return number of bytes written to the buffer (64)
     * @throws ISOException if interation is <= 0
     */
    static public short pbkdf2(byte[] pass, short pOff, short pLen,
                              byte[] salt, short sOff, short sLen,
                              short iterations,
                              byte[] out, short outOff) throws ISOException{
        if(iterations <= 0){
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        // put into RAM, it will slightly speed up calculations
        short blockSize = HMACDigest.ALG_SHA_512_BLOCK_SIZE;
        byte ipad = HMACDigest.IPAD;
        byte opad = HMACDigest.OPAD;
        MessageDigest hash = sha512;
        hash.reset();
        // get temp buffer for ikey, okey and U
        short len = (short)(blockSize*2+64);
        short ikeyOff = heap.allocate(len);
        short okeyOff = (short)(ikeyOff+blockSize);
        short dataOff = (short)(okeyOff+blockSize);
        byte[] buf = heap.buffer;

        if(pLen > blockSize) {
            hash.doFinal(pass, pOff, pLen, buf, ikeyOff);
        }else{
            Util.arrayCopyNonAtomic(pass, pOff, buf, ikeyOff, pLen);
        }
        Util.arrayCopyNonAtomic(buf, ikeyOff, buf, okeyOff, blockSize);
        for(short i = (short)0; i < blockSize; i++) {
            buf[(short)(ikeyOff+i)] ^= ipad;
            buf[(short)(okeyOff+i)] ^= opad;
        }
        // i = 1
        Util.arrayFillNonAtomic(buf, dataOff, (short)4, (byte)0);
        buf[(short)(dataOff+3)] = (byte)1;
        // U
        hash.update(buf, ikeyOff, blockSize);
        hash.update(salt, sOff, sLen);
        hash.doFinal(buf, dataOff, (short)4, buf, dataOff);
        hash.update(buf, okeyOff, blockSize);
        hash.doFinal(buf, dataOff, (short)64, buf, dataOff);

        Util.arrayCopyNonAtomic(buf, dataOff, out, outOff, (short)64);
        for(short j=(short)2; j<=iterations; j++){
            hash.update(buf, ikeyOff, blockSize);
            hash.doFinal(buf, dataOff, (short)64, buf, dataOff);
            hash.update(buf, okeyOff, blockSize);
            hash.doFinal(buf, dataOff, (short)64, buf, dataOff);
            for(short i = (short)0; i < (short)64; i++) {
                out[(short)(outOff+i)] ^= buf[(short)(dataOff+i)];
            }
        }
        // get our memory back
        heap.free(len);
        return hash.getLength();
    }
}