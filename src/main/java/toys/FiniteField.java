package toys;

import javacard.framework.*;
import javacardx.crypto.Cipher;
import javacard.security.RSAPublicKey;
import javacard.security.KeyBuilder;

/**
 * Utility methods to work with the field elements used in Secp256k1.
 * <p>
 * There is no need to create a new instance of this class, 
 * but you have to call FiniteField.init(heap) method in the applet constructor.
 * TransientHeap instance is used to allocate memory when the class needs it.
 */
public class FiniteField{
    /** Field prime P, 64-byte version for RSA512 engine */
    static final private byte[] RSA_FP = {
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,(byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F
    };
    /** Curve order N, 64-byte version for RSA512 engine */
    static final private byte[] RSA_N = {
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
        (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6,(byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
        (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C,(byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41
    };
    /** {@code (P+1)/4} - a constant to calculate square root modulo P */
    static final private byte[] ROOT_FP = {
        (byte)0x3F,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xBF,(byte)0xFF,(byte)0xFF,(byte)0x0C
    };
    /** RSA engine used for exponentiations */
    static private Cipher rsaCipher;

    /** RSA public key used for opreations modulo curve order N */
    static private RSAPublicKey rsaModN;
    /** RSA public key used to calculate 1/a modulo N */
    static private RSAPublicKey rsaInverseN;

    /** RSA public key used for operations modulo field prime P */
    static private RSAPublicKey rsaModFP;
    // common operations on modulo P:
    /** RSA public key used to calculate square root modulo P */
    static private RSAPublicKey rsaRootFP;
    /** RSA public key used to calculate square modulo P */
    static private RSAPublicKey rsaSqaureFP;
    /** RSA public key used to calculate cube modulo P */
    static private RSAPublicKey rsaCubeFP;
    /** RSA public key used to calculate 1/a modulo P */
    static private RSAPublicKey rsaInverseFP;

    /** Memory allocator */
    static private TransientHeap heap;

    /** Size of the field element in bytes */
    final static public short LENGTH_FIELD_ELEMENT = (short)32;
    /** Size of the RSA key in bytes */
    final static public short LENGTH_RSA_KEY = (short)64;
    /** offset in RSA_* for 32-byte field element */
    final static public short OFFSET_FIELD_ELEMENT = (short)(LENGTH_RSA_KEY-LENGTH_FIELD_ELEMENT);

    /**
     * Allocates objects needed by this class.
     * <p>
     * Must be invoked during the applet installation exactly 1 time.
     * @param hp - instance of the TransientHeap class for memory allocations
     */
    static public void init(TransientHeap hp)
    {
        heap = hp;
        rsaModN = (RSAPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
        rsaInverseN = (RSAPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
        rsaModFP = (RSAPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
        rsaRootFP = (RSAPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
        rsaSqaureFP = (RSAPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
        rsaCubeFP = (RSAPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
        rsaInverseFP = (RSAPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        rsaModN.setModulus(RSA_N, (short)0, (short)RSA_N.length);        
        rsaModFP.setModulus(RSA_FP, (short)0, (short)RSA_FP.length);

        rsaRootFP.setModulus(RSA_FP, (short)0, (short)RSA_FP.length);
        rsaRootFP.setExponent(ROOT_FP, (short)0, (short)ROOT_FP.length);

        short off = heap.allocate(LENGTH_FIELD_ELEMENT);
        byte[] buf = heap.buffer;
        short lastOff = (short)(off+LENGTH_FIELD_ELEMENT-1);

        buf[lastOff] = (byte)2;
        rsaSqaureFP.setModulus(RSA_FP, (short)0, (short)RSA_FP.length);
        rsaSqaureFP.setExponent(buf, off, LENGTH_FIELD_ELEMENT);

        buf[lastOff] = (byte)3;
        rsaCubeFP.setModulus(RSA_FP, (short)0, (short)RSA_FP.length);
        rsaCubeFP.setExponent(buf, off, LENGTH_FIELD_ELEMENT);

        rsaInverseN.setModulus(RSA_N, (short)0, (short)RSA_N.length);
        Util.arrayCopyNonAtomic(RSA_N, OFFSET_FIELD_ELEMENT, buf, off, LENGTH_FIELD_ELEMENT);
        // 1/a = a^(p-2) mod p
        buf[lastOff]-=2;
        rsaInverseN.setExponent(buf, off, LENGTH_FIELD_ELEMENT);

        rsaInverseFP.setModulus(RSA_FP, (short)0, (short)RSA_FP.length);
        Util.arrayCopyNonAtomic(RSA_FP, OFFSET_FIELD_ELEMENT, buf, off, LENGTH_FIELD_ELEMENT);
        // 1/a = a^(p-2) mod p
        buf[lastOff]-=2;
        rsaInverseFP.setExponent(buf, off, LENGTH_FIELD_ELEMENT);

        heap.free(LENGTH_FIELD_ELEMENT);
    }
    /**
     * Exponentiates a number with a short exponent (like 3 or -1) modulo field prime P
     * 
     * @param a        - buffer containing a number to exponentiate
     * @param aOff     - offset of the buffer
     * @param exponent - short exponent value
     * @param out      - output buffer to write result to
     * @param outOff   - offset of the output buffer
     */
    static public short powShortModFP(
                    byte[] a, short aOff,
                    short exponent,
                    byte[] out, short outOff)
    {
        return powShortMod(a, aOff, exponent, rsaModFP, RSA_FP, OFFSET_FIELD_ELEMENT, out, outOff);
    }
    /**
     * Exponentiates a number modulo field prime P
     * 
     * @param a      - buffer containing a number to exponentiate
     * @param aOff   - offset of the number
     * @param exp    - buffer with the exponent
     * @param expOff - offset of the exponent
     * @param out    - output buffer
     * @param outOff - offset of the output buffer
     * @return number of bytes written to the output buffer
     */
    static public short powModFP(
                    byte[] a, short aOff,
                    byte[] exp, short expOff, 
                    byte[] out, short outOff)
    {
        return powMod(a, aOff, exp, expOff, rsaModFP, out, outOff);
    }
    /**
     * Exponentiates a number with a short exponent (like 3 or -1) modulo curve order N.
     * 
     * @param a        - buffer containing a number to exponentiate
     * @param aOff     - offset of the number
     * @param exponent - short exponent value
     * @param out      - output buffer
     * @param outOff   - offset of the output buffer
     * @return number of bytes written to the output buffer
     */
    static public short powShortModN(
                    byte[] a, short aOff,
                    short exponent,
                    byte[] out, short outOff)
    {
        return powShortMod(a, aOff, exponent, rsaModN, RSA_N, OFFSET_FIELD_ELEMENT, out, outOff);
    }
    /**
     * Exponentiates a number modulo curve order N.
     * 
     * @param a      - buffer containing a number to exponentiate
     * @param aOff   - offset of the number
     * @param exp    - buffer with the exponent
     * @param expOff - offset of the exponent
     * @param out    - output buffer
     * @param outOff - offset of the output buffer
     * @return number of bytes written to the output buffer
     */
    static public short powModN(
                    byte[] a, short aOff,
                    byte[] exp, short expOff, 
                    byte[] out, short outOff)
    {
        return powMod(a, aOff, exp, expOff, rsaModN, out, outOff);
    }
    /**
     * Exponentiates a number with a short exponent modulo rsaKey.Modulus
     * 
     * @param a      - buffer with the number to exponentiate
     * @param aOff   - offset of the number
     * @param exp    - buffer with the exponent
     * @param expOff - offset of the exponent
     * @param rsaKey - RSAPublicKey containing modulo number
     * @param mod    - buffer with the modulo, should contain the same number as Modulus in rsaKey
     * @param modOff - offset in the modulo buffer
     * @param out    - output buffer
     * @param outOff - output offset
     */
    static private short powShortMod(
                    byte[] a, short aOff,
                    short exponent,
                    RSAPublicKey rsaKey,
                    byte[] mod, short modOff,
                    byte[] out, short outOff)
    {
        short len = LENGTH_FIELD_ELEMENT;
        short off = heap.allocate(len);
        byte[] buf = heap.buffer;
        // set 32-byte exponent
        if(exponent > 0){ // positive
            Util.setShort(buf, (short)(off+LENGTH_FIELD_ELEMENT-2), exponent);
        }else{ // negative
            exponent--; // n^(p-1)=1
            Util.setShort(buf, (short)(off+LENGTH_FIELD_ELEMENT-2), (short)(-exponent));
            subtract(mod, modOff, buf, off, buf, off);
        }
        short outLen = powMod(a, aOff, buf, off, rsaKey, out, outOff);
        heap.free(len);
        return outLen;
    }
    /**
     * Exponentiates the number with parameters 
     * (exp and modulus) defined in rsaKey
     * @param a      - buffer with the number
     * @param aOff   - offset of the number
     * @param rsaKey - RSAPublicKey storing modulo and exponent
     * @param out    - output buffer
     * @param outOff - output offset
     * @return number of bytes written to the buffer
     */
    static private short expMod(
                    byte[] a, short aOff,
                    RSAPublicKey rsaKey,
                    byte[] out, short outOff)
    {
        short len = LENGTH_RSA_KEY;
        short off = heap.allocate(len);
        byte[] buf = heap.buffer;

        short elementOff = (short)(off+OFFSET_FIELD_ELEMENT);
        Util.arrayCopyNonAtomic(a, aOff, buf, elementOff, LENGTH_FIELD_ELEMENT);
        rsaCipher.init(rsaKey, Cipher.MODE_ENCRYPT);
        rsaCipher.doFinal(buf, off, LENGTH_RSA_KEY, buf, off);
        Util.arrayCopyNonAtomic(buf, elementOff, out, outOff, LENGTH_FIELD_ELEMENT);
        heap.free(len);
        return LENGTH_FIELD_ELEMENT;
    }
    /**
     * Exponentiates a number modulo rsaKey.Modulus
     * 
     * @param a      - buffer with the number to exponentiate
     * @param aOff   - offset of the number
     * @param exp    - buffer with the exponent
     * @param expOff - offset of the exponent
     * @param rsaKey - RSAPublicKey containing modulo number
     * @param out    - output buffer
     * @param outOff - output offset
     * @return number of bytes written to the output buffer (32)
     */
    static private short powMod(
                    byte[] a, short aOff,
                    byte[] exp, short expOff,
                    RSAPublicKey rsaKey,
                    byte[] out, short outOff)
    {
        rsaKey.setExponent(exp, expOff, LENGTH_FIELD_ELEMENT);
        return expMod(a, aOff, rsaKey, out, outOff);
    }
    /**
     * Squares a number modulo P
     * @param a      - buffer with the number
     * @param aOff   - offset of the number
     * @param out    - output buffer
     * @param outOff - output offset
     * @return number of bytes written to the buffer (32)
     */
    static public short squareFP(
                    byte[] a, short aOff,
                    byte[] out, short outOff)
    {
        return expMod(a, aOff, rsaSqaureFP, out, outOff);
    }
    /**
     * Cubes a number modulo P (a^3 mod P)
     * @param a      - buffer with the number
     * @param aOff   - offset of the number
     * @param out    - output buffer
     * @param outOff - output offset
     * @return number of bytes written to the buffer (32)
     */
    static public short cubeFP(
                    byte[] a, short aOff,
                    byte[] out, short outOff)
    {
        return expMod(a, aOff, rsaCubeFP, out, outOff);
    }
    /**
     * Square root of the number modulo P
     * @param a      - buffer with the number
     * @param aOff   - offset of the number
     * @param out    - output buffer
     * @param outOff - output offset
     * @return number of bytes written to the buffer (32)
     */
    static public short rootFP(
                    byte[] a, short aOff,
                    byte[] out, short outOff)
    {
        return expMod(a, aOff, rsaRootFP, out, outOff);
    }
    /**
     * Inverse the number modulo P
     * @param a      - buffer with the number
     * @param aOff   - offset of the number
     * @param out    - output buffer
     * @param outOff - output offset
     * @return number of bytes written to the buffer (32)
     */
    static public short inverseFP(
                    byte[] a, short aOff,
                    byte[] out, short outOff)
    {
        return expMod(a, aOff, rsaInverseFP, out, outOff);
    }
    /**
     * Inverse the number modulo N
     * @param a      - buffer with the number
     * @param aOff   - offset of the number
     * @param out    - output buffer
     * @param outOff - output offset
     * @return number of bytes written to the buffer (32)
     */
    static public short inverseN(
                    byte[] a, short aOff,
                    byte[] out, short outOff)
    {
        return expMod(a, aOff, rsaInverseN, out, outOff);
    }
    /**
     * Generates a random number up to max value.
     * Max value should be large enough (like curve order or field prime) 
     * as we are just trying over and over until we get correct number.
     * 
     * @param max    - buffer with max value
     * @param maxOff - offset in the buffer with max value
     * @param out    - buffer to generate random element to
     * @param outOff - offset in the output buffer
     * @return number of bytes written to the output buffer (32)
     */
    static public short getRandomElement(
                    byte[] max, short maxOff,
                    byte[] out, short outOff)
    {
        Crypto.random.generateData(out, outOff, LENGTH_FIELD_ELEMENT);
        while(isGreaterOrEqual(out, outOff, max, maxOff) > 0){
            Crypto.random.generateData(out, outOff, LENGTH_FIELD_ELEMENT);
        }
        return LENGTH_FIELD_ELEMENT;
    }
    /**
     * Constant time modulo addition modulo field prime P. 
     * <p>
     * Arguments should be 32-bytes long. Can tweak in place.
     * 
     * @param a      - buffer with the first number
     * @param aOff   - offset of the first number
     * @param b      - buffer with the second number
     * @param bOff   - offset of the second number
     * @param out    - output buffer
     * @param outOff - offset in the output buffer
     * @return number of bytes written to the output buffer
     */
    static public short addModFP(
                    byte[] a,     short aOff, 
                    byte[] b,     short bOff, 
                    byte[] out,   short outOff) 
    {
        return addMod(a, aOff, b, bOff, RSA_FP, OFFSET_FIELD_ELEMENT, out, outOff);
    }
    /**
     * Constant time modulo addition modulo curve order N. 
     * <p>
     * Arguments should be 32-bytes long. Can tweak in place.
     * 
     * @param a      - buffer with the first number
     * @param aOff   - offset of the first number
     * @param b      - buffer with the second number
     * @param bOff   - offset of the second number
     * @param out    - output buffer
     * @param outOff - offset in the output buffer
     * @return number of bytes written to the output buffer
     */
    static public short addModN(
                    byte[] a,     short aOff, 
                    byte[] b,     short bOff, 
                    byte[] out,   short outOff) 
    {
        return addMod(a, aOff, b, bOff, RSA_N, OFFSET_FIELD_ELEMENT, out, outOff);
    }
    /**
     * Constant time modulo addition. 
     * <p>
     * Arguments should be 32-bytes long. Can tweak in place.
     * 
     * @param a      - buffer with the first number
     * @param aOff   - offset of the first number
     * @param b      - buffer with the second number
     * @param bOff   - offset of the second number
     * @param mod    - buffer with the modulus
     * @param modOff - offset of the modulus
     * @param out    - output buffer
     * @param outOff - offset in the output buffer
     * @return number of bytes written to the output buffer
     */
    static public short addMod(
                    byte[] a,     short aOff, 
                    byte[] b,     short bOff, 
                    byte[] mod,   short modOff,
                    byte[] out,   short outOff) 
    {
        short len = LENGTH_FIELD_ELEMENT;
        short off = heap.allocate(len);
        byte[] buf = heap.buffer;
        // addition with carry
        short carry = add(a, aOff, b, bOff, buf, off);
        // carry will be 1 only if we got it from addition or
        // if result is larger than modulo
        carry += isGreaterOrEqual(buf, off, mod, modOff);
        // subtract in any case and store result in output buffer
        // if carry is 0, subtraction will be skipped and it is just copy
        subtractConditional(buf, off, mod, modOff, out, outOff, carry);
        heap.free(len);
        return LENGTH_FIELD_ELEMENT;
    }
    /**
     * Constant time subtraction modulo field prime P. 
     * <p>
     * Arguments should be 32-bytes long. Can tweak in place.
     * 
     * @param a      - buffer with the first number
     * @param aOff   - offset of the first number
     * @param b      - buffer with the number to subtract
     * @param bOff   - offset of the second number
     * @param out    - output buffer
     * @param outOff - offset in the output buffer
     * @return number of bytes written to the output buffer
     * @throws ISOException if b is larger than mod.
     */
    static public short subtractModFP(
                    byte[] a,     short aOff, 
                    byte[] b,     short bOff, 
                    byte[] out,   short outOff) throws ISOException
    {
        return subtractMod(a, aOff, b, bOff, RSA_FP, OFFSET_FIELD_ELEMENT, out, outOff);
    }
    /**
     * Constant time subtraction modulo curve order N. 
     * <p>
     * Arguments should be 32-bytes long. Can tweak in place.
     * 
     * @param a      - buffer with the first number
     * @param aOff   - offset of the first number
     * @param b      - buffer with the number to subtract
     * @param bOff   - offset of the second number
     * @param out    - output buffer
     * @param outOff - offset in the output buffer
     * @return number of bytes written to the output buffer
     * @throws ISOException if b is larger than mod.
     */
    static public short subtractModN(
                    byte[] a,     short aOff, 
                    byte[] b,     short bOff, 
                    byte[] out,   short outOff) throws ISOException
    {
        return subtractMod(a, aOff, b, bOff, RSA_N, OFFSET_FIELD_ELEMENT, out, outOff);
    }
    /**
     * Constant time modulo subtraction. 
     * <p>
     * Arguments should be 32-bytes long. Can tweak in place.
     * 
     * @param a      - buffer with the first number
     * @param aOff   - offset of the first number
     * @param b      - buffer with the number to subtract
     * @param bOff   - offset of the second number
     * @param mod    - buffer with the modulus
     * @param modOff - offset of the modulus
     * @param out    - output buffer
     * @param outOff - offset in the output buffer
     * @return number of bytes written to the output buffer
     * @throws ISOException if b is larger than mod.
     */
    static public short subtractMod(
                    byte[] a,     short aOff, 
                    byte[] b,     short bOff, 
                    byte[] mod,   short modOff,
                    byte[] out,   short outOff) throws ISOException
    {
        short len = LENGTH_FIELD_ELEMENT;
        short off = heap.allocate(len);
        byte[] buf = heap.buffer;
        // get mod-b
        short carry = subtract(mod, modOff, b, bOff, buf, off);
        if(carry!=(short)0){
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        // add modulo: a+(mod-b)
        addMod(buf, off, a, aOff, mod, modOff, out, outOff);
        heap.free(len);
        return LENGTH_FIELD_ELEMENT;
    }
    /**
     * Constant time comparison of two 32-byte numbers.
     * <p>
     * Result is 1 if {@code a >= b}, 0 otherwise
     * 
     * @param a    - buffer with the number a
     * @param aOff - offset of the number a
     * @param b    - buffer with the number b
     * @param bOff - offset of the number b
     * @return 1 if {@code a >= b}, 0 otherwise
     */
    static public short isGreaterOrEqual(
                    byte[] a, short aOff,
                    byte[] b, short bOff)
    {
        // if a is smaller than b, a-b will be negative
        // and we will get carry of -1
        short carry = 0;
        for(short i=(short)(LENGTH_FIELD_ELEMENT-1); i>=0; i--){
            carry = (short)((a[(short)(aOff+i)]&0xFF)-(b[(short)(bOff+i)]&0xFF)+carry);
            carry = (short)(carry>>8);
        }
        return (short)(1+carry);
    }
    /**
     * Adds two 32-byte numbers, and writes result to the output buffer. Returns carry.
     * 
     * @param a      - buffer with the first number
     * @param aOff   - offset of the first number
     * @param b      - buffer with the second number
     * @param bOff   - offset of the second number
     * @param out    - output buffer
     * @param outOff - output offset
     * @return carry that is 1 if the result didn't fit in 32-bytes, 0 otherwise.
     */
    static public short add(
                    byte[] a, short aOff,
                    byte[] b, short bOff,
                    byte[] out, short outOff)
    {
        // allocate memory for temporary result
        short len = LENGTH_FIELD_ELEMENT;
        short off = heap.allocate(len);
        byte[] buf = heap.buffer;
        // add
        short carry = 0;
        for(short i=(short)(LENGTH_FIELD_ELEMENT-1); i>=0; i--){
            carry = (short)((short)(a[(short)(aOff+i)]&0xFF)+(short)(b[(short)(bOff+i)]&0xFF)+carry);
            buf[(short)(off+i)] = (byte)carry;
            carry = (short)(carry>>8);
        }
        // copy result to the output buffer
        Util.arrayCopyNonAtomic(buf, off, out, outOff, LENGTH_FIELD_ELEMENT);
        heap.free(len);
        return carry;
    }
    /**
     * Subtracts two 32-byte numbers, returns carry.
     * 
     * @param a          - buffer with the first number
     * @param aOff       - offset of the first number
     * @param b          - buffer with the number to subtract
     * @param bOff       - offset of the buffer
     * @param out        - output buffer to write result to
     * @param outOff     - offset of the output buffer
     * @return carry that is 0 if result is non-negative, -1 if result is negative
     */
    static public short subtract(
                    byte[] a, short aOff, 
                    byte[] b, short bOff,
                    byte[] out, short outOff)
    {
        return subtractConditional(a, aOff, b, bOff, out, outOff, (short)1);
    }
    /**
     * Subtracts (or not) two 32-byte numbers, returns carry.
     * <p>
     * Multiplier should be either 1 or 0. 
     * If multiplier is 1 subtraction happens as usual, 
     * if 0 - second argument is multiplied by 0 that effectively makes
     * conditional subtraction constant-time.
     * 
     * @param a          - buffer with the first number
     * @param aOff       - offset of the first number
     * @param b          - buffer with the number to subtract
     * @param bOff       - offset of the buffer
     * @param out        - output buffer to write result to
     * @param outOff     - offset of the output buffer
     * @param multiplier - set to 1 to subtract, set to 0 to simulate subtraction
     * @return carry that is 0 if result is non-negative, -1 if result is negative
     */
    static public short subtractConditional(
                    byte[] a, short aOff, 
                    byte[] b, short bOff,
                    byte[] out, short outOff, 
                    short multiplier)
    {
        // allocate memory for temporary result
        short len = LENGTH_FIELD_ELEMENT;
        short off = heap.allocate(len);
        byte[] buf = heap.buffer;
        // subtract
        short carry = 0;
        for(short i=(short)(LENGTH_FIELD_ELEMENT-1); i>=0; i--){
            carry = (short)((a[(short)(aOff+i)]&0xFF)-(b[(short)(bOff+i)]&0xFF)*multiplier+carry);
            buf[(short)(off+i)] = (byte)carry;
            carry = (short)(carry>>8);
        }
        // copy result to the output buffer
        Util.arrayCopyNonAtomic(buf, off, out, outOff, LENGTH_FIELD_ELEMENT);
        heap.free(len);
        return carry;
    }
    // TODO: implement mulModFP & mulModN
    // hint: 4*a*b = (a+b)^2-(a-b)^2
}