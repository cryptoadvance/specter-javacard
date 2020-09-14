package toys;

import javacard.framework.*;
import javacard.security.*;

/**
 * Utility methods to work with the SECP256k1 curve.
 * <p> 
 * There is no need to create a new instance of this class, 
 * but you have to call Secp256k1.init(heap) method in the applet constructor.
 * TransientHeap instance is used to allocate memory when the class needs it.
 */
public class Secp256k1 {
    /** Field prime P */
    static final public byte[] SECP256K1_FP = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,(byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F
    };
    /** Parameter A from equation {@code y^2 = x^3 + A x + B} */
    static final public byte[] SECP256K1_A = {
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
    };
    /** Parameter B from equation {@code y^2 = x^3 + A x + B} */
    static final public byte[] SECP256K1_B = {
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x07
    };
    /** Generator point G in uncompressed form */
    static final public byte[] SECP256K1_G = {
        (byte)0x04,
        (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E,(byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,
        (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95,(byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,
        (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB,(byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,
        (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B,(byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,
        (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77,(byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,
        (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC,(byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,
        (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48,(byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,
        (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F,(byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8
    };
    /** Group order N of the curve */
    static final public byte[] SECP256K1_R = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
        (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6,(byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
        (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C,(byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41
    };

    static final public byte SECP256K1_K = (byte)0x01;

    static final public short SECP256K1_KEY_SIZE             = (short)256;

    static final public short LENGTH_PUBLIC_KEY_UNCOMPRESSED = (short)65;
    static final public short LENGTH_PUBLIC_KEY_COMPRESSED   = (short)33;
    static final public short LENGTH_PRIVATE_KEY             = (short)32;
    static final public short LENGTH_MESSAGE                 = (short)32;

    // constants from JavaCard 3.0.5
    static final private byte ALG_EC_SVDP_DH_PLAIN_XY = 6;
    static final private byte ALG_EC_PACE_GM          = 5;

    static private KeyAgreement  ecMult;
    static private KeyAgreement  ecMultX;
    static private KeyAgreement  ecAdd;
    static private Signature     sig;
    static private ECPrivateKey  tempPrivateKey;
    static private ECPublicKey   tempPublicKey;
    // this one is used for point addition - G changes to arbitrary points
    static private ECPrivateKey  tempPoint;
    static private TransientHeap heap;

    /**
     * Allocates objects needed by this class.
     * <p>
     * Must be invoked during the applet installation exactly 1 time.
     * @param hp - instance of the TransientHeap class for memory allocations
     */
    static public void init(TransientHeap hp)
    {
        heap = hp;
        ecMult = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
        ecMultX = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        // TODO: fails in the simulator, write implementation if not supported
        try {
            ecAdd = KeyAgreement.getInstance(ALG_EC_PACE_GM, false);
        } catch (Exception e) {
            // nothing here yet :(
        }
        sig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

        tempPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(tempPrivateKey);
        tempPoint = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(tempPoint);
        tempPublicKey = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(tempPublicKey);
        // set scalar of the tempPoint to 1
        short len = LENGTH_PRIVATE_KEY;
        short off = heap.allocate(len);
        byte[] buf = heap.buffer;
        buf[(short)(off+LENGTH_PRIVATE_KEY-1)] = (byte)0x01;
        tempPoint.setS(heap.buffer, off, LENGTH_PRIVATE_KEY);
        heap.free(len);
    }
    /**
     * Sets the SECP256k1 curve parameters to the given ECKey (public or private).
     *
     * @param key the key where the curve parameters must be set
     */
    static public void setCommonCurveParameters(ECKey key)
    {
        key.setA(SECP256K1_A, (short)0, (short)SECP256K1_A.length);
        key.setB(SECP256K1_B, (short)0, (short)SECP256K1_B.length);
        key.setFieldFP(SECP256K1_FP, (short)0, (short)SECP256K1_FP.length);
        key.setG(SECP256K1_G, (short)0, (short)SECP256K1_G.length);
        key.setR(SECP256K1_R, (short)0, (short)SECP256K1_R.length);
        key.setK(SECP256K1_K);
    }
    /**
     * Generate a new private-public keypair on Secp256k1 curve
     * @return KeyPair instance with curve parameters set to Secp256k1
     */
    static public KeyPair newKeyPair()
    {
        KeyPair kp = new KeyPair(KeyPair.ALG_EC_FP, SECP256K1_KEY_SIZE);
        setCommonCurveParameters((ECPrivateKey)kp.getPrivate());
        setCommonCurveParameters((ECPublicKey)kp.getPublic());
        return kp;
    }
    /**
     * Checks whether the point is in compressed or uncompressed form.
     * <p>
     * Also checks if point buffer is large enough and serialization format is correct.
     * 
     * @param point    - buffer containting a point
     * @param pointOff - offset of the point
     * @return true if the point is compressed, false if not
     * @throws ISOException if serialization format is invalid
     */
    static public boolean isCompressed(byte[] point, short pointOff) throws ISOException
    {
        if(point[pointOff]>(byte)0x04 || point[pointOff]<(byte)0x02){
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        boolean compressed = (point[pointOff]!=(byte)0x04);
        short expectedLen = (compressed) ? LENGTH_PUBLIC_KEY_COMPRESSED : LENGTH_PUBLIC_KEY_UNCOMPRESSED;
        // check length
        if((short)(point.length-expectedLen-pointOff)<(short)0){
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        return compressed;
    }
    /**
     * Check if the point is on the curve. Can be in compressed or uncompressed form.
     * 
     * @param point - buffer containing a point in (un)compressed form
     * @param pOff  - offset in the buffer
     * @return true if point is on the curve, false otherwise
     * @throws ISOException if serialization format is wrong.
     */
    static public boolean pointVerify(byte[] point, short pOff) throws ISOException{
        // are we working with compressed or uncompressed point?
        boolean compressed = isCompressed(point,pOff);
        // allocate memory for two field elements
        short len = (short)(2*FiniteField.LENGTH_FIELD_ELEMENT);
        byte[] buf = heap.buffer;
        short off1 = heap.allocate(len);
        short off2 = (short)(off1 + FiniteField.LENGTH_FIELD_ELEMENT);
        short pOffX = (short)(pOff+1);
        short pOffY = (short)(pOffX+FiniteField.LENGTH_FIELD_ELEMENT);
        // first element is x^3
        FiniteField.cubeFP(point, pOffX, buf, off1);
        // second element is 7
        buf[(short)(off2+FiniteField.LENGTH_FIELD_ELEMENT-1)]=0x07;
        // first element is x^3+7 now
        FiniteField.addMod(buf, off1, buf, off2, SECP256K1_FP, (short)0, buf, off1);
        if(!compressed){
            // if we work with uncompressed - just copy Y to second element
            Util.arrayCopyNonAtomic(point, pOffY, buf, off2, FiniteField.LENGTH_FIELD_ELEMENT);
        }else{
            // otherwise - do sqrt
            // second element is a square root: sqrt(x^3+7)
            FiniteField.rootFP(buf, off1, buf, off2);
        }
        // calculate y^2 again and put it to the 2nd element
        FiniteField.squareFP(buf, off2, buf, off2);
        // if they are the same - point is on the curve
        boolean isValid = (Util.arrayCompare(buf, off1, buf, off2, FiniteField.LENGTH_FIELD_ELEMENT)==(byte)0);
        heap.free(len);
        return isValid;
    }
    /**
     * Uncompress compressed public key. Doesn't check if it's on the curve.
     * @param point  - buffer containing compressed public key 
     * @param pOff   - offset of the point buffer
     * @param out    - output buffer to write uncompressed pubkey to
     * @param outOff - offset in the output buffer
     * @return number of bytes written to the buffer (65)
     */
    static public short uncompress(
                    byte[] point, short pOff,
                    byte[] out, short outOff)
    {
        // check if it's already uncompressed
        if(!isCompressed(point, pOff)){
            Util.arrayCopyNonAtomic(point, pOff, out, outOff, LENGTH_PUBLIC_KEY_UNCOMPRESSED);
            return LENGTH_PUBLIC_KEY_UNCOMPRESSED;
        }
        short pOffX = (short)(pOff+1);
        // allocate space for three field elements
        short len = (short)(2*FiniteField.LENGTH_FIELD_ELEMENT);
        // offset of the first RAM element
        short off1 = heap.allocate(len);
        // offset of the second RAM element
        short off2 = (short)(off1+FiniteField.LENGTH_FIELD_ELEMENT);
        byte[] buf = heap.buffer;
        // first element is x^3
        FiniteField.cubeFP(point, pOffX, buf, off1);
        // second element is 7
        buf[(short)(off2+FiniteField.LENGTH_FIELD_ELEMENT-1)]=0x07;
        // first element is x^3+7 now
        FiniteField.addMod(buf, off1, buf, off2, SECP256K1_FP, (short)0, buf, off1);
        // second element is a square root: sqrt(x^3+7)
        FiniteField.rootFP(buf, off1, buf, off2);
        // check sign and negate if necessary
        if((point[pOff]-0x02) != (buf[(short)(off2+FiniteField.LENGTH_FIELD_ELEMENT-1)]&0x01)){
            FiniteField.subtract(SECP256K1_FP, (short)0, buf, off2, buf, off2);
        }
        // copy x to the first element
        Util.arrayCopyNonAtomic(point, (short)(pOff+1), buf, off1, FiniteField.LENGTH_FIELD_ELEMENT);
        // set first byte
        out[outOff] = (byte)0x04;
        // copy x and y to the output
        Util.arrayCopyNonAtomic(buf, off1, out, (short)(outOff+1), (short)(2*FiniteField.LENGTH_FIELD_ELEMENT));
        heap.free(len);
        return LENGTH_PUBLIC_KEY_UNCOMPRESSED;
    }
    /**
     * Compress uncompressed public key. Doesn't check if the point is on the curve.
     * @param point  - buffer containing uncompressed public key 
     * @param pOff   - offset of the point buffer
     * @param out    - output buffer to write compressed pubkey to
     * @param outOff - offset in the output buffer
     * @return number of bytes written to the buffer (33)
     */
    static public short compress(
                    byte[] point, short pOff,
                    byte[] out, short outOff)
    {
        // check if already compressed
        if(isCompressed(point, pOff)){
            Util.arrayCopyNonAtomic(point, pOff, out, outOff, LENGTH_PUBLIC_KEY_COMPRESSED);
            return LENGTH_PUBLIC_KEY_COMPRESSED;
        }
        short len = LENGTH_PUBLIC_KEY_COMPRESSED;
        short off = heap.allocate(len);

        heap.buffer[off] = (byte)(0x02+(point[(short)(pOff+64)]&0x01));
        // because maybe it's the same buffer...
        Util.arrayCopyNonAtomic(point, (short)(pOff+1), heap.buffer, (short)(off+1), (short)(LENGTH_PUBLIC_KEY_COMPRESSED-1));
        Util.arrayCopyNonAtomic(heap.buffer, off, out, outOff, LENGTH_PUBLIC_KEY_COMPRESSED);
        heap.free(len);
        return LENGTH_PUBLIC_KEY_COMPRESSED;
    }
    /**
     * Serialize ECPublicKey to the buffer
     * @param key        - ECPublicKey to serialize
     * @param compressed - flag to serialize in compressed (33 bytes) or uncompressed (65 bytes) form
     * @param out        - output buffer to serialize the key to
     * @param outOff     - offset in the buffer
     * @return number of bytes written to the buffer. 33 for compressed, 65 for uncompressed.
     */
    static public short serialize(
                    ECPublicKey key, boolean compressed, 
                    byte[] out, short outOff)
    {
        if(!compressed){
            return key.getW(out, outOff);
        }else{
            short len = LENGTH_PUBLIC_KEY_UNCOMPRESSED;
            short off = heap.allocate(len);
            byte[] buf = heap.buffer;
            key.getW(buf, off);
            short lenOut = compress(buf, off, out, outOff);
            heap.free(len);
            return lenOut;
        }
    }
    /**
     * Multiplies a scalar by a point and writes result to the output buffer. 
     * Output public key is uses the same serialization form as the input public key.
     *
     * @param privateKey  - ECPrivateKey instance with the private key
     * @param point       - buffer containing the point to multiply
     * @param pointOffset - offset of the point buffer
     * @param out         - output buffer to write result to
     * @param outOffset   - offset in the output buffer
     * @return number of bytes written to the output buffer
     */
    static public short pointMultiply(
                    ECPrivateKey privateKey, 
                    byte[] point, short pointOff, 
                    byte[] out, short outOff)
    {
        ecMult.init(privateKey);
        // check if compressed point is used or not
        if(!isCompressed(point, pointOff)){
            return ecMult.generateSecret(point, pointOff, LENGTH_PUBLIC_KEY_UNCOMPRESSED, out, outOff);
        }else{
            short len = LENGTH_PUBLIC_KEY_UNCOMPRESSED;
            short off = heap.allocate(len);
            short lenPoint = uncompress(point, pointOff, heap.buffer, off);
            ecMult.generateSecret(heap.buffer, off, lenPoint, heap.buffer, off);
            short lenOut = compress(heap.buffer, off, out, outOff);
            heap.free(len);
            return lenOut;
        }
    }
    /**
     * Multiplies a scalar by a point and writes result to the output buffer. 
     *
     * @param scalar      - buffer containing the private key
     * @param scalarOff   - offset in the scalar buffer
     * @param point       - buffer containing the point to multiply
     * @param pointOffset - offset of the point buffer
     * @param pointLen    - length of the point (should be 65)
     * @param out         - output buffer to write result to
     * @param outOffset   - offset in the output buffer
     * @return number of bytes written to the output buffer
     */
    static public short pointMultiply(
                    byte scalar[], short scalarOff,
                    byte[] point, short pointOff,
                    byte[] out, short outOff)
    {
        tempPrivateKey.setS(scalar, scalarOff, LENGTH_PRIVATE_KEY);
        return pointMultiply(tempPrivateKey, point, pointOff, out, outOff);
    }
    /**
     * Creates a public key from private key and writes it to output buffer.
     * 
     * @param privateKey - ECPrivateKey instance containing private key
     * @param compressed - a flag to serialize in compressed (33 bytes) or uncompressed form (65 bytes)
     * @param out        - output buffer serialize pubkey to
     * @param outOff     - offset in the output buffer
     * @return number of bytes written to the output buffer
     */
    static public short getPublicKey(
                    ECPrivateKey privateKey, boolean compressed,
                    byte[] out, short outOff)
    {
        if(compressed){
            short len = LENGTH_PUBLIC_KEY_UNCOMPRESSED;
            short off = heap.allocate(len);
            byte[] buf = heap.buffer;
            pointMultiply(privateKey, 
                        SECP256K1_G, (short)0, 
                        buf, off);
            short lenOut = compress(buf, off, out, outOff);
            heap.free(len);
            return lenOut;
        }else{
            return pointMultiply(privateKey, 
                        SECP256K1_G, (short)0,
                        out, outOff);
        }
    }
    /**
     * Creates a public key from private key and writes it to output buffer.
     * 
     * @param privkey    - buffer containing private key
     * @param privOff    - offset in the private key buffer
     * @param compressed - a flag to serialize in compressed (33 bytes) or uncompressed form (65 bytes)
     * @param out        - output buffer serialize pubkey to
     * @param outOff     - offset in the output buffer
     * @return number of bytes written to the output buffer
     */
    static public short getPublicKey(
                    byte[] privkey, short privOff,
                    boolean compressed,
                    byte[] out, short outOff)
    {
        tempPrivateKey.setS(privkey, privOff, LENGTH_PRIVATE_KEY);
        return getPublicKey(tempPrivateKey, compressed, out, outOff);
    }
    /**
     * Adds tweak*G to the point. Returs P+tweak*G.
     * <p>
     * If you want to add two points: P1 + P2
     * set tweak=1, tweak.G = P1, point = P2 -> you'll get it.
     * 
     * @param tweak  - ECPrivateKey instance with the private key
     * @param point  - point to add secret*G to
     * @param pOff   - offset of the point
     * @param pLen   - length of the point (should be 65)
     * @param out    - output buffer to write result to
     * @param outOff - output offset
     * @return number of bytes written to the output buffer
     */
    static public short tweakAdd(
                    ECPrivateKey tweak,
                    byte[] point, short pointOff,
                    byte[] out, short outOff)
    {
        // if add engine is not available
        if(ecAdd==null){
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        ecAdd.init(tweak);
        if(!isCompressed(point, pointOff)){
            return ecAdd.generateSecret(point, pointOff, LENGTH_PUBLIC_KEY_UNCOMPRESSED, out, outOff);
        }else{
            short len = LENGTH_PUBLIC_KEY_UNCOMPRESSED;
            short off = heap.allocate(len);
            byte[] buf = heap.buffer;
            short pointLen = uncompress(point, pointOff, buf, off);
            ecAdd.generateSecret(buf, off, pointLen, buf, off);
            short lenOut = compress(buf, off, out, outOff);
            heap.free(len);
            return lenOut;
        }
    }
    /**
     * Adds tweak*G to the point. Returs P+tweak*G.
     * 
     * @param tweak    - buffer with a tweak scalar
     * @param tweakOff - offset in the tweak buffer
     * @param point    - point to add secret*G to
     * @param pOff     - offset of the point
     * @param out      - output buffer to write result to
     * @param outOff   - output offset
     * @return number of bytes written to the output buffer
     */
    static public short tweakAdd(
                    byte[] tweak, short tweakOff,
                    byte[] point, short pOff,
                    byte[] out, short outOff)
    {
        tempPrivateKey.setS(tweak, tweakOff, LENGTH_PRIVATE_KEY);
        return tweakAdd(tempPrivateKey, point, pOff, out, outOff);
    }
    /**
     * Adds two points, writes P1+P2 to the output.
     * <p>
     * Output point will be serialized in the same form as point2
     * 
     * @param point1     - buffer containing the first point (compressed or not)
     * @param pOff1      - offset in the first buffer
     * @param point2     - buffer containing the second point (compressed or not, used for output)
     * @param pOff2      - offset in the second buffer
     * @param out        - output buffer to write result
     * @param outOff     - offset of the output buffer
     * @return number of bytes written to the output buffer
     */
    static public short pointAdd(
                    byte[] point1, short pOff1,
                    byte[] point2, short pOff2,
                    byte[] out, short outOff)
    {
        // set G to point1
        if(isCompressed(point1, pOff1)){
            short len = LENGTH_PUBLIC_KEY_UNCOMPRESSED;
            short off = heap.allocate(len);
            byte[] buf = heap.buffer;
            uncompress(point1, pOff1, buf, off);
            tempPoint.setG(buf, off, LENGTH_PUBLIC_KEY_UNCOMPRESSED);
            heap.free(len);
        }else{
            tempPoint.setG(point1, pOff1, LENGTH_PUBLIC_KEY_UNCOMPRESSED);
        }
        short outLen = tweakAdd(tempPoint, point2, pOff2, out, outOff);
        return outLen;
    }
    /**
     * Preforms ECDH key agreement. 
     * Writes x-coordinate of the resulting point to the output buffer.
     *
     * @param privateKey  - ECPrivateKey instance
     * @param point       - buffer with a point to multiply in uncompressed form {@code 04<x><y>} (65 bytes)
     * @param pointOffset - offset of the point
     * @param pointLen    - length of the point - should be 65
     * @param out         - output buffer to write x-coordinate of the product to
     * @param outOffset   - offset in the output buffer
     * @return number of bytes written in the output buffer (should be 32)
     * @throws ISOException if the point is not on the curve.
     */
    static public short ecdh(
                    ECPrivateKey privateKey, 
                    byte[] point, short pointOffset, 
                    byte[] out, short outOffset) throws ISOException
    {
        // ecMultX on the card verifies that the point is on the curve 
        // and raises exception if it's not,
        // so we don't need to do it ourselves.
        // Simulator doesn't verify it, meh...
        ecMultX.init(privateKey);
        if(isCompressed(point, pointOffset)){
            short len = LENGTH_PUBLIC_KEY_UNCOMPRESSED;
            short off = heap.allocate(len);
            byte[] buf = heap.buffer;
            short pLen = uncompress(point, pointOffset, buf, off);
            short outLen = ecMultX.generateSecret(buf, off, pLen, out, outOffset);
            heap.free(len);
            return outLen;
        }else{
            return ecMultX.generateSecret(point, pointOffset, LENGTH_PUBLIC_KEY_UNCOMPRESSED, out, outOffset);
        }
    }
    /**
     * Preforms ECDH key agreement. 
     * Writes x-coordinate of the resulting point to the output buffer.
     *
     * @param scalar      - buffer with a scalar ( private key )
     * @param scalarOff   - offset in the scalar buffer
     * @param point       - buffer with a point to multiply in uncompressed form {@code 04<x><y>} (65 bytes)
     * @param pointOffset - offset of the point
     * @param pointLen    - length of the point - should be 65
     * @param out         - output buffer to write x-coordinate of the product to
     * @param outOffset   - offset in the output buffer
     * @return number of bytes written in the output buffer (should be 32)
     * @throws ISOException if the point is not on the curve.
     */
    static public short ecdh(
                    byte[] scalar, short scalarOff, 
                    byte[] point, short pointOffset, 
                    byte[] out, short outOffset) throws ISOException
    {
        tempPrivateKey.setS(scalar, scalarOff, LENGTH_PRIVATE_KEY);
        return ecdh(tempPrivateKey, point, pointOffset, out, outOffset);
    }
    /**
     * Signs the message with the private key. The message should be already hashed.
     * @param privateKey - private key object to sign with
     * @param msg        - buffer with a 32-byte hash to sign
     * @param msgOffset  - offset in the msg buffer
     * @param out        - output buffer to write the signature to
     * @param outOffset  - offset in the output buffer
     * @return number of bytes written to the output buffer
     */
    static public short sign(
                    ECPrivateKey privateKey, 
                    byte[] msg, short msgOffset,
                    byte[] out, short outOffset)
    {
        sig.init(privateKey, Signature.MODE_SIGN);
        short len = sig.signPreComputedHash(msg, msgOffset, LENGTH_MESSAGE, out, outOffset);
        return (short)(len+setLowS(out, outOffset));
    }
    /**
     * Signs the message with the private key. The message should be already hashed.
     * @param scalar     - buffer with a scalar ( private key )
     * @param scalarOff  - offset in the scalar buffer
     * @param msg        - buffer with a 32-byte hash to sign
     * @param msgOffset  - offset in the msg buffer
     * @param out        - output buffer to write the signature to
     * @param outOffset  - offset in the output buffer
     * @return number of bytes written to the output buffer
     */
    static public short sign(
                    byte[] scalar, short scalarOff, 
                    byte[] msg, short msgOffset,
                    byte[] out, short outOffset)
    {
        tempPrivateKey.setS(scalar, scalarOff, LENGTH_PRIVATE_KEY);
        return sign(tempPrivateKey, msg, msgOffset, out, outOffset);
    }
    /**
     * Verifies a signature against the message and the public key
     * @param pubkey - buffer with the pubkey serialized in uncompressed form
     * @param pubkeyOff - offset of the pubkey buffer
     * @param msgBuf - buffer with the message to verify (will be sha256-ed)
     * @param msgOff - offset in the message buffer
     * @param sigBuf - buffer with DER-serialized signature
     * @param sigOff - offset of the signature buffer
     * @param sigLen - length of the signature in the buffer
     * @return true if the signature is valid, false otherwise
     */
    static public boolean verifyPreimage(
                    byte[] pubkey, short pubkeyOff,
                    byte[] msgBuf, short msgOff, short msgLen,
                    byte[] sigBuf, short sigOff, short sigLen)
    {
        tempPublicKey.setW(pubkey, pubkeyOff, LENGTH_PUBLIC_KEY_UNCOMPRESSED);
        return verifyPreimage(tempPublicKey, msgBuf, msgOff, msgLen, sigBuf, sigOff, sigLen);
    }
    /**
     * Verifies a signature against the message and the public key
     * @param pubkey - Instance of the ECPublicKey
     * @param msgBuf - buffer with the message to verify (will be sha256-ed)
     * @param msgOff - offset in the message buffer
     * @param sigBuf - buffer with DER-serialized signature
     * @param sigOff - offset of the signature buffer
     * @param sigLen - length of the signature in the buffer
     * @return true if the signature is valid, false otherwise
     */
    static public boolean verifyPreimage(
                    ECPublicKey publicKey,
                    byte[] msgBuf, short msgOff, short msgLen,
                    byte[] sigBuf, short sigOff, short sigLen)
    {
        sig.init(publicKey, Signature.MODE_VERIFY);
        return sig.verify(msgBuf, msgOff, msgLen,
                          sigBuf, sigOff, sigLen);
    }
    /**
     * Generates a random 32-byte secret up to the group order. It is always a valid private key.
     * @param buf - buffer where to put the secret
     * @param off - offset in the buffer
     * @return number of bytes written to the buffer (32)
     */
    static public short generateRandomSecret(byte[] buf, short off){
        return FiniteField.getRandomElement(SECP256K1_R, (short)0, buf, off);
    }
    /**
     * Fixes S to lower half according to BIP-62. Changes it in place and returns difference in length.
     * <p>
     * https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#low-s-values-in-signatures
     * 
     * @param sig    - buffer with a signature to fix
     * @param sigOff - offset of the signature in the buffer
     * @return difference in signature length comparing to initial (not positive)
     */
    static public short setLowS(byte[] sig, short sigOff){
        short sLenOff = (short)(sigOff+5+sig[(short)(sigOff+3)]);
        short sLen = sig[sLenOff];
        if(sLen < (short)32){ // no need to do anything for sure
            return (short)0;
        }
        // otherwise check
        short len = (short)32;
        short off = heap.allocate(len);
        byte[] buf = heap.buffer;
        short numZeroes = (short)0;
        short delta = (short)0;
        if(sLen == (short)33){ // need to subtract for sure
            FiniteField.subtract(SECP256K1_R, (short)0, sig, (short)(sLenOff+2), buf, off);
            delta--;
        }else{ // len = 32
            FiniteField.subtract(SECP256K1_R, (short)0, sig, (short)(sLenOff+1), buf, off);
        }
        // check if we need to replace it
        if(FiniteField.isGreaterOrEqual(sig, (short)(sLenOff+1+sLen-32), buf, off) > 0){
            // find number of zeroes
            while(numZeroes<32){
                if(buf[(short)(off+numZeroes)]!=(byte)0x00){
                    // if high bit is set - we need zero
                    // hack - in Java bytes are signed...
                    if(buf[(short)(off+numZeroes)]<0){
                        numZeroes--;
                    }
                    break;
                }
                numZeroes++;
            }
            delta -= numZeroes;
            Util.arrayCopyNonAtomic(buf, (short)(off+numZeroes), sig, (short)(sLenOff+1), (short)(32-numZeroes));
            // if length have changed
            if(delta < 0){
                sig[(short)(sigOff+1)]+=delta;
                sig[sLenOff]+=delta;
            }
        }
        heap.free(len);
        return delta;
    }
}
