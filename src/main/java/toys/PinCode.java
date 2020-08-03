package toys;

import javacard.framework.*;

/**
 * A class that extends OwnerPIN to make it more resistant
 * against timing attacks.
 * <p>
 * In the constructor the class instance generates a unique secret
 * that is used to calculate HMAC_SHA256(secret,pin).
 * Result of hmac is used as a PIN in the parent class.
 * <p>
 * As internal secret is not known to anyone the timing difference
 * when verifying PIN codes is unpredictable and significantly reduces
 * amount of information leaked to the attacker.
 */
public class PinCode extends OwnerPIN{
    static final private byte  LENGTH_PIN_HMAC = (byte)32;
    static final private short LENGTH_SECRET   = (short)32;
    private byte[] secret;
    private byte[] hmacResult;
    /**
     * Class constructor.
     * @param maxCounter - maximum number of tries before the PIN is locked
     * @param maxLen     - maximum length of the PIN code
     */
    public PinCode(byte maxCounter, byte maxLen){
        super(maxCounter, LENGTH_PIN_HMAC);
        secret = new byte[LENGTH_SECRET];
        Crypto.random.generateData(secret, (short)0, (short)secret.length);
        hmacResult = JCSystem.makeTransientByteArray(LENGTH_PIN_HMAC, JCSystem.CLEAR_ON_DESELECT);
    }
    public boolean check(byte[] buf, short off, byte len){
        Crypto.hmacSha256.init(secret, (short)0, (short)secret.length);
        short lenHmac = Crypto.hmacSha256.doFinal(buf, off, (short)len, hmacResult, (short)0);
        boolean result = super.check(hmacResult, (short)0, (byte)lenHmac);
        // empty array
        Util.arrayFillNonAtomic(hmacResult, (short)0, (short)hmacResult.length, (byte)0x00);
        return result;
    }
    public void update(byte[] buf, short off, byte len){
        Crypto.hmacSha256.init(secret, (short)0, (short)secret.length);
        short lenHmac = Crypto.hmacSha256.doFinal(buf, off, (short)len, hmacResult, (short)0);
        super.update(hmacResult, (short)0, (byte)lenHmac);
        // empty array
        Util.arrayFillNonAtomic(hmacResult, (short)0, (short)hmacResult.length, (byte)0x00);
    }
}