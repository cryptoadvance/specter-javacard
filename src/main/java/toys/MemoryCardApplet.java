package toys;

// import using java card API interface.
import javacard.framework.*;

/* 
 * Package: toys
 * Filename: MemoryCardApplet.java 
 * Class: MemoryCardApplet
 */
public class MemoryCardApplet extends SecureApplet{

    // Max storage
    protected static final short MAX_DATA_LENGTH         = (short)255;

    // commands transmitted over secure channel
    // 0x00 - 0x04 are reserved
    protected static final byte CMD_STORAGE             = (byte)0x05;
    // storage
    protected static final byte SUBCMD_STORAGE_GET      = (byte)0x00;
    protected static final byte SUBCMD_STORAGE_PUT      = (byte)0x01;

    protected DataEntry secretData;

    // Create an instance of the Applet subclass using its constructor, 
    // and to register the instance.
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        if(bArray!=null && bArray.length > 0){
            // the line below works on the card, but not in the simulator
            new MemoryCardApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);;
        }else{
            // keep the simulator happy and register without arguments
            new MemoryCardApplet().register();
        }
    }
    public MemoryCardApplet(){
        super();
        secretData = new DataEntry(MAX_DATA_LENGTH);
    }
    protected short processSecureMessage(byte[] buf, short len){
        if(buf[OFFSET_CMD] == CMD_STORAGE){
            return processStorageCommand(buf, len);
        }else{
            ISOException.throwIt(ERR_INVALID_CMD);
        }
        return 0;
    }
    protected short processStorageCommand(byte[] buf, short len){
        if(isLocked()){
            ISOException.throwIt(ERR_CARD_LOCKED);
        }
        byte subcmd = buf[OFFSET_SUBCMD];
        short lenOut = setResponseCode(RESPONSE_SUCCESS, buf);
        switch (subcmd){
            case SUBCMD_STORAGE_PUT:
                secretData.put(buf, OFFSET_SECURE_PAYLOAD, (short)(len-LENGTH_CMD_SUBCMD));
                lenOut += fillData(buf, OFFSET_SECURE_PAYLOAD);
                return lenOut;
            case SUBCMD_STORAGE_GET:
                lenOut += fillData(buf, OFFSET_SECURE_PAYLOAD);
                return lenOut;
            default:
                ISOException.throwIt(ERR_INVALID_SUBCMD);
        }
        return lenOut;
    }
    protected short fillData(byte[] buf, short off){
        Util.arrayCopyNonAtomic(secretData.get(), (short)0, buf, off, secretData.length());
        return secretData.length();
    }
}