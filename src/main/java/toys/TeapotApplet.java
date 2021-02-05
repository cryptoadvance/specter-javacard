package toys;

// import using java card API interface.
import javacard.framework.*;

/**
 * A simple applet that stores data up to 254 bytes on the card. 
 * <p>
 * It does not include any encryption or authentication, completely useless in production,
 * but it is very useful for debugging and testing. Like a simple Hello World.
 * <p>
 * Only two APDU commands are available for this class:
 * <ul>
 * <li>{@code B0A10000} - get data stored in the applet.
 * <li>{@code B0A20000<len><data>} - stores provided data in the applet, also returns stored data.
 */
public class TeapotApplet extends Applet{
    /** Class code for Teapot applet */
    protected static final byte CLA_TEAPOT               = (byte)0xB0;
    /** Instruction code to get data from the card */
    protected static final byte INS_GET                  = (byte)0xA1;
    /** Instruction code to save data on the card */
    protected static final byte INS_PUT                  = (byte)0xA2;
    /** Max storage capacity. We use 254 to fit in one APDU buffer. */
    protected static final short MAX_DATA_LENGTH         = (short)254;

    /** Data stored on the card, up to `MAX_DATA_LENGTH` in length */
    protected DataEntry data = null;

    /** 
     * Create an instance of the TeapotApplet using its constructor, 
     * and register the instance on the card.
     */ 
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        if(bArray!=null && bArray.length > 0){
            // the line below works on the card, but not in the simulator
            new TeapotApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
        }else{
            // keep the simulator happy and register without arguments
            new TeapotApplet().register();
        }
    }

    /**
     * Class constructor. Allocates memory for data storage and puts default data there.
     * Initially data stored on the card is a string "I am a teapot gimme some tea plz".
     */
    public TeapotApplet(){
        
        data = new DataEntry(MAX_DATA_LENGTH);
        byte[] defaultData = { 
            'I', ' ', 'a', 'm', ' ', 'a', ' ', 't', 
            'e', 'a', 'p', 'o', 't', ' ', 'g', 'i', 
            'm', 'm', 'e', ' ', 's', 'o', 'm', 'e', 
            ' ', 't', 'e', 'a', ' ', 'p', 'l', 'z' 
        };
        data.put(defaultData, (short)0, (short)defaultData.length);
    }
    /** 
     * Process the APDU command and send back the response.
     * @param apdu - APDU command to process. CLA should be 0xB0 (CLA_TEAPOT),
     * INS - 0xA1 (INS_GET) to get data from the card or 0xA2 (INS_PUT) to store data.
     * P1 and P2 parameters are ignored.
     */
    public void process(APDU apdu){
        // Select the Applet, through the select method, this applet is selectable, 
        // After successful selection, all APDUs are delivered to the currently selected applet
        // via the process method.
        if (selectingApplet()){
            return;
        }
        // Get the APDU buffer byte array.
        byte[] buf = apdu.getBuffer();
        // Receive all incoming data. 
        apdu.setIncomingAndReceive();
        
        // If the CLA is not equal to 0xB0(CLA_TEAPOT),  throw an exception.
        if(buf[ISO7816.OFFSET_CLA] != CLA_TEAPOT){
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        // Dispatch INS in APDU.
        switch (buf[ISO7816.OFFSET_INS]){
        case INS_GET:
            // The APDU format can be "0xB0 0xA1 P1 P2 [Lc] [Data] [Le]", 
            // such as "B0A10000" or "B0A101020311223300".
            // All parameters are ignored, just returns data.
            SendData(apdu);
            break;

        case INS_PUT:
            // The APDU format can be "0xB0 0xA2 P1 P2 Lc Data [Le]",
            // such as "B0A2000002112200".
            // Parameters P1 and P2 are ignored.
            // Data can be up to 254 bytes.
            StoreData(apdu);
            break;

        default:
            // We don't know the INS - throw an exception.
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    
    /**
     * Stores data on the card and then sends updated data as a responce
     * @param apdu the APDU command containing data to store
     */
    protected void StoreData(APDU apdu){
        byte[] buf = apdu.getBuffer();
        short len = Util.makeShort((byte)0, buf[ISO7816.OFFSET_LC]);
        // check if data length is ok,
        // if MAX_DATA_LENGTH is 254 or less it will be always ok.
        if(len > MAX_DATA_LENGTH){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // copy content of the buffer to the data array
        data.put(buf, ISO7816.OFFSET_CDATA, len);
        // send back data stored in flash
        SendData(apdu);
    }

    /**
     * Sends data from the card in APDU responce
     * @param apdu the APDU command where we will put the result.
     */
    protected void SendData(APDU apdu){
        apdu.setOutgoing();
        apdu.setOutgoingLength(data.length());
        apdu.sendBytesLong(data.get(), (short)0, data.length());
    }

}
