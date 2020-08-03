package toys;

import javacard.framework.*;

/**
 * A class to store variable length data in EEPROM.
 * In the constructor define the maximum capacity 
 * that will be allocated for storage.
 * <p>
 * Constructor is called with a single parameter - maximum capacity.
 * <pre>
 * // Usage example
 * DataEntry de = new DataEntry(maxLen); // create DataEntry with max capacity of maxLen
 * de.put(data, offset, len); // store data in the storage
 * byte[] buf = de.get();    // access bytearray of the storage,
 * short len = de.length();  // figure out the length of data stored,
 * short maxLen = de.maxLength(); // find maximum capacity of the storage
 * </pre>
 */
public class DataEntry{
    /** Byte buffer to store data in. Allocated in the constructor */
    private byte[] buffer;
    /** Length of the data currently stored */
    private short bufferLength = (short)0;
    /** Maximum length of the data we can store. Defined in the constructor. */
    private short bufferMaxLength = (short)0;

    /**
     * Class constructor. Allocates enough memory in EEPROM to store data.
     * @param maxSize - size that will be allocated for storage. 
     *                  Defines the maximum length of the data that we can store.
     * @throws ISOException if maxSize is negative.
     */
    public DataEntry(short maxSize) throws ISOException{
        if(maxSize < 0){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        bufferMaxLength = maxSize;
        buffer = new byte[maxSize];
    }
    /**
     * Stores data on the card and then sends updated data as a responce
     * @param data   - byte array with data to store
     * @param offset - start position of the data in the buffer
     * @param len    - length of the data
     * @return number of bytes stored. 
     * @throws ISOException if data is larger than capacity.
     */
    public short put(byte[] data, short offset, short len) throws ISOException{
        if(len > bufferMaxLength){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        wipe();
        Util.arrayCopy(data, offset, buffer, (short)0, len);
        bufferLength = len;
        return bufferLength;
    }
    /**
     * @return internal buffer with the data
     */
    public byte[] get(){
        return buffer;
    }
    /**
     * @return length of the data currently stored
     */
    public short length(){
        return bufferLength;
    }
    /**
     * @return maximum length of the data that can be stored in this class 
     *         (internal buffer capacity)
     */
    public short maxLength(){
        return bufferMaxLength;
    }
    /** Overwrites the content of the internal buffer with zeroes */
    public void wipe(){
        Util.arrayFillNonAtomic(buffer, (short)0, bufferMaxLength, (byte)0x00);
        bufferLength = (short)0;
    }
}