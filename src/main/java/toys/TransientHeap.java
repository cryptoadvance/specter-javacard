package toys;

import javacard.framework.*;

/** 
 * This class is a helper class to allocate and free memory in RAM for some temporary objects.
 * <p>
 * It can be shared between multiple classes.
 * In the constructor define maximum memory that will be reserved for allocations.
 * <p>
 * I strongly recommend to free allocated memory when you don't need it anymore.
 * It also makes sense to free all the memory before new APDU command is processed.
 * <p>
 * A standard pattern I follow:
 * <pre>
 * short len = NUMBER_OF_BYTES_TO_ALLOCATE;
 * short off = heap.allocate(len); // offset where our memory starts
 * byte[] buf = heap.buffer; // buffer of the heap with allocated memory
 * // ... do stuff
 * heap.free(len);
 * return WHATEVER_YOU_RETURN;
 * </pre>
 */
public class TransientHeap{
    /** byte array in RAM that acts as heap for temp memory allocations */
    public byte[] buffer;
    /** a 1-element array in RAM to store cursor position */
    private short[] cur;
    /** position of the cursor in the cur array (0) */
    final static private short CUR_OFFSET = (short)0;
    /**
     * Class constructor. Reserves maxSize memory for allocations.
     * @param maxSize - number of bytes to reserve.
     */
    public TransientHeap(short maxSize){
        // if maxSize < 0 -> throw error
        buffer = JCSystem.makeTransientByteArray(maxSize, JCSystem.CLEAR_ON_DESELECT);
        // because we want to keep it in RAM
        cur = JCSystem.makeTransientShortArray((short)1, JCSystem.CLEAR_ON_DESELECT);
        cur[CUR_OFFSET] = (short)0;
    }
    /**
     * @return length of the internal buffer
     */
    public short length(){
        return (short)buffer.length;
    }
    /**
     * @return number of free bytes that can be reserved
     */
    public short available(){
        return (short)(buffer.length-cur[CUR_OFFSET]);
    }
    /**
     * @return number of bytes allocated on the stack
     */
    public short allocated(){
        return cur[CUR_OFFSET];
    }
    /**
     * Allocates some memory in the buffer
     * @param size - number of bytes to allocate in the buffer
     * @return offset in the buffer where allocated bytes start
     */
    public short allocate(short size) throws ISOException {
        if(size > available()){
            free();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        short offset = cur[CUR_OFFSET];
        cur[CUR_OFFSET] = (short)(offset+size);
        return offset;
    }
    /**
     * Frees memory allocated earlier
     * @param size - number of bytes to free
     * @return number of bytes allocated in the buffer
     */
    public short free(short size){
        if(size > cur[CUR_OFFSET]){
            free();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        cur[CUR_OFFSET] -= size;
        // fill with zeroes such that next function can be sure everything is zero
        Util.arrayFillNonAtomic(buffer, cur[CUR_OFFSET], size, (byte)0x00);
        return cur[CUR_OFFSET];
    }
    /**
     * Frees the whole buffer
     * @return 0 (number of bytes allocated in the buffer)
     */
    public short free(){
        Util.arrayFillNonAtomic(buffer, (short)0, (short)buffer.length, (byte)0x00);
        cur[CUR_OFFSET] = (short)0;
        return cur[CUR_OFFSET];
    }
}