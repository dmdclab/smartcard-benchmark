package mil.osd.dmdc.is.ctl;

import javacard.framework.ISOException;
import javacard.framework.Util;
/**
 * DER object. Reusable object describing type and length byte array for DER encoding.
 */
public class DerObject {
    static public final byte TYPE_SEQ = 0x30;
    static public final byte TYPE_INT = 0x02;
    static public final byte TYPE_BIT_STRING = 0x03;
    static public final byte TYPE_OCTET_STRING  = 0x04;
    static public final byte TYPE_FIXED = 0x7F;
    static private final short INV_DER_ENCODING = 0x6F30;
    private short lenLen;
    private byte[] tagHdrBytes = { 0, 0, 0, 0 };
    private byte[] fixedObjectBytes = null;
    private short objSize;  // Overall size of data object including tag and enclosed data/objects
    private short dataLen;  // length of enclosed data 
    private short dataPrefixCount; // if set indicates additional zero byte after tag but before enclosed data
                                   // set for integer tags to set sign byte for positive integers
                                   // and always for bit string tags to indicate 0 unused bits (eben byte alignment) 
    private byte type;      // type of tag
    
    DerObject(byte type) {
        this.type = type;
        if (type == TYPE_BIT_STRING) {
            dataPrefixCount = 1;
        }
        dataLen = 0;
        tagHdrBytes[0] = type;
        objSize = 0;
    }
    DerObject(byte[] fixedData) {
        fixedObjectBytes = fixedData;
        objSize = (short)fixedData.length;
        type = TYPE_FIXED;
    }
    /**
     * Used to add an enclosed object to a composed data type
     * @param obj object to add
     * @param reset clear any length value from previous instance before adding enclosed object size
     */
    void addChildTag(DerObject obj, boolean reset) {
        
        if (type == TYPE_FIXED || type == TYPE_INT) {
            ISOException.throwIt(INV_DER_ENCODING);
        }
        // reset must be set when adding first object to composed tat
        if (reset)
            dataLen = 0;
        dataLen += obj.getObjectSize();
    }
    /**
     * Calculates length of the tag length parameter end enclosed data. Only valid for simple data tags
     * and not composed tags.
     * @param data
     */
    void setTagDataLength(byte[] data, short len) {
        if (type == TYPE_FIXED) {
            //objSize = (short)data.length;
            objSize = len;
            return;
        } else if (tagHdrBytes[0] == TYPE_INT) {
            if ((data[0] & (byte)0x80) != 0){
                dataPrefixCount = 1;
            } else {
                dataPrefixCount = 0;
            }
        } else if (tagHdrBytes[0] == TYPE_BIT_STRING) {
            dataPrefixCount = 1; // acount for bit string "unused bits" byte;
        } else {
            ISOException.throwIt(INV_DER_ENCODING);
        }
        dataLen = len;
        finalizeTag();
    }
    /**
     * Set tag length bytes based on the final enclosed data length of a tag, and the
     * final object size.
     */
    void finalizeTag() {
        dataLen += dataPrefixCount;
        if (dataLen > 0x00ff) {
            lenLen = 3;
            tagHdrBytes[1] = (byte)0x82;
            tagHdrBytes[2] = (byte)((dataLen >> 8) & 0xff);
            tagHdrBytes[3] = (byte)(dataLen & 0xff);
        } else if (dataLen > 0x007f) {
            lenLen = 2;
            tagHdrBytes[1] = (byte)0x81;
            tagHdrBytes[2] = (byte)(dataLen & 0xff);
        } else {
            lenLen = 1;
            tagHdrBytes[1] = (byte)(dataLen);
        } 
        // Final size of the object is the length of all enclosed data plus
        // the length of the encoded length bytes + the tag type byte
        objSize = (short)(dataLen + lenLen + 1);
    }
    /**
     * Get the final size of a der object 
     * @return size including all nested objects
     */
    short getObjectSize() {
        return objSize;
    }
    /**
     * Serializes a TYPE_FIXED data object to the output buffer. Note that 
     * fixed type objects include the tag type and length bytes in the
     * fixed data.
     * @param buff output data buffer
     * @param offset offset within the data buffer
     * @return the updated offset for the next buffer write
     */
    short writeFixedObject(byte[] buff, short offset) {
        Util.arrayCopy(fixedObjectBytes, (short)0, buff, offset, objSize);
        return (short)(offset + objSize);
    }
    /**
     * Write non-fixed data object to the output data buffer.
     * @param buff output buffer
     * @param offset offset within the buffer to write the object
     * @param data array of enclosed data object for primative types
     * @param len sise of the array to write to output
     * @return updated offset for the next buffer write
     */
    short writeObject(byte[] buff, short offset, byte[] data, short len) {
        // Fixed types should be projibited - exception???
        if (type == TYPE_FIXED) {
            Util.arrayCopy(data, (short)0, buff, offset, len);
            return (short)(offset + len);
        }
        Util.arrayCopy(tagHdrBytes, (short)0, buff, offset, (short)(lenLen + 1));
        offset += (short)(lenLen + 1);
        if (dataPrefixCount == 1) {
            buff[offset++] = 0;
        }
        if (data != null) {
            Util.arrayCopy(data, (short)0, buff, offset, len);
            offset += len;
        }
        return offset;
    }

}
