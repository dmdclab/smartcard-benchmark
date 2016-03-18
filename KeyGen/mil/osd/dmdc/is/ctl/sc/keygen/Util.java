package mil.osd.dmdc.is.ctl.sc.keygen;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class Util {
  // Class variable in support of utility debug output formatting information at end of this class file.
  private static final int HEXFIELDSIZE = 49;
  private static final char[] hexChars = "0123456789ABCDEF".toCharArray();
  //###################################################################################################
  //# The remainder of this file contains utility methods taken for other libraries and unrelated
  //# to the specific functionality of this test program and are included to provide debugging support
  //# while keeping this sample limited to a single source file for simplicity.
  //###################################################################################################
    /**
     * Writes a hex dump representation of input data to the output stream.
     * @param is Input data assumed binary data.
     * @param os Output that receives formatted dump.
     * @throws IOException
     */
    public static void hexDump(InputStream is, OutputStream os) throws IOException {
      int offset = 0;

      ByteArrayOutputStream hexStream;
      ByteArrayOutputStream asciiStream;
      while(true) {
        hexStream = new ByteArrayOutputStream();
        asciiStream = new ByteArrayOutputStream();
        int count = getHexSegment(is, hexStream, asciiStream);
        if (count <= 0)
          break;
        // Write Hex offset string as first 4 chars of line
        StringBuffer startLine = new StringBuffer("0000: ");
        String offsetStr = Integer.toHexString(offset & 0xffff).toUpperCase();
        startLine.replace(4 - offsetStr.length(), 4, offsetStr);
        os.write(startLine.toString().getBytes());
        byte[] hexField = hexStream.toByteArray();
        os.write(hexField);
        for (int i = 0; i < HEXFIELDSIZE - hexField.length; i++) {
          os.write(' ');
        }
        os.write ("  |".getBytes());
        os.write(asciiStream.toByteArray());
        os.write('\n');
        offset += 16;
      }
    }
    /**
     * Interprets up to 16 bytes of input data and writes formatted dump data.
     *
     * @param is Input data stream
     * @param hexStream Output for hex data written as 8 bit data bytes represented
     * as ascii hex.
     * @param asciiStream Ascii output for the input data. If input is not a printable
     * ascii character, a '.' is output.
     * @return Number of bytes processed.
     * @throws IOException
     */
    public static int getHexSegment(InputStream is,
                          OutputStream hexStream,
                          OutputStream asciiStream) throws IOException{
      int count = 0;
      int val;

      for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 8; j++) {
          val = is.read();
          if (val < 0)
            return count;
          putHex(val, hexStream);
          putAscii(val, asciiStream);
          count++;
          if (j != 7)
            hexStream.write(' ');
        }
        if (i == 0) {
          hexStream.write(' ');
          hexStream.write('-');
          hexStream.write(' ');
        }
      }
      return count;
    }

    public static void putHex(int val, OutputStream out) throws IOException {
      out.write(hexChars[(val & 0xf0) >> 4]);
      out.write(hexChars[val & 0xf]);
    }
    public static void putAscii(int c, OutputStream out) throws IOException {
      if ((c >= ' ') && (c <= '~'))
        out.write(c);
      else
        out.write('.');
    }
    public static String getDumpBytes(byte[] src) {
      if (src == null)
        return ("Null Buffer");
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      ByteArrayInputStream bis = new ByteArrayInputStream(src);
      try {
        hexDump(bis, bos);
      } catch (IOException e) {
        return e.toString() ;
      }

      return new String(bos.toByteArray());
    }
    public static String toDisplayHex(short sVal) {
      byte[] sBytes = new byte[2];
      sBytes[0] = (byte)(sVal & 0xff);
      sBytes[1] = (byte)((sVal >> 4) & 0xff);
      return "0x" + toHex(sBytes);
    }
    public static String toHex(byte[] bytes) {
      return toHex(bytes, 0, bytes.length);
    }
    public static String toHex(byte[] bytes, int offset, int length) {
        StringBuffer sb = new StringBuffer();
        if (bytes == null)
          return " null";
        if (offset >= length)
          return "invalid offset/length";
        for (int i = offset; i < (length - offset); i++) {
            sb.append(toHex(bytes[i]));
        }
        return sb.toString();
    }
    public static String toHex(byte val) {
      byte[] buff = new byte[2];
      buff[0] = (byte)hexChars[(val & 0xf0) >> 4];
      buff[1] = (byte)hexChars[val & 0xf];
      return new String(buff);
    }
    
    
}
