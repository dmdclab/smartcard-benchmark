package samples;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;


/**
 * Test class to demonstrate use of the DMDC AsymKeyGen applet.
 *
 * In order to keep this sample program as simple as possible, this class is entirely self contained (with
 * the exception of standard Java (1.6 and above) classes. Exception handling and error processing have
 * been kept to a minimum.
 *
 */
public class ScioGenKey {
  private boolean debug = false;
  // APDU Commands
  private static final int iso_cla = 0x00;
  private static final int sel_ins = 0xA4;
  private static final int sel_app_p1 = 0x04;

  private static final int app_cla = 0x80; // Application Class byte
  private static final int ins_cap = 0x10;   // Get Capabilities instruction byte.
                         // Returns a 7 byte array with each byte reflecting the current status of an algorithm.
                         // Algorithm IDs indicate the offset into the array as follows:
                         // 0 - No algorithm
                         // 1 - RSA 1024 bit key
                         // 3 - RSA 2048 bit key
                         // 4 - RSA 3072 bit key #Note this is not supported on current cards
                         // 5 - RSA CRT 1024 bit key # Note the current version of the applet does not support CRT keys
                         // 6 - RSA CRT 2048 bit key
                         // 7 - RSA CRT 3072 bit key
  private static final int MAX_ALGOS = 4;
  private static final String[] algoName = {"None", "RSA 1024", "RSA 2048", "RSA 3072",
                                             "RSA CRT 1024", "RSA CRT 2048", "RSA CRT 3072" };
                         // The byte values of the capabilities of the array are:
                         // 0xff - Not supported by the applet
                         // 0x00 - Key has been initialized
                         // 0x02 - Key has been instantiated but not initialized (Requires Key Gen)
                         // 0x03 - Key is not supported by the card
                         // Other values are various java card error conditions.
                         // Only algorithms with status of 0 or 2 can generate new keys.
                         //
  private static final int ins_key_gen = 0x12; // Generates new keys for the indicated algorithm
  private static final int ins_get_pub = 0x15; // Retrieve the public key material for the given algorithm
                           // Data is BER-TLV X.509 encoded public key
                           //
  private static final int ins_get_pri = 0x17;  // Retrieve the private key material for the given algorithm.
                           // Data is BER-TLV PKCS8 encoded private key

                           // Truncated AID (without the maj/minor version) for the applet is:
  private static final byte[] keyGenAid = { (byte)0xA0, 0x00, 0x00, 0x01, 0x47, (byte)0x80, 0x02 };

  int maxBytesIndicator = 0;

  // Class variable in support of utility debug output formatting information at end of this class file.
  private static final int HEXFIELDSIZE = 49;
  private static final char[] hexChars = "0123456789ABCDEF".toCharArray();

  public ScioGenKey() {
    super();
  }

  /**
   * Perform a generate and validate test.
   * For each supported keypair in the applet, this function generates a new key pair, retrieves the encoded
   * public and private keys and instantiates the corresponding Java key objects. An array of random bytes
   * of the size of the key modulus is then generated and used as source data which is encrypted by the
   * public key and then decrypted by the private key and compared to validate that the decryption buffer
   * matches the original source buffer.
   *
   * Note: This test does not verify that the keys instantiated on the host are the same keys that are on
   * the applet only that the public key and the private key are a valid key pair.
   *
   * @throws IOException
   */
  private void test() throws IOException {
    ResponseAPDU response;
    try {
      Card card = getCard();
      CardChannel channel = card.getBasicChannel();
      // Select the applet
      select(channel, keyGenAid);
      // Get the capabilities array
      byte[] capsArray = getCaps(channel);
      if (capsArray == null || capsArray.length < MAX_ALGOS) {
        throw new IOException("Invalid Capabilities Array. Cannot continue ...");
      }
      for (int i = 1; i < MAX_ALGOS; i++) {
        if (capsArray[i] == 0 || capsArray[i] == 2) {
          System.out.println("*** Generating " + getAlgoName(i) + " ***");
          response = genKey(channel, i);
          System.out.println("    Requesting public key");
          response = getPub(channel, i);
          RSAPublicKey pubKey = getPublicKey(response);
          System.out.println("    Requesting private key");
          response = getPri(channel, i);
          RSAPrivateKey priKey = getPrivateKey(response);
          System.out.println("    Verifying valid key pair");
          if (verifyKeyPair(pubKey, priKey)) {
            System.out.println("  * KeyPair verified.");
          } else {
            // failure infomation printed out in verify routine
          }
        } else {
          System.out.println("Skipping algorithm '" + getAlgoName(i) + "' with status: " + capsArray[i]);
        }
      }


    } catch (Exception e) {
        e.printStackTrace();
        return;
    }

  }

    private void writeToFile(int algo, String filename) throws Exception {
      ResponseAPDU response;
      try {
        Card card = getCard();
        CardChannel channel = card.getBasicChannel();
        // Select the applet
        select(channel, keyGenAid);
        // Get the capabilities array
        byte[] capsArray = getCaps(channel);
        if (capsArray == null || capsArray.length < MAX_ALGOS) {
          throw new IOException("Invalid Capabilities Array. Cannot continue ...");
        }
        if (capsArray[algo] != 2 && capsArray[algo] != 0) {
          throw new IOException("Algorithm not supported");
        }
          
          
        System.out.println("*** Generating " + getAlgoName(algo) + " ***");
        response = genKey(channel, algo);
        System.out.println("    Requesting private key");
        response = getPri(channel, algo);
        RSAPrivateKey priKey = getPrivateKey(response);
        
          System.out.println("    Writing private key to " + filename);
        FileOutputStream fos = new FileOutputStream(filename);
        fos.write(priKey.getEncoded()); 
        fos.close();

      } catch (Exception e) {
          e.printStackTrace();
          return;
      }

    }
  /**
   * Select AsymKeyGen applet.
   *
   * @param channel
   * @param aidBytes
   * @return
   * @throws CardException
   */
  private ResponseAPDU select(CardChannel channel, byte[] aidBytes) throws CardException {
    CommandAPDU cmd = new CommandAPDU(iso_cla, sel_ins, sel_app_p1, 0, aidBytes);
    //return channel.transmit(cmd);
    return doTransmit("Select application", channel, cmd);
  }

  /**
   * Get Capabilities Array
   * @param channel
   * @return
   * @throws CardException
   */
  private byte[] getCaps(CardChannel channel) throws CardException {
    CommandAPDU cmd = new CommandAPDU(app_cla, ins_cap, 0, 0, 7);
    ResponseAPDU resp = doTransmit("Get Capabilities", channel, cmd);
    byte[] respData = resp.getData();

    return respData;
  }
  /**
   * Generate new asymmetric key pair
   *
   * @param channel
   * @param algo
   * @return
   * @throws CardException
   */
  private ResponseAPDU genKey(CardChannel channel, int algo) throws CardException {
    CommandAPDU cmd = new CommandAPDU(app_cla, ins_key_gen, algo, 0);
    return doTransmit("Generate Key: " + getAlgoName(algo), channel, cmd);
  }

  /**
   * Get encoded public key.
   *
   * @param channel
   * @param algo
   * @return
   * @throws CardException
   */
  private ResponseAPDU getPub(CardChannel channel, int algo) throws CardException {
    CommandAPDU cmd = new CommandAPDU(app_cla, ins_get_pub, algo, 0, 0xff);
    return doTransmit("Get Public Key " + getAlgoName(algo), channel, cmd);
  }
  /**
   * Get encoded private key
   *
   * @param channel
   * @param algo
   * @return
   * @throws CardException
   */
  private ResponseAPDU getPri(CardChannel channel, int algo) throws CardException {
    CommandAPDU cmd = new CommandAPDU(app_cla, ins_get_pri, algo, 0, 0xff);
    //return channel.transmit(cmd);
    return doTransmit("Get Private Key " + getAlgoName(algo), channel, cmd);
  }

  private ResponseAPDU doTransmit(String label, CardChannel channel, CommandAPDU apdu) throws CardException {
    if (debug) {
      System.out.println(label);
      System.out.print(">> ");
      System.out.println(getDumpBytes(apdu.getBytes()));
    }
    ResponseAPDU resp = channel.transmit(apdu);
    if (debug) {
      System.out.print("<< ");
      System.out.println(getDumpBytes(resp.getBytes()));
    }
    if (resp.getSW1() != 0x90 && resp.getSW1() != 0x6C) {
      System.err.println("Error status executing APDU command: " + toDisplayHex((short)(resp.getSW() & 0xFFFF)));
      throw new CardException("Unexpected APDU status");
    }
    return resp;
  }

  /**
   * Instantiate Java public key object from applet response data.
   *
   * @param resp
   * @return
   * @throws Exception
   */
  private RSAPublicKey getPublicKey(ResponseAPDU resp) throws Exception {
    KeyFactory kf = KeyFactory.getInstance("RSA");
    RSAPublicKey rPub = (RSAPublicKey)kf.generatePublic(new X509EncodedKeySpec(resp.getData()));
    if (debug) {
      System.out.println(getDumpBytes(rPub.getPublicExponent().toByteArray()));
    }
    return rPub;
  }

  /**
   * Instantiate Java private key object from applet response data
   *
   * @param resp
   * @return
   * @throws Exception
   */
  private RSAPrivateKey getPrivateKey(ResponseAPDU resp) throws Exception {
    PKCS8EncodedKeySpec p8s = new PKCS8EncodedKeySpec(resp.getData());
    KeyFactory kf = KeyFactory.getInstance("RSA");
    RSAPrivateKey rPri = (RSAPrivateKey)kf.generatePrivate(p8s);
    if (debug) {
        System.out.println(getDumpBytes(rPri.getPrivateExponent().toByteArray()));
    }
    return rPri;
  }

  /**
   * Verify that data encrypted with public key and decrypted with private key matches.
   *
   * @param pubKey
   * @param priKey
   * @return
   */
  private boolean verifyKeyPair(RSAPublicKey pubKey, RSAPrivateKey priKey) {
    int keyBytes = pubKey.getModulus().bitLength() / 8;
    byte[] plainBuffer = new byte[keyBytes];
    byte[] encBuffer = new byte[keyBytes];
    byte[] decBuffer = new byte[keyBytes];
    try {
      Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, pubKey);
      cipher.doFinal(plainBuffer, 0, keyBytes,  encBuffer);

      cipher.init(Cipher.DECRYPT_MODE, priKey);
      cipher.doFinal(encBuffer, 0, keyBytes, decBuffer);
    } catch (Exception e) {
      e.printStackTrace();
      showCryptAttempt(plainBuffer, encBuffer, decBuffer, pubKey.getModulus().toByteArray(), priKey.getPrivateExponent().toByteArray());
      return false;
    }
    if (Arrays.equals(plainBuffer, decBuffer)) {
      if(debug) {
        System.out.println(" **** Encryption Verified *****");
      }
    } else {
      System.err.println(" **** Encryption Failed *****");
      showCryptAttempt(plainBuffer, encBuffer, decBuffer, pubKey.getModulus().toByteArray(), priKey.getPrivateExponent().toByteArray());
      return false;
    }
    return true;
  }
  /**
   * Gets the name string associated with an algorithm identifier.
   * @param algoId
   * @return
   */
  private String getAlgoName(int algoId) {
    if (algoId < 0 || algoId > MAX_ALGOS) {
      return ("Invalid algorithm identifier: " + algoId);
    }
    return (algoName[algoId]);
  }
  /**
   * Dumps out debugging information for the "verify" stage of the test
   *
   * @param plain Random bytes
   * @param encrypt Plain buffer processed with public key
   * @param decrypt Encrypt buffer processed with private key
   * @param mod Public/private modulus
   * @param priExp Private exponent
   */
  private void showCryptAttempt(byte[] plain, byte[] encrypt, byte[] decrypt, byte[] mod, byte[] priExp) {
    System.out.println("**** Encryption Failed *****");
    System.out.println("plain buffer:");
    System.out.println(getDumpBytes(plain));
    System.out.println("Encrypted buffer:");
    System.out.println(getDumpBytes(encrypt));
    System.out.println("Decrypted buffer:");
    System.out.println(getDumpBytes(decrypt));
    System.out.println("Modulus:");
    System.out.println(getDumpBytes(mod));
    System.out.println("Private exponent:");
    System.out.println(getDumpBytes(priExp));
  }
  /**
   * Get the reader and card to use to perform the test.
   * Uses the following algorithm:
   * - If only one reader is found and it contains a card, silently return the card.
   * - if only one reader is found and no card is present, prompts and waits for card insertion
   * - if multiple readers are found prompt for which reader to use.
   * - if card is present in selected reader return the card
   * - if no card is present in selected reader prompt and wait for card insertion.
   *
   * @return the card to use for the test
   * @throws CardException
   * @throws IOException
   */
  public Card getCard() throws CardException, IOException {
    TerminalFactory factory = TerminalFactory.getDefault();
    List<CardTerminal> terminals = factory.terminals().list();
    CardTerminal terminal = null;
    boolean inputDone = false;
    while (!inputDone) {
      if (terminals.size() == 1) {
        // Only one terminal, use it if there is a card present
        terminal = terminals.get(0);
        inputDone = true;
      } else {
        System.out.println();
        for (int i = 0; i < terminals.size(); i++) {
          terminal = terminals.get(i);
          System.out.println("" + i + ". " + terminal.getName());
        }
        System.out.println("\nSelect reader number: ");
        int choice = (System.in.read() & 0xff) - '0';
        if (choice < 0 || choice >= terminals.size()) {
          System.out.println("Invalid reader number. Please retry.");
          continue;
        }
        terminal = terminals.get(choice);
      }
      if (terminal.isCardPresent()) {
        inputDone = true;
      }
      while (!terminal.isCardPresent()) {
        System.out.println("Please insert card in reader \"" + terminal.getName());
        terminal.waitForCardPresent(0);
        if (terminal.isCardPresent()) {
          inputDone = true;
        }
      }
    }
    return terminal.connect("T=0");
  }
  /**
   * Primary entry point for AsymKeyGen operation.
   *
   * @param args
   * @throws IOException
   */
  public static void main(String[] args) throws Exception{
    ScioGenKey scioGenKey = new ScioGenKey();
    scioGenKey.writeToFile(2, "priKeyData");
  }

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
      StringBuffer sb = new StringBuffer();
      if (bytes == null)
        return " null";
      for (int i = 0; i < bytes.length; i++) {
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
