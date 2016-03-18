package mil.osd.dmdc.is.ctl.sc.keygen;

import java.io.IOException;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;


public class AppletAPI {
  private static boolean debug = false;
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
  static final int MAX_ALGOS = 4;
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
  private static final byte[] origKeyGenAid = { (byte)0xA0, 0x00, 0x00, 0x01, 0x47, 0x00, 0x00, (byte)0x80, 0x02 };

  int maxBytesIndicator = 0;
  public AppletAPI() {
    super();
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
  public static Card getCard() throws CardException, IOException {
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
   * Select AsymKeyGen applet.
   *
   * @param channel
   * @param aidBytes
   * @return
   * @throws CardException
   */
  ResponseAPDU select(CardChannel channel) throws CardException {
    try {
      return select(channel, origKeyGenAid);
    } catch (Exception e) {
      ; // fall through and try other aid
    }
    return select(channel, keyGenAid);
  }
  ResponseAPDU select(CardChannel channel, byte[] aidBytes) throws CardException {
    CommandAPDU cmd = new CommandAPDU(iso_cla, sel_ins, sel_app_p1, 0, aidBytes);
    return doTransmit("Select application", channel, cmd);
  }
  private ResponseAPDU doTransmit(String label, CardChannel channel, CommandAPDU apdu) throws CardException {
    if (debug) {
      System.out.println(label);
      System.out.print(">> ");
      System.out.println(Util.getDumpBytes(apdu.getBytes()));
    }
    ResponseAPDU resp = channel.transmit(apdu);
    if (debug) {
      System.out.print("<< ");
      System.out.println(Util.getDumpBytes(resp.getBytes()));
    }
    if (resp.getSW1() != 0x90 && resp.getSW1() != 0x6C) {
      System.err.println("Error status executing APDU command: " + Util.toDisplayHex((short)(resp.getSW() & 0xFFFF)));
      throw new CardException("Unexpected APDU status");
    }
    return resp;
  }
  /**
   * Get Capabilities Array
   * @param channel
   * @return
   * @throws CardException
   */
  byte[] getCaps(CardChannel channel) throws CardException {
    CommandAPDU cmd = new CommandAPDU(app_cla, ins_cap, 0, 0, 7);
    ResponseAPDU resp = doTransmit("Get Capabilities", channel, cmd);
    byte[] respData = resp.getData();

    return respData;
  }
    /**
     * Gets the name string associated with an algorithm identifier.
     * @param algoId
     * @return
     */
    String getAlgoName(int algoId) {
      if (algoId < 0 || algoId > MAX_ALGOS) {
        return ("Invalid algorithm identifier: " + algoId);
      }
      return (algoName[algoId]);
    }
  /**
   * Generate new asymmetric key pair
   *
   * @param channel
   * @param algo
   * @return
   * @throws CardException
   */
  ResponseAPDU genKey(CardChannel channel, int algo) throws CardException {
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
  ResponseAPDU getPub(CardChannel channel, int algo) throws CardException {
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
  ResponseAPDU getPri(CardChannel channel, int algo) throws CardException {
    CommandAPDU cmd = new CommandAPDU(app_cla, ins_get_pri, algo, 0, 0xff);
    //return channel.transmit(cmd);
    return doTransmit("Get Private Key " + getAlgoName(algo), channel, cmd);
  }
  /**
   * Instantiate Java public key object from applet response data.
   *
   * @param resp
   * @return
   * @throws Exception
   */
  RSAPublicKey getPublicKey(ResponseAPDU resp) throws Exception {
    KeyFactory kf = KeyFactory.getInstance("RSA");
    RSAPublicKey rPub = (RSAPublicKey)kf.generatePublic(new X509EncodedKeySpec(resp.getData()));
    if (debug) {
      System.out.println(Util.getDumpBytes(rPub.getPublicExponent().toByteArray()));
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
  RSAPrivateKey getPrivateKey(ResponseAPDU resp) throws Exception {
    PKCS8EncodedKeySpec p8s = new PKCS8EncodedKeySpec(resp.getData());
    KeyFactory kf = KeyFactory.getInstance("RSA");
    RSAPrivateKey rPri = (RSAPrivateKey)kf.generatePrivate(p8s);
    if (debug) {
        System.out.println(Util.getDumpBytes(rPri.getPrivateExponent().toByteArray()));
    }
    return rPri;
  }

}
