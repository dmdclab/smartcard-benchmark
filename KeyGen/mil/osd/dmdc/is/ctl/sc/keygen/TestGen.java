package mil.osd.dmdc.is.ctl.sc.keygen;

import java.io.IOException;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import java.util.Arrays;

import javax.crypto.Cipher;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.ResponseAPDU;

public class TestGen {
  boolean debug = false;
  public TestGen() {
    super();
  }
  private void test() throws IOException {
    ResponseAPDU response;
    AppletAPI applet = new AppletAPI();
    try {
      Card card = AppletAPI.getCard();
      card.beginExclusive();
      CardChannel channel = card.getBasicChannel();
      
      // Select the applet
      applet.select(channel);
      // Get the capabilities array
      byte[] capsArray = applet.getCaps(channel);
      if (capsArray == null || capsArray.length < applet.MAX_ALGOS) {
        throw new IOException("Invalid Capabilities Array. Cannot continue ...");
      }
      for (int i = 1; i < applet.MAX_ALGOS; i++) {
        if (capsArray[i] == 0 || capsArray[i] == 2) {
          System.out.println("*** Generating " + applet.getAlgoName(i) + " ***");
          response = applet.genKey(channel, i);
          System.out.println("    Requesting public key");
          response = applet.getPub(channel, i);
          RSAPublicKey pubKey = applet.getPublicKey(response);
          System.out.println("    Requesting private key");
          response = applet.getPri(channel, i);
          RSAPrivateKey priKey = applet.getPrivateKey(response);
          System.out.println("    Verifying valid key pair");
          if (verifyKeyPair(pubKey, priKey)) {
            System.out.println("  * KeyPair verified.");
          } else {
            // failure infomation printed out in verify routine
          }
        } else {
          System.out.println("Skipping algorithm '" + applet.getAlgoName(i) + "' with status: " + capsArray[i]);
        }
      }
      card.endExclusive();

    } catch (Exception e) {
        e.printStackTrace();
        return;
    }

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
    System.out.println(Util.getDumpBytes(plain));
    System.out.println("Encrypted buffer:");
    System.out.println(Util.getDumpBytes(encrypt));
    System.out.println("Decrypted buffer:");
    System.out.println(Util.getDumpBytes(decrypt));
    System.out.println("Modulus:");
    System.out.println(Util.getDumpBytes(mod));
    System.out.println("Private exponent:");
    System.out.println(Util.getDumpBytes(priExp));
  }
  public static void main(String[] args) throws Exception {
    TestGen test = new TestGen();
    test.test();
  }
}
