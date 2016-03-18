package mil.osd.dmdc.is.ctl.sc.keygen;

import java.io.IOException;
import java.io.PrintStream;

import java.math.BigInteger;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.ResponseAPDU;


public class GenAndExport {
  public GenAndExport() {
    super();
  }
  private void process(int algo, int nIterations, String filename) throws IOException {
    ResponseAPDU response;
    AppletAPI applet = new AppletAPI();
    PrintStream out;
    try {
      out = new PrintStream(filename);
    } catch (Exception e) {
      System.out.println("Unable to create file: " + filename);
      return;
    }
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
      if (!(capsArray[algo] == 2 || capsArray[algo] == 0)) {
        System.out.println(applet.getAlgoName(algo) + " is not supported on this card");
        return;
      }
      out.println("Writing " + nIterations + " " + applet.getAlgoName(algo) + " keys");
      for (int i = 0; i < nIterations; i++) {
        System.out.println("*** Generating " + applet.getAlgoName(algo) + " (" + (i + 1) + ") ***");
        response = applet.genKey(channel, algo);
        response = applet.getPri(channel, algo);
        RSAPrivateKey priKey = applet.getPrivateKey(response);
        response = applet.getPub(channel, algo);
        RSAPublicKey pubKey = applet.getPublicKey(response);

        out.println("** Iteration " + (i + 1) + " ***");
        System.out.println("Writing public key to file: ");
        out.println("Public Modulus:");
        writeBigIntegerArray(pubKey.getModulus(), out);
        out.println("Public Exponent");
        writeBigIntegerArray(pubKey.getPublicExponent(), out);

        System.out.println("Writing private key to file: ");
        out.println("Private Exponent");
        writeBigIntegerArray(priKey.getPrivateExponent(), out);
        out.println("Private Modulus:");
        writeBigIntegerArray(priKey.getModulus(), out);
      }
      card.endExclusive();
      out.close();
    } catch (Exception e) {
        e.printStackTrace();
        return;
    }

  }
  private void writeBigIntegerArray(BigInteger bi, PrintStream out) throws Exception {
    byte[] array = bi.toByteArray();
    if (array == null || array.length == 0) {
      out.println("Null data array");
      return;
    }
    int adjSignByte = 0;
    if (array[0] == 0) {
      adjSignByte = 1;
    }
    out.println(Util.toHex(array, adjSignByte, array.length - adjSignByte));
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 3) {
      System.out.println("usage: GenAndExport algorithmNumber iterations filename");
      return;
    }
    GenAndExport gae = new GenAndExport();
    int algo = Integer.parseInt(args[0]);
    int iters = Integer.parseInt(args[1]);
    String outFile = args[2];
    gae.process(algo, iters, outFile);
  }

}
