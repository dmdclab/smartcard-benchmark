package mil.osd.dmdc.is.ctl;

import java.applet.Applet;

import javacard.framework.*;
import javacard.security.*;
//import javacard.framework.Util;

public class KeyGen  extends Applet {
    static private final byte KG_CLA_BYTE   = (byte)0x80;
    // Instructions
    static private final byte INS_CAPABILITIES = 0x10;
    static private final byte INS_KEY_GEN = 0x12;
    static private final byte INS_GET_PUB = 0x15;
    static private final byte INS_GET_PRI = 0x17;
    // ISO Intruction bytes
    static private final byte INS_GET_RESPONSE = (byte)0xC0;
    // Key Generation parameters in P1
    // Lower nibble algorithm:
    // - if == 0 invalid
    
    static private final short MAX_RSA_KEY_BUFF_SIZE = 400;

    static private final short KG_EX_SHORT = 0x6F00; 
    static private final short KG_EX_HIBYTE = 0x6F;
    // cryptography exceptions
    static private final short KG_CE_ILLEGAL_VAL = 0x01;
    static private final short KG_CE_UNITIALIZED_KEY = 0x02;
    static private final short KG_CE_UNK_ALGO = 0x03;
    static private final short KG_CE_INV_INIT = 0x04;
    static private final short KG_CE_ILLEGAL_USE = 0x05;
    static private final short KG_CE_ILLEGAL_DP = 0x06;
    static private final short MAX_SEND_SIZE = 256;
    static private final short MAX_SEND_SIZE_INDICATOR = 0;
    static private final byte ALG_NONE       = 0;
    static private final byte ALG_RSA1       = 1;
    static private final byte ALG_RSA2       = 2;
    static private final byte ALG_RSA3       = 3; 
    static private final byte ALG_RSA_CRT1   = 4;
    static private final byte ALG_RSA_CRT2   = 5;
    static private final byte ALG_RSA_CRT3   = 6; 
    static private final short N_ALGO_IDS     = 7;
    
    static private final byte BLK_SIZE_256  = (byte)0x00;
    static private final byte BLK_SIZE_NONE = (byte)0xFF;
    static private final short DATA_CAPACITY = 2048;
    static private final short RESULTS_CAPACITY = 1500;
    
    // Card Capabilities Status bytes
    static private final byte CAP_SUCCESS = 0x00;
    static private final byte CAP_NOT_INITIALIZED = 0x2;
    static private final byte CAP_NOT_SUPPORTED = 0x11;
    static private final byte CAP_EXE_INIT_ERR = 0x12;
    static private final byte CAP_EXE_ERR = 0x13;
    static private final byte CAP_ALGO_PARAM_ERR = 0x14;
    
    // key declarations in eeprom
    static private RSAPrivateKey rsa1024pri = null;
    static private RSAPublicKey rsa1024pub = null;
    static private RSAPrivateKey rsa2048pri = null;
    static private RSAPrivateCrtKey rsaCrt2048pri = null;
    static private RSAPublicKey rsa2048pub = null;
    static private RSAPublicKey rsaCrt2048pub = null;
    static private RSAPrivateKey rsa3072pri = null;
    static private RSAPublicKey rsa3072pub = null;
/*    
    static private Key rsaCrt1024pri = null;
    static private Key rsaCrt1024pub = null;
    static private Key rsaCrt2048pri = null;
    static private Key rsaCrt2048pub = null;
    static private Key rsaCrt3072pri = null;
    static private Key rsaCrt3072pub = null;	
*/    
    static private KeyPair rsa1024Kp = null;
    static private KeyPair rsa2048Kp = null;
    static private KeyPair rsa3072Kp = null;
    static private KeyPair rsaCrt2048Kp = null;

    
    
    
    // 'context' keys - keys used in current operation
    static private Key pubKey = null;
    static private Key priKey = null;
    static private KeyPair kaPair = null;
    static private RSAPrivateKey rPri;
    static private RSAPrivateCrtKey rCrtPri;
    static private RSAPublicKey rPub;
    static private short keySize;
    
    // Buffer declarations
    static private byte[] eeResBuff;
    static private short currResBuffSize;
    static private short currResBuffOff;
    
    static private byte[] biLeadByte = { 0 };

    // Card algorithm support array
    static private byte[] algos;


    // ASN.1 Key encoding
    // common 
    
    //static byte[] asnAlgo = { 0x10,0x0d,0x06,0x09,0x2a,(byte)0x86,(byte)0x87,0x0d,0x01,0x01,0x01,0x05,0x00 };
    
    // Assumes that the public exponent can always be represented in 3 bytes
    static private byte[] pubModulus;
    static private byte[] priModulus;
    static private byte[] pubExponent;
    static private byte[] priExponent;
    static private short pubModLen;
    static private short priModLen;
    static private short pubExpLen;
    static private short priExpLen;
    

    static private byte[] rsaAlgoSeq = { 0x30,0x0d,0x06,0x09,0x2a,(byte)0x86,0x48,(byte)0x86,(byte)0xf7,0x0d,0x01,0x01,0x01,0x05,0x00 };
    static private byte[] intZero = { 0x02, 0x01, 0x00 }; 
    //byte[] rsa1024seg1 = { 0x30, (byte)0x81, (byte)0x89, 0x02, (byte)0x81, (byte)0x81 };
    static private byte[] rsaPub1024seg1 = { 0x30, (byte)0x81, (byte)0x9b };
    static private byte[] rsaPub1024Seg3 = { 0x30,(byte)0x81,(byte)0x89,0x02,(byte)0x81,(byte)0x81};
    static private byte[] rsaPub2048seg1 = { 0x30, (byte)0x82, 0x01, 0x1d };
    static private byte[] rsaPub2048Seg3 = { 0x30,(byte)0x82,0x01, 0x0a, 0x02,(byte)0x82,0x01, 0x01};
    static private byte[] rsaPub3072seg1 = { 0x30, (byte)0x82, 0x01, (byte)0x9d };
    static private byte[] rsaPub3072Seg3 = { 0x30,(byte)0x82,0x01, (byte)0x8a, 0x02,(byte)0x82,0x01,(byte)0x81};
    // seg 4 is binary modulus
    static private byte[] rsaPubCommonSeg5 = { 0x02,0x03};
    
    static private byte[] rsaPri1024seg1 = { 0x30, (byte)0x82, 0x01, 0x1b };
    static private byte[] rsaPri1024Seg3 = { 0x30,(byte)0x82,0x01,0x08,0x02,(byte)0x81,(byte)0x81};
    // seg 4 is binary modulus
    static private byte[] rsaPri1024Seg5 = { 0x02,(byte)0x81,(byte)0x80};
    
    static private byte[] rsaPri2048seg1 = { 0x30, (byte)0x82, 0x01, 0x19 };
    static private byte[] rsaPri2048Seg3 = { 0x30,(byte)0x82,0x02,0x07,0x02,(byte)0x82,0x01, 0x01};
    static private byte[] rsaPri2048Seg5 = { 0x02,(byte)0x82,0x01, 0x00};
    
    static private DerObject derPubKey;
    static private DerObject derPubKeyInfo;
    static private DerObject derPubKeyInfoBitString;
    static private DerObject derPubKeyModulus;
    static private DerObject derPubKeyExponent;
    static private DerObject derPriKey;
    static private DerObject derPriKeyInfo;
    static private DerObject derPriKeyInfoOctetString;
    static private DerObject derPriKeyModulus;
    static private DerObject derPriKeyExponent;
    static private DerObject derRsaAlgo;
    static private DerObject derZeroInt;
    
    
    /*
    byte[] asn2048KeyHdr = { 0x30, (byte)0x82, 0x01, 0x0a, 0x02, (byte)0x82,  0x01, 0x01 };
    byte[] asn3072KeyHdr = { 0x30, (byte)0x82, 0x01, (byte)0x8a, 0x02, (byte)0x82,  0x01, (byte)0x81 };
    */

    private KeyGen() {; }
    
    protected KeyGen(byte bArray[], short bOffset, byte bLength) {
        super();
    }
    public static void install(byte bArray[], short bOffset, byte bLength)
    {
        //KeyGen kg = new KeyGen(bArray, bOffset, bLength);
        KeyGen kg = new KeyGen(bArray, bOffset, bLength);
        // Allocate eeprom buffer space
        eeResBuff = new byte[RESULTS_CAPACITY];
        // Allocate space for an arry to keep track of the status
        // when initializaiton each of the algorithms. 0xff indicates
        // that the algorithm initialization has not been attempted.
        algos = new byte[N_ALGO_IDS];
        for (short i = 0; i < N_ALGO_IDS; i++) { algos[i] = (byte)0xff; }

        pubModulus = new byte[MAX_RSA_KEY_BUFF_SIZE];
        priModulus = new byte[MAX_RSA_KEY_BUFF_SIZE];
        pubExponent = new byte[16];
        priExponent = new byte[MAX_RSA_KEY_BUFF_SIZE];
        // Initial standard modulus/exponent RSA keys
        try {
                rsa1024pri = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,
                             KeyBuilder.LENGTH_RSA_1024, false);
                rsa1024pub = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,
                             KeyBuilder.LENGTH_RSA_1024, false);                    
                rsa1024Kp = new KeyPair((RSAPublicKey)rsa1024pub, (RSAPrivateKey)rsa1024pri);
                algos[ALG_RSA1] = CAP_NOT_INITIALIZED;
        } catch (CryptoException ce) { 
                algos[ALG_RSA1] = (byte)ce.getReason(); 
        }
        try {
                rsa2048pri = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,
                            KeyBuilder.LENGTH_RSA_2048, false);
                rsa2048pub = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,
                            KeyBuilder.LENGTH_RSA_2048, false);                 
                //rsa2048Kp = new KeyPair(KeyPair.ALG_RSA, (short)rsa2048pub.getSize());
                rsa2048Kp = new KeyPair((RSAPublicKey)rsa2048pub, (RSAPrivateKey)rsa2048pri);
                algos[ALG_RSA2] = CAP_NOT_INITIALIZED;
        } catch (CryptoException ce) { 
                algos[ALG_RSA2] = (byte)ce.getReason(); 
        }
        try {
                rsa3072pri = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,
                                //KeyBuilder.LENGTH_RSA_3072, false);
                                (short)3072, false);
                rsa3072pub = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,
            //KeyBuilder.LENGTH_RSA_2048, false);
                                (short)3072, false);
                rsa3072Kp = new KeyPair((RSAPublicKey)rsa3072pub, (RSAPrivateKey)rsa3072pri);
                algos[ALG_RSA3] = CAP_NOT_INITIALIZED;
        } catch (CryptoException ce) { 
                algos[ALG_RSA3] = (byte)ce.getReason(); 
        }
//        try {
//                rsaCrt2048pri = (RSAPrivateCrtKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE,
//                                 KeyBuilder.LENGTH_RSA_2048, false);
//                rsaCrt2048pub = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,
//                        KeyBuilder.LENGTH_RSA_2048, false);                 
//                //rsa2048Kp = new KeyPair(KeyPair.ALG_RSA, (short)rsa2048pub.getSize());
//                rsaCrt2048Kp = new KeyPair((RSAPublicKey)rsaCrt2048pub, (RSAPrivateCrtKey)rsaCrt2048pri);
//                algos[ALG_RSA_CRT2] = CAP_NOT_INITIALIZED;
//        } catch (CryptoException ce) { 
//                algos[ALG_RSA2] = (byte)ce.getReason(); 
//        }
        derPubKey = new DerObject(DerObject.TYPE_SEQ);
        derPubKeyInfo = new DerObject(DerObject.TYPE_SEQ);
        derPubKeyInfoBitString = new DerObject(DerObject.TYPE_BIT_STRING);
        derPubKeyModulus = new DerObject(DerObject.TYPE_INT);
        derPubKeyExponent = new DerObject(DerObject.TYPE_INT);
        derPriKey = new DerObject(DerObject.TYPE_SEQ);
        derPriKeyInfo = new DerObject(DerObject.TYPE_SEQ);
        derPriKeyInfoOctetString = new DerObject(DerObject.TYPE_OCTET_STRING);
        derPriKeyModulus = new DerObject(DerObject.TYPE_INT);
        derPriKeyExponent = new DerObject(DerObject.TYPE_INT);
        // RSA algorithm DER Sequence and zeroInt are static throughout operation. Set up here.
        derRsaAlgo = new DerObject(rsaAlgoSeq);
        derZeroInt = new DerObject(intZero);
        kg.register(bArray, (short)(bOffset + 1), bArray[bOffset]);
        //kg.register();
    }
    //
    // **** Most processing starts here!!
    //
    public void process(APDU apdu) {
            // No applet specific processing for SELECT command
            if (selectingApplet()) {
    //                      apdu.setOutgoingLength((short)0);
                    return;
            }
            
            byte[] buffer = apdu.getBuffer();
            
            if (buffer[ISO7816.OFFSET_CLA] != KG_CLA_BYTE) {
                    // also support interindustry GET RESPONSE command
                    if (buffer[ISO7816.OFFSET_INS] != (byte)INS_GET_RESPONSE) {
                            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);                             
                            //ISOException.throwIt((short)(ISO7816.SW_UNKNOWN + (short)0x77));
                    }
            }
            
            switch (buffer[ISO7816.OFFSET_INS]) {
            
                // Instruction to get the supported algorithm array
                case INS_CAPABILITIES:
                    doGetCapabilities(apdu);
                    return;
                case INS_KEY_GEN:
                    if (buffer[ISO7816.OFFSET_P1] == 0 || buffer[ISO7816.OFFSET_P1] > N_ALGO_IDS) {
                            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                    }

                    try {
                        switch (buffer[ISO7816.OFFSET_P1]) {
                        case ALG_RSA1:
                                doRsaKeyGen(rsa1024Kp);
                                break;
                        case ALG_RSA2:
                                doRsaKeyGen(rsa2048Kp);
                                break;
                        case ALG_RSA3:
                                doRsaKeyGen(rsa3072Kp);
                                break;
//                        case ALG_RSA_CRT2:
//                                doRsaKeyGen(rsaCrt2048Kp);
//                                break;
                        default:
                                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                        }
                            
                    } catch (CryptoException ce) {
                            ISOException.throwIt(getKgException(ce));
                    }
                    return;
                case INS_GET_PUB:
                    if (buffer[ISO7816.OFFSET_P1] == 0 || buffer[ISO7816.OFFSET_P1] > N_ALGO_IDS) {
                            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                    }

                    try {
                        switch (buffer[ISO7816.OFFSET_P1]) {
                        case ALG_RSA1:
                                getRsaPubKey(rsa1024Kp);
                                break;
                        case ALG_RSA2:
                                getRsaPubKey(rsa2048Kp);
                                break;
                        case ALG_RSA3:
                                getRsaPubKey(rsa3072Kp);
                                break;
//                        case ALG_RSA_CRT2:
//                                getRsaPubKey(rsaCrt2048Kp);
//                                break;
                        default:
                                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                        }
                        sendData(apdu);
                            
                    } catch (CryptoException ce) {
                            ISOException.throwIt(getKgException(ce));
                    }
                    return;
                case INS_GET_PRI:
                    if (buffer[ISO7816.OFFSET_P1] == 0 || buffer[ISO7816.OFFSET_P1] > N_ALGO_IDS) {
                            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                    }

                    try {
                        switch (buffer[ISO7816.OFFSET_P1]) {
                        case ALG_RSA1:
                                getRsaPriKey(rsa1024Kp);
                                break;
                        case ALG_RSA2:
                                getRsaPriKey(rsa2048Kp);
                                break;
                        case ALG_RSA3:
                                getRsaPriKey(rsa3072Kp);
                                break;
                        case ALG_RSA_CRT2:
                                getRsaPriKey(rsaCrt2048Kp);
                                break;
                        default:
                                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                        }
                        sendData(apdu);
                            
                    } catch (CryptoException ce) {
                            ISOException.throwIt(getKgException(ce));
                    }
                    return;
            case INS_GET_RESPONSE:
                    if (buffer[ISO7816.OFFSET_P1] != 0 || buffer[ISO7816.OFFSET_P2] != 0) {
                            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                    }
                    sendData(apdu);
                    return;
            default:
                    // Unknown instruction
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
            
    }
    /**
     * Indicate that the applet is ready to be selected
     * @return
     */
    public boolean select() {
        return true;
    }
    /**
     * Build DER encoded public key in EEPROM result (output) buffer.
     * @param kp KeyPair containing public key to return
     */
    private void getRsaPubKey(KeyPair kp) {
        rPub = (RSAPublicKey)kp.getPublic();
        rPub.getModulus(pubModulus, (short)0);
        rPub.getExponent(pubExponent, (short)0);
        keySize = (short)(rPub.getSize() / 8);
        // Setup innermost "terminal" DER tags
        derPubKeyModulus.setTagDataLength(pubModulus, keySize);
        derPubKeyExponent.setTagDataLength(pubExponent, (short)3);
        // Setup enclosing sequence tags
        derPubKeyInfo.addChildTag(derPubKeyModulus, true);
        derPubKeyInfo.addChildTag(derPubKeyExponent, false);
        derPubKeyInfo.finalizeTag();
        
        derPubKeyInfoBitString.addChildTag(derPubKeyInfo, true);
        derPubKeyInfoBitString.finalizeTag();
        // and top level sequence tags
        derPubKey.addChildTag(derRsaAlgo, true);
        derPubKey.addChildTag(derPubKeyInfoBitString, false);
        derPubKey.finalizeTag();
        // Now write tags and data to output buffer
        currResBuffOff = 0;
        currResBuffOff = derPubKey.writeObject(eeResBuff, currResBuffOff, null, (short)0);
        currResBuffOff = derRsaAlgo.writeFixedObject(eeResBuff, currResBuffOff);
        currResBuffOff = derPubKeyInfoBitString.writeObject(eeResBuff, currResBuffOff, null, (short)0);
        currResBuffOff = derPubKeyInfo.writeObject(eeResBuff, currResBuffOff, null, (short)0);
        currResBuffOff = derPubKeyModulus.writeObject(eeResBuff, currResBuffOff, pubModulus, keySize);
        currResBuffOff = derPubKeyExponent.writeObject(eeResBuff, currResBuffOff, pubExponent, (short)3);
        // size buffer for output
        currResBuffSize = currResBuffOff;
        currResBuffOff = 0;
    }
    /**
     * Build DER encoded private key in EEPROM result (output) buffer.
     * @param kp KeyPair containing private key to return
     */
    private void getRsaPriKey(KeyPair kp) {
        
        rPri = (RSAPrivateKey)kp.getPrivate();
        rPri.getModulus(priModulus, (short)0);
        rPri.getExponent(priExponent, (short)0);
        keySize = (short)(rPri.getSize() / 8);
        // Setup innermost "terminal" DER tags
        derPriKeyModulus.setTagDataLength(priModulus, keySize);
        derPriKeyExponent.setTagDataLength(priExponent, keySize);
        // Innermost enclosing tags
        derPriKeyInfo.addChildTag(derZeroInt, true);
        derPriKeyInfo.addChildTag(derPriKeyModulus, false);
        derPriKeyInfo.addChildTag(derZeroInt, false);
        derPriKeyInfo.addChildTag(derPriKeyExponent, false);
        derPriKeyInfo.addChildTag(derZeroInt, false);
        derPriKeyInfo.addChildTag(derZeroInt, false);
        derPriKeyInfo.addChildTag(derZeroInt, false);
        derPriKeyInfo.addChildTag(derZeroInt, false);
        derPriKeyInfo.addChildTag(derZeroInt, false);
        derPriKeyInfo.finalizeTag();
        // wrap rsaprivatekey in octet string
        derPriKeyInfoOctetString.addChildTag(derPriKeyInfo, true);
        derPriKeyInfoOctetString.finalizeTag();
        // Top level sequence tags
        derPriKey.addChildTag(derZeroInt, true);
        derPriKey.addChildTag(derRsaAlgo, false);
        derPriKey.addChildTag(derPriKeyInfoOctetString, false);
        derPriKey.finalizeTag();
        // Now write tags and data to output buffer
        currResBuffOff = 0;
        currResBuffOff = derPriKey.writeObject(eeResBuff, currResBuffOff, null,(short)0);        
        currResBuffOff = derZeroInt.writeFixedObject(eeResBuff, currResBuffOff); // Version
        currResBuffOff = derRsaAlgo.writeFixedObject(eeResBuff, currResBuffOff);
        currResBuffOff = derPriKeyInfoOctetString.writeObject(eeResBuff, currResBuffOff,null, (short)0);        
        currResBuffOff = derPriKeyInfo.writeObject(eeResBuff, currResBuffOff,null, (short)0);
        currResBuffOff = derZeroInt.writeFixedObject(eeResBuff, currResBuffOff); // Version
        currResBuffOff = derPriKeyModulus.writeObject(eeResBuff, currResBuffOff,priModulus, keySize);
        currResBuffOff = derZeroInt.writeFixedObject(eeResBuff, currResBuffOff); // public exponent
        currResBuffOff = derPriKeyExponent.writeObject(eeResBuff, currResBuffOff,priExponent, keySize);
        currResBuffOff = derZeroInt.writeFixedObject(eeResBuff, currResBuffOff); // public exponent
        currResBuffOff = derZeroInt.writeFixedObject(eeResBuff, currResBuffOff); // public exponent
        currResBuffOff = derZeroInt.writeFixedObject(eeResBuff, currResBuffOff); // public exponent
        currResBuffOff = derZeroInt.writeFixedObject(eeResBuff, currResBuffOff); // public exponent
        currResBuffOff = derZeroInt.writeFixedObject(eeResBuff, currResBuffOff); // public exponent
        // size buffer for output
        currResBuffSize = currResBuffOff;
        currResBuffOff = 0;
        
    }
//    /**
//     * Build DER encoded private key in EEPROM result (output) buffer.
//     * @param kp KeyPair containing private key to return
//     */
//    private void getRsaPriKey(KeyPair kp) {
//        rPri = (RSAPrivateKey)kp.getPrivate();
//        rPri.getModulus(priModulus, (short)0);
//        rPri.getExponent(priExponent, (short)0);
//        keySize = (short)(rPri.getSize() / 8);
//        // Setup innermost "terminal" DER tags
//        derPriKeyModulus.setTagDataLength(priModulus, keySize);
//        derPriKeyExponent.setTagDataLength(priExponent, keySize);
//        // Innermost enclosing tags
//        derPriKeyInfo.addChildTag(derPriKeyModulus, true);
//        derPriKeyInfo.addChildTag(derPriKeyExponent, false);
//        derPriKeyInfo.finalizeTag();
//        // Top level sequence tags
//        derPriKey.addChildTag(derRsaAlgo, true);
//        derPriKey.addChildTag(derPriKeyInfo, false);
//        derPriKey.finalizeTag();
//        // Now write tags and data to output buffer
//        currResBuffOff = 0;
//        currResBuffOff = derPriKey.writeObject(eeResBuff, currResBuffOff, null,(short)0);
//        currResBuffOff = derRsaAlgo.writeObject(eeResBuff, currResBuffOff,rsaCommonSeg2, (short)rsaCommonSeg2.length);
//        currResBuffOff = derPriKeyInfo.writeObject(eeResBuff, currResBuffOff,null, (short)0);
//        currResBuffOff = derPriKeyModulus.writeObject(eeResBuff, currResBuffOff,priModulus, keySize);
//        currResBuffOff = derPriKeyExponent.writeObject(eeResBuff, currResBuffOff,priExponent, keySize);
//        // size buffer for output
//        currResBuffSize = currResBuffOff;
//        currResBuffOff = 0;
//        
//    }
    private void doRsaKeyGen(KeyPair kp) {
        try {
            kp.genKeyPair();
        } catch (CryptoException ce) {
            ISOException.throwIt(getKgException(ce));
        }
    }
    /*
    private void doRsaKeyGen(APDU apdu, KeyPair kp) {
        try {
            kp.genKeyPair();
        } catch (CryptoException ce) {
            ISOException.throwIt(getKgException(ce));
        }
        rsa1024pub = (RSAPublicKey)kp.getPublic();
        rsa1024pub.getModulus(pubModulus, (short)0);
        rsa1024pub.getExponent(pubExponent, (short)0);
        keySize = (short)(rsa1024pub.getSize() / 8);
        rsa1024pri = (RSAPrivateKey)kp.getPrivate();
        rsa1024pri.getModulus(priModulus, (short)0);
        rsa1024pri.getExponent(priExponent, (short)0);
        // initialize all simple tags for current key
        derRsaAlgo.setTagDataLength(rsaCommonSeg2, (short)rsaCommonSeg2.length);
        derPubKeyModulus.setTagDataLength(pubModulus, keySize);
        derPubKeyExponent.setTagDataLength(pubExponent, (short)3);
        derPubKeyInfo.addChildTag(derPubKeyModulus, true);
        derPubKeyInfo.addChildTag(derPubKeyExponent, false);
        derPubKeyInfo.finalizeTag();
        derPubKey.addChildTag(derRsaAlgo, true);
        derPubKey.addChildTag(derPubKeyInfo, false);
        derPubKey.finalizeTag();

         derPriKeyModulus.setTagDataLength(priModulus, keySize);
         derPriKeyExponent.setTagDataLength(priExponent, keySize);
         derPriKeyInfo.addChildTag(derPriKeyModulus, true);
         derPriKeyInfo.addChildTag(derPriKeyExponent, false);
         derPriKeyInfo.finalizeTag();
         derPriKey.addChildTag(derRsaAlgo, true);
         derPriKey.addChildTag(derPriKeyInfo, false);
         derPriKey.finalizeTag();


        
         currResBuffOff = 0;
         currResBuffOff = derPubKey.writeObject(eeResBuff, currResBuffOff, null, (short)0);
         currResBuffOff = derRsaAlgo.writeObject(eeResBuff, currResBuffOff, rsaCommonSeg2, (short)rsaCommonSeg2.length);
         currResBuffOff = derPubKeyInfo.writeObject(eeResBuff, currResBuffOff, null, (short)0);
         currResBuffOff = derPubKeyModulus.writeObject(eeResBuff, currResBuffOff, pubModulus, keySize);
         currResBuffOff = derPubKeyExponent.writeObject(eeResBuff, currResBuffOff, pubExponent, (short)3);

         currResBuffOff = derPriKey.writeObject(eeResBuff, currResBuffOff, null,(short)0);
         currResBuffOff = derRsaAlgo.writeObject(eeResBuff, currResBuffOff,rsaCommonSeg2, (short)rsaCommonSeg2.length);
         currResBuffOff = derPriKeyInfo.writeObject(eeResBuff, currResBuffOff,null, (short)0);
         currResBuffOff = derPriKeyModulus.writeObject(eeResBuff, currResBuffOff,priModulus, keySize);
         currResBuffOff = derPriKeyExponent.writeObject(eeResBuff, currResBuffOff,priExponent, keySize);

        currResBuffSize = currResBuffOff;
        currResBuffOff = 0;

     }
    */
    private void doGetCapabilities(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_P1] != 0 || buffer[ISO7816.OFFSET_P2] != 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        short le = apdu.setOutgoing();
        if (le != 256 && le != N_ALGO_IDS){
               ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength((byte)((N_ALGO_IDS) & 0xff));
                        
        Util.arrayCopy(algos, (short)0, buffer, (short)0, N_ALGO_IDS);
        apdu.sendBytes((short)0, N_ALGO_IDS);
        
    }
    private void sendData(APDU apdu) {
            // Return data is always in the test results eeprom buffer
            if (eeResBuff == null) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            short available = (short)(currResBuffSize - currResBuffOff);
            if (available < 0) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            boolean multiResponse = available > MAX_SEND_SIZE;
            short sendLen = multiResponse ? MAX_SEND_SIZE : available;
            
            short le = apdu.setOutgoing();
            if (le == 0)
                le = MAX_SEND_SIZE;
            if (sendLen > le)
                sendLen = le;
            apdu.setOutgoingLength(sendLen);
            apdu.sendBytesLong(eeResBuff, currResBuffOff, sendLen);
            currResBuffOff += sendLen;
            available -= sendLen;
            if (available == 0) {
                    // reset buffer if done
                    currResBuffOff = 0;
                    return;
            }
            short nextSendSize = (available > MAX_SEND_SIZE) ? MAX_SEND_SIZE_INDICATOR : available; 
            if (nextSendSize > le) {
                nextSendSize = le;
            }
            short sw_available = (short)(0x6100 | nextSendSize);
            ISOException.throwIt(sw_available);     
    }
    private static short getKgException(CryptoException ce) {
            return (short)(KG_EX_SHORT | (ce.getReason() & 0x0f));
    }
}
