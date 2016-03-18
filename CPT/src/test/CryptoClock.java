
package test;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyPair;
import javacard.security.Key;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.CryptoException;
import javacard.security.RandomData;
import javacard.security.RSAPublicKey;
import javacard.security.RSAPrivateKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class CryptoClock extends Applet {
	static private final short CPT_EX_SHORT = 0x6F00; 
	static private final short CPT_EX_HIBYTE = 0x6F;
	// cryptography exceptions
	static private final short CPT_CE_ILLEGAL_VAL = 0x01;
	static private final short CPT_CE_UNITIALIZED_KEY = 0x02;
	static private final short CPT_CE_UNK_ALGO = 0x03;
	static private final short CPT_CE_INV_INIT = 0x04;
	static private final short CPT_CE_ILLEGAL_USE = 0x05;
	static private final short CPT_CE_ILLEGAL_DP = 0x06;
	
	static private final short MAX_SEND_SIZE = 256;
	static private final short MAX_SEND_SIZE_INDICATOR = 0;
	static private final byte ALG_NONE   = 0;
	static private final byte ALG_SHA1   = 1;
	static private final byte ALG_SHA256 = 2;
	static private final byte ALG_SHA384 = 3;
	static private final byte ALG_RSA1   = 4;
	static private final byte ALG_RSA2   = 5;
	static private final byte ALG_EC224  = 6;
	static private final byte ALG_EC256  = 7;
	static private final byte ALG_EC384  = 8;
	static private final byte ALG_AES128  = 9;
	static private final byte ALG_AES192  = 10;
	static private final byte ALG_AES256  = 11;
	static private final byte ALG_SEC_RAND = 12;
	static private final byte ALG_EC_SVDP_DH = 13;
	static private final byte ALG_EC_SVDP_DH_PLAIN = 14;
	static private final byte ALG_RSA3   = 15; // TODO: move to other RSA after versioning test
	static private final byte N_ALGO_IDS  = 16;
	
	static private final byte BLK_SIZE_256  = (byte)0x00;
	static private final byte BLK_SIZE_NONE = (byte)0xFF;
	static private final short DATA_CAPACITY = 2048;
	static private final short RESULTS_CAPACITY = 384;
	
	static private final short TDS_INIT_00 = 0;
	static private final short TDS_INIT_INC = 0x40;
	static private final short TDS_INIT_RAND = 0x80;
	static private final short TDS_INIT_CMD = 0xC0;
	static private final short TDS_INIT_MASK = 0xC0;
	//static private final short DATA_SRC_MAP[] = { TDS_INIT_00, TDS_INIT_INC, TDS_INIT_RAND, TDS_INIT_CMD };
	
	static private final byte CAP_SUCCESS = 0x00;
	static private final byte CAP_NOT_INITIALIZED = 0x2;
	static private final byte CAP_NOT_SUPPORTED = 0x11;
	static private final byte CAP_EXE_INIT_ERR = 0x12;
	static private final byte CAP_EXE_ERR = 0x13;
	static private final byte CAP_ALGO_PARAM_ERR = 0x14;
	
	static private final byte TID_NOOP       = 0x00;
	static private final byte TID_WRITE      = 0x10;
	static private final byte TID_READ       = 0x20;
	static private final byte TID_PARSE_CERT = 0x30;
	static private final byte TID_COMPUTE    = 0x40;
	static private final byte TID_PUB_COMPUTE= 0x50;
	static private final byte TID_KEY_GEN    = 0x60;
	static private final byte TID_KEY_AGREEMENT_HASHED = 0x70;
	static private final byte TID_KEY_AGREEMENT_PLAIN = (byte)0x80;
	static private final byte TID_SIGN  = (byte)0x90;
	static private final short N_IDS    = 10;
	
	static private final byte CC_CLA_BYTE = (byte)0x80;
	static private final byte INS_CAPABILITIES = 0x10;
	static private final byte INS_INITDATA     = 0x12;
	static private final byte INS_PERFORM_TEST = 0x14;
	static private final byte INS_GET_RESULT   = 0x16;
	static private final byte INS_GET_DATA = 0x18;
	static private final byte INS_GET_ALGORITHM_PARAMETERS = 0x1A;
	static private final byte INS_SET_ALGORITHM_PARAMETERS = 0x1C;
	static private final byte INS_GET_RESPONSE = (byte)0xC0;
	static private final byte INS_WRITE_DATA = 0x20;
	static private final byte INS_READ_DATA = 0x22;
	
	static private final byte DO_TEST_BUFF = 0x40; // Pre-allocated EEPROM Buffer
	static private final byte DO_RESULT_BUFF = 0x41; // Pre-allocated EEPROM Buffer
	static private final byte DO_RAM_BUFF = 0x42; // dynamically allocated 
	
	
	static private final byte PT_P1_DATA_SRC = (byte)0x80;
	static private final byte PT_P1_RESULTS_DST = 0x40;
	static private final byte PT_DATA_SRC_CMD = 0x00;
	static private final byte PT_DATA_SRC_BUF = (byte)0x80;
	static private final byte PT_DATA_DEST_RESP = 0x00;
	static private final byte PT_DATA_DEST_BUF = 0x40;
	
	static private final byte AP_EC_DOMAIN_A = 0;
	static private final byte AP_EC_DOMAIN_B = 1;
	static private final byte AP_EC_DOMAIN_FIELD = 2;
	static private final byte AP_EC_DOMAIN_G = 3;
	static private final byte AP_EC_DOMAIN_K = 4;
	static private final byte AP_EC_DOMAIN_R = 5;
	static private final byte AP_EC_DOMAIN_PRI_S = 6;
	static private final byte AP_EC_DOMAIN_PUB_W = 7;
	
	static private final byte AP_KEY_PRI_MOD = 8;
	static private final byte AP_KEY_PRI_EXP = 9;
	static private final byte AP_KEY_PUB_MOD = 10;
	static private final byte AP_KEY_PUB_EXP = 11;
	static private final byte AP_KEY_SECRET  = 12;
	static private final byte AP_X509_CERT   = 13;
	static private final byte AP_EC_CVC      = 14;
	static private final byte AP_AGREEMENT_KEY_LEN = 15;
	static private final short MAX_ALGO_PARAMS = 16;
	
	
	// Capabilities response structure defined here
	//static private final short N_ALGOS = 8;
	static private final short CAP_CAPACITY_OFFSET = 0;
	static private final short CAP_CAPACITY_SIZE = 2;
	static private final short CAP_MAX_INCOMING_BLK_SIZE_OFFSET = CAP_CAPACITY_OFFSET + CAP_CAPACITY_SIZE;
	static private final short CAP_MAX_INCOMING_BLK_SIZE_SIZE = 2;	
	static private final short CAP_MAX_OUTGOING_BLK_SIZE_OFFSET = CAP_MAX_INCOMING_BLK_SIZE_OFFSET + CAP_MAX_INCOMING_BLK_SIZE_SIZE;
	static private final short CAP_MAX_OUTGOING_BLK_SIZE_SIZE = 2;	
	static private final short CAP_JC_VERSION_OFFSET = CAP_MAX_OUTGOING_BLK_SIZE_OFFSET + CAP_MAX_OUTGOING_BLK_SIZE_SIZE;
	static private final short CAP_JC_VERSION_SIZE = 2;	
	static private final short CAP_AVAIL_PERSIST_MEM_OFFSET = CAP_JC_VERSION_OFFSET + CAP_JC_VERSION_SIZE;
	static private final short CAP_AVAIL_PERSIST_MEM_SIZE = 2;	
	static private final short CAP_AVAIL_TRANS_DESEL_MEM_OFFSET = CAP_AVAIL_PERSIST_MEM_OFFSET + CAP_AVAIL_PERSIST_MEM_SIZE;
	static private final short CAP_AVAIL_TRANS_DESEL_MEM_SIZE = 2;	
	static private final short CAP_AVAIL_TRANS_RESET_MEM_OFFSET = CAP_AVAIL_TRANS_DESEL_MEM_OFFSET + CAP_AVAIL_TRANS_DESEL_MEM_SIZE;
	static private final short CAP_AVAIL_TRANS_RESET_MEM_SIZE = 2;
	static private final short CAP_CONNECT_PROT_MEDIA_OFFSET = CAP_AVAIL_TRANS_RESET_MEM_OFFSET + CAP_AVAIL_TRANS_RESET_MEM_SIZE;
	static private final short CAP_CONNECT_PROT_MEDIA_SIZE = 1;
	static private final short CAP_N_ALGOS_OFFSET = CAP_CONNECT_PROT_MEDIA_OFFSET + CAP_CONNECT_PROT_MEDIA_SIZE;
	static private final short CAP_N_ALGOS_SIZE = 1;
	static private final short CAP_ALGO_ARRAY_OFFSET = CAP_N_ALGOS_OFFSET + CAP_N_ALGOS_SIZE;
	static private final short CAP_ALGO_ARRAY_SIZE = N_ALGO_IDS;

	static private final short CAP_SIZE = CAP_ALGO_ARRAY_OFFSET + CAP_ALGO_ARRAY_SIZE;
	
	
	static private MessageDigest sha1Digest = null;
	static private MessageDigest sha256Digest = null;
	static private MessageDigest sha384Digest = null;
	static private MessageDigest sha512Digest = null;
	
	static private Key aes128 = null;
	static private Key aes192 = null;
	static private Key aes256 = null;
	static private byte[] aes128Km = null;
	static private byte[] aes192Km = null;
	static private byte[] aes256Km = null;
	static private byte[] aesIv = null;
	static private Key rsa1024pri = null;
	static private Key rsa1024pub = null;
	static private Key rsa2048pri = null;
	static private Key rsa2048pub = null;
	static private Key rsa3072pri = null;
	static private Key rsa3072pub = null;
	
	// 'context' keys
	static private Key pubKey = null;
	static private Key priKey = null;
	static private KeyPair kaPair = null;

	static private Key ec224pri = null;
	static private Key ec224pub = null;
	static private Key ec256pri = null;
	static private Key ec256pub = null;
	static private Key ec384pri = null;
	static private Key ec384pub = null;
		
	static private KeyPair rsa1024Kp = null;
	static private KeyPair rsa2048Kp = null;
	static private KeyPair rsa3072Kp = null;
	static private KeyPair ec224Kp = null;
	static private KeyPair ec256Kp = null;
	static private KeyPair ec384Kp = null;
	
	static private KeyAgreement ecSvdpDh224 = null;
	static private KeyAgreement ecSvdpDhPlain224 = null;
	static private KeyAgreement ecSvdpDh256 = null;
	static private KeyAgreement ecSvdpDhPlain256 = null;
	static private KeyAgreement ecSvdpDh384 = null;
	static private KeyAgreement ecSvdpDhPlain384 = null;
	
	static private Signature ecSig = null;
//	static private Signature ec256Sig = null;
//	static private Signature ec384Sig = null;
	
	static private Signature rsaSig = null;
//	static private Signature rsa2048Sig = null;
//	static private Signature rsa3072Sig = null;
	
	static private RandomData srng = null;
	static private short maxReceiveBlockSize = BLK_SIZE_256;
	static private short maxSendBlockSize = BLK_SIZE_256;
	static short currTestDataSize = 0;
	static short currResultsDataSize = 0;
	static short nCurrTestDataBlks = 0; //(short)(currTestDataSize / BLK_SIZE_256);
	static short currTestDataWriteOffset = 0;
	static short currTestResultsReadOffset = 0;
	static byte[] currTestData;
	static byte[] currTestResults;
	static short maxTestDataSize;
	static short maxResultsDataSize;
	static boolean chainingReads = false;
/*	
	static final short BUF_CAPACITY = 0;
	static final short BUF_SIZE     = 1;
	static final short BUF_SEND_BLK_SIZE = 2;
	static final short BUF_CURR_OFFSET = 3;
	static final short BUFFERCTL_SIZE = 4; 
*/	
/*---------	
----*/	
	static private final short DATA_BUF = 0;
	static private final short RESULTS_BUF = 1;
	// Algorithm to block size Map table
	static private final short[] algoBlkSizeMap = {
		64,          // ALG_NONE
		20,           // ALG_SHA1 (20 bytes)
		32,           // ALG_SHA256 (32 bytes)
		48,           // ALG_SHA384 (48 bytes)
		128,          // ALG_RSA1 (128 bytes)
		256,          // ALG RSA2 (256 bytes)
		28,           // ALG_EC224
		32,           // ALG_EC256
		48,           // ALG_EC384
		16,			  // ALG_AES128
		16,           // ALG_AES192
		16,           // ALG_AES256
		16,			  // ALG_SEC_RAND
		20,           // ALG_EC_SVDP_DH - SHA1 result
		48,            // ALG_EC_SVDP_DH_PLAIN - Raw result. Use key block size. ec384 max
		256          // ALG RSA2 (256 bytes) TODO: move inline with other RSA after versioning
	};
	static private byte[] algos;
	static private short[] testDataBufferCtl = { DATA_CAPACITY, 2048, 255, 0 };
	static private short[] resultsDataBufferCtl = {RESULTS_CAPACITY, 300, 255, 0 };
	
	static private byte[] testDataEepromBuffer;
	static private byte[] testDataRamBuffer;
	static private byte[] testResultsEepromBuffer;
	static private byte[] testResultsRamBuffer;
	
	/*
	static private byte[] testData = new byte[DATA_CAPACITY];
	static private byte[] resultsData = new byte[RESULTS_CAPACITY];
	static private byte[][] bufferData = {testData, resultsData};
	static private short activeSendBuffer = -1; // Active Buffer src
	*/
	
	// These values set in the init test data command
	// and reset  
	static private short activeTestId = -1;
	static private short activeTestAlgorithm = -1;
	
	// Java 3 constants - some may work even in jc2.2
	static final private byte JC3_SHA256_ID = 4;
	static final private byte JC3_SHA384_ID = 5;
	static final private byte JC3_AES192_ID = 19;
	static final private byte JC3_AES256_ID = 21;
	static final private byte JC3_AES_128BS_NP_ID = 14;
	static final private byte JC3_AES_ECB_P5 = 27;
	static final private byte JC3_EC_SVDP_DH_PLAIN_ID = 3;
	
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		CryptoClock cc = new CryptoClock();
		// Instantiate class scope persistent arrays
		testDataEepromBuffer = new byte[DATA_CAPACITY];
		testResultsEepromBuffer = new byte[RESULTS_CAPACITY];
		testResultsRamBuffer = JCSystem.makeTransientByteArray(RESULTS_CAPACITY, JCSystem.CLEAR_ON_RESET);
		aes128Km = new byte[16];
		aes192Km = new byte[24];
		aes256Km = new byte[32];
		aesIv = new byte[] {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		
		algos = new byte[N_ALGO_IDS];
		for (short i = 0; i < N_ALGO_IDS; i++) { algos[i] = (byte)0xff; }
		//bufferCtl = new short[2][];
		//bufferCtl[DATA_BUF] = testDataBufferCtl;
		//bufferCtl[RESULTS_BUF] = resultsDataBufferCtl;
		// Allocate space for all keys that will be used
		algos[ALG_NONE] = 0; // plain r/w always supported
		try {
			sha1Digest = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
			algos[ALG_SHA1] = 0;
		} catch (CryptoException ce) { 
			algos[ALG_SHA1] = (byte)ce.getReason(); 
		}
		try {
			sha256Digest = MessageDigest.getInstance(JC3_SHA256_ID, false);
			algos[ALG_SHA256] = 0;
		} catch (CryptoException ce) { 
			algos[ALG_SHA256] = (byte)ce.getReason(); 
		}
		try {
			sha384Digest = MessageDigest.getInstance(JC3_SHA384_ID, false);
			algos[ALG_SHA384] = 0;
		} catch (CryptoException ce) { 
			algos[ALG_SHA384] = (byte)ce.getReason(); 
		}
		try {
			aes128 = KeyBuilder.buildKey(KeyBuilder.TYPE_AES, (short)128, false);
			if (initializeAesKey((AESKey)aes128, aes128Km)) {
				algos[ALG_AES128] = CAP_SUCCESS;
			} else {
				algos[ALG_AES128] = CAP_NOT_INITIALIZED;
			}
		} catch (CryptoException ce) { 
			algos[ALG_AES128] = (byte)ce.getReason();
		}
		try {
			aes192 = KeyBuilder.buildKey(KeyBuilder.TYPE_AES, (short)192, false);
			//if (initializeAesKey((AESKey)aes192)) {
			if (initializeAesKey((AESKey)aes192, aes192Km)) {
				algos[ALG_AES192] = CAP_SUCCESS;
			} else {
				algos[ALG_AES192] = CAP_NOT_INITIALIZED;
			}
		} catch (CryptoException ce) { 
			algos[ALG_AES192] = (byte)ce.getReason();
		}
		try {
			aes256 = KeyBuilder.buildKey(KeyBuilder.TYPE_AES, (short)256, false);
//			if (initializeAesKey((AESKey)aes256)) {
			if (initializeAesKey((AESKey)aes256, aes256Km)) {
				algos[ALG_AES256] = CAP_SUCCESS;
			} else {
				algos[ALG_AES256] = CAP_NOT_INITIALIZED;
			}
		} catch (CryptoException ce) { 
			algos[ALG_AES256] = (byte)ce.getReason();
		}
		try {
			rsa1024pri = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,
											 KeyBuilder.LENGTH_RSA_1024, false);
			rsa1024pub = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,
					                         KeyBuilder.LENGTH_RSA_1024, false);			
			rsa1024Kp = new KeyPair((RSAPublicKey)rsa1024pub, (RSAPrivateKey)rsa1024pri);
			algos[ALG_RSA1] = CAP_NOT_INITIALIZED;
		} catch (CryptoException ce) { 
			algos[ALG_RSA1] = (byte)ce.getReason(); 
		}
		try {
			rsa2048pri = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,
					 KeyBuilder.LENGTH_RSA_2048, false);
			rsa2048pub = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,
                    KeyBuilder.LENGTH_RSA_2048, false);			
			//rsa2048Kp = new KeyPair(KeyPair.ALG_RSA, (short)rsa2048pub.getSize());
			rsa2048Kp = new KeyPair((RSAPublicKey)rsa2048pub, (RSAPrivateKey)rsa2048pri);
			algos[ALG_RSA2] = CAP_NOT_INITIALIZED;
		} catch (CryptoException ce) { 
			algos[ALG_RSA2] = (byte)ce.getReason(); 
		}
		try {
			rsa3072pri = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,
					//KeyBuilder.LENGTH_RSA_3072, false);
			 		(short)3072, false);
			rsa3072pub = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,
                    //KeyBuilder.LENGTH_RSA_2048, false);
					(short)3072, false);
			rsa3072Kp = new KeyPair((RSAPublicKey)rsa3072pub, (RSAPrivateKey)rsa3072pri);
			algos[ALG_RSA3] = CAP_NOT_INITIALIZED;
		} catch (CryptoException ce) { 
			algos[ALG_RSA3] = (byte)ce.getReason(); 
		}
		try {
			ec224pri = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short)224, false);
			ec224pub = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short)224, false);
			ec224Kp = new KeyPair((ECPublicKey)ec224pub, (ECPrivateKey)ec224pri);
			algos[ALG_EC224] = CAP_NOT_INITIALIZED;
		} catch (CryptoException ce) { 
			algos[ALG_EC224] = (byte)ce.getReason(); 
		}
		try {
			ec256pri = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short)256, false);
			ec256pub = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short)256, false);
			ec256Kp = new KeyPair((ECPublicKey)ec256pub, (ECPrivateKey)ec256pri);
			algos[ALG_EC256] = CAP_NOT_INITIALIZED;
		} catch (CryptoException ce) { 
			algos[ALG_EC256] = (byte)ce.getReason(); 
		}
		try {
			ec384pri = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short)384, false);
			ec384pub = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short)384, false);
			ec384Kp = new KeyPair((ECPublicKey)ec384pub, (ECPrivateKey)ec384pri);
			algos[ALG_EC384] = CAP_NOT_INITIALIZED;
		} catch (CryptoException ce) { 
			algos[ALG_EC384] = (byte)ce.getReason(); 
		}
		try {
			ecSig = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
		} catch (CryptoException ce) {
			// TODO: ignore here. Don't have separate support for sig support 
		}
		try {
			rsaSig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		} catch (CryptoException ce) {
			// TODO: ignore here. Don't have separate support for sig support 
		}
		try {
			ecSvdpDh224 = (KeyAgreement)KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
			ecSvdpDh256 = (KeyAgreement)KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
			ecSvdpDh384 = (KeyAgreement)KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
			algos[ALG_EC_SVDP_DH] = CAP_NOT_INITIALIZED; // initialize after key initialized
			//ecSvdpDhPlain256 = (KeyAgreement)KeyAgreement.getInstance(JC3_EC_SVDP_DH_PLAIN_ID, false);
			//algos[ALG_EC_SVDP_DH_PLAIN] = CAP_NOT_INITIALIZED; // initialize after key initialized
		} catch (CryptoException ce) { 
			algos[ALG_EC_SVDP_DH] = (byte)ce.getReason(); 
		} 
		try {
		//rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
			srng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
			algos[ALG_SEC_RAND] = 0;
		} catch (CryptoException ce) { 
			algos[ALG_SEC_RAND] = (byte)ce.getReason(); 
		}
		
		cc.register(bArray, (short)(bOffset + 1), bArray[bOffset]);
	}

	private CryptoClock() {
	}
		
	public void process(APDU apdu) {
		// No applet specific processing for SELECT command
		if (selectingApplet()) {
//			apdu.setOutgoingLength((short)0);
			return;
		}
		
		byte[] buffer = apdu.getBuffer();
		
		if (buffer[ISO7816.OFFSET_CLA] != CC_CLA_BYTE) {
			// also support interindustry GET RESPONSE command
			if (buffer[ISO7816.OFFSET_INS] != (byte)INS_GET_RESPONSE) {
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);				
				//ISOException.throwIt((short)(ISO7816.SW_UNKNOWN + (short)0x77));
			}
		}
		
		switch (buffer[ISO7816.OFFSET_INS]) {
		case INS_CAPABILITIES:
			getCapabilities(apdu);
			return;
		case INS_INITDATA:
			initTestData(apdu);
			return;
		case INS_PERFORM_TEST:
			performTest(apdu);
			return;
		case INS_GET_DATA:
			setResultBuffFromTest();
			sendData(apdu);
			return;
		case INS_GET_ALGORITHM_PARAMETERS:
			getAlgoParams(apdu);
			if (currResultsDataSize > 0) {
				sendData(apdu);
			}
			return;
		case INS_SET_ALGORITHM_PARAMETERS:
			setAlgoParams(apdu);
			return;
		case INS_GET_RESULT:
			sendData(apdu);
			return;
		case INS_GET_RESPONSE:
			if (buffer[ISO7816.OFFSET_P1] != 0 || buffer[ISO7816.OFFSET_P2] != 0) {
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			}
//			if((buffer[ISO7816.OFFSET_LC] & 0xff) != 0) {
//				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);				
//			}
			
			sendData(apdu);
			return;
		default:
			// Unknown instruction
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
		
	}
	private void updateKeyInitialization() {
		
		algos[ALG_RSA1] = getKeyStatus(rsa1024Kp);
		algos[ALG_RSA2] = getKeyStatus(rsa2048Kp);
		algos[ALG_RSA3] = getKeyStatus(rsa3072Kp);
		algos[ALG_AES128] = getKeyStatus(aes128);
		algos[ALG_AES192] = getKeyStatus(aes192);
		algos[ALG_AES256] = getKeyStatus(aes256);
		
		algos[ALG_EC224] = getKeyStatus(ec224Kp);
		algos[ALG_EC256] = getKeyStatus(ec256Kp);
		algos[ALG_EC384] = getKeyStatus(ec384Kp);

		
	}
	private byte getKeyStatus(Object keyObj) {
		
		try {
			if (keyObj instanceof KeyPair) {
				if (!(((KeyPair)keyObj).getPrivate().isInitialized())) {
					return CAP_NOT_INITIALIZED;
				}
				if (!(((KeyPair)keyObj).getPublic().isInitialized())) {
					return CAP_NOT_INITIALIZED;
				}
				return CAP_SUCCESS; 
			}
			// Must be key
			return ((Key)keyObj).isInitialized() ? CAP_SUCCESS : CAP_NOT_INITIALIZED;
		} catch (CryptoException e) {
			return (byte)(e.getReason() & 0xff);
		} catch (Exception e) {
			return CAP_NOT_SUPPORTED;
		}
		
		//return CAP_SUCCESS; // test
	} 
	private void getCapabilities(APDU apdu) {
		
	  // Update initialized status of Key algos.
	  updateKeyInitialization();
	  byte[] buffer = apdu.getBuffer();
	  if (buffer[ISO7816.OFFSET_P1] != 0 || buffer[ISO7816.OFFSET_P2] != 0) {
		  ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
	  }
	  short le = apdu.setOutgoing();
	  if (le != 256 && le != CAP_SIZE){
		 ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	  }
	  apdu.setOutgoingLength((byte)((CAP_SIZE) & 0xff));
	  
	  Util.setShort(buffer, (short)CAP_CAPACITY_OFFSET, DATA_CAPACITY);
	  Util.setShort(buffer, (short)CAP_MAX_INCOMING_BLK_SIZE_OFFSET, APDU.getInBlockSize());
	  Util.setShort(buffer, (short)CAP_MAX_OUTGOING_BLK_SIZE_OFFSET, APDU.getOutBlockSize());
	  Util.setShort(buffer, (short)CAP_JC_VERSION_OFFSET, JCSystem.getVersion());
	  Util.setShort(buffer, (short)CAP_AVAIL_PERSIST_MEM_OFFSET, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT));
	  Util.setShort(buffer, (short)CAP_AVAIL_TRANS_DESEL_MEM_OFFSET, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT));
	  Util.setShort(buffer, (short)CAP_AVAIL_TRANS_RESET_MEM_OFFSET, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET));
	  buffer[CAP_CONNECT_PROT_MEDIA_OFFSET] = APDU.getProtocol();
	  buffer[CAP_N_ALGOS_OFFSET] = (byte)(N_ALGO_IDS & 0xff);
	  	  
	  Util.arrayCopy(algos, (short)0, buffer, CAP_ALGO_ARRAY_OFFSET, CAP_ALGO_ARRAY_SIZE);
	  apdu.sendBytes((short)0, CAP_SIZE);
	  
	}
	private void setTestBuffers(short testBuffId, short resultBuffId) {
		if (testBuffId == RESULTS_BUF) {
			currTestData = testResultsEepromBuffer;
			maxTestDataSize = RESULTS_CAPACITY;
		} else {
			currTestData = testDataEepromBuffer;
			maxTestDataSize = DATA_CAPACITY;
		}
		if (resultBuffId == DATA_BUF) {
			currTestResults = testDataEepromBuffer;
			maxResultsDataSize = DATA_CAPACITY;
		} else {
			currTestResults = testResultsEepromBuffer;
			maxResultsDataSize = RESULTS_CAPACITY;
		}
		
		currTestDataWriteOffset = 0;
		currTestResultsReadOffset = 0;
		
		currTestDataSize = 0; // manage when data added
		currResultsDataSize = 0;
	}
	private void setResultBuffFromTest() {
		currTestResults = currTestData;
		currTestResultsReadOffset = 0;
		currResultsDataSize = currTestDataSize;
		maxResultsDataSize = maxTestDataSize;
		if (currResultsDataSize > maxResultsDataSize) {
			ISOException.throwIt(ISO7816.SW_FILE_FULL);
		}
	}
	private void setAlgoParams(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short algo = (short)(buffer[ISO7816.OFFSET_P2]);
		short paramId = (short)(buffer[ISO7816.OFFSET_P1]);
		if (paramId >= MAX_ALGO_PARAMS ) {
			ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
		}
		short bytesRead = (short)(apdu.setIncomingAndReceive() & 0xff);
		if ((bytesRead == 0) || (bytesRead != (short)(buffer[ISO7816.OFFSET_LC]))) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		switch (buffer[ISO7816.OFFSET_P2]) {
		case ALG_EC224: 
			pubKey = ec224pub;
			priKey = ec224pri;
			break;
		case ALG_EC256: 
			pubKey = ec256pub;
			priKey = ec256pri;
			break;
		case ALG_EC384: 
			pubKey = ec384pub;
			priKey = ec384pri;
			break;
		case ALG_RSA1:
			pubKey = rsa1024pub;
			priKey = rsa1024pri;
			break;
		case ALG_RSA2:
			pubKey = rsa2048pub;
			priKey = rsa2048pri;
			break;
		case ALG_RSA3:
			pubKey = rsa3072pub;
			priKey = rsa3072pri;
			break;
		case ALG_AES128:
			priKey = aes128;
			break;
		case ALG_AES192:
			priKey = aes192;
			break;
		case ALG_AES256:
			priKey = aes256;
			break;
		default:
			break;
		}
		try {
			switch (paramId) {
			case AP_EC_DOMAIN_A:
				((ECPublicKey)pubKey).setA(buffer, ISO7816.OFFSET_CDATA, bytesRead);
				return;
			case AP_EC_DOMAIN_B:
				((ECPublicKey)pubKey).setB(buffer, ISO7816.OFFSET_CDATA, bytesRead);
				return;
			case AP_EC_DOMAIN_FIELD:
				((ECPublicKey)pubKey).setFieldFP(buffer, ISO7816.OFFSET_CDATA, bytesRead);
				return;
			case AP_EC_DOMAIN_G:
				((ECPublicKey)pubKey).setG(buffer, ISO7816.OFFSET_CDATA, bytesRead);
				return;
			case AP_EC_DOMAIN_K:
				short kVal = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
				((ECPublicKey)pubKey).setK(kVal);
				return;
			case AP_EC_DOMAIN_R:
				((ECPublicKey)pubKey).setR(buffer, ISO7816.OFFSET_CDATA, bytesRead);
				return;
			case AP_EC_DOMAIN_PRI_S:
				((ECPrivateKey)priKey).setS(buffer, ISO7816.OFFSET_CDATA, bytesRead);
				return;
			case AP_EC_DOMAIN_PUB_W:
				((ECPublicKey)pubKey).setW(buffer, ISO7816.OFFSET_CDATA, bytesRead);
				return;
			case AP_KEY_PUB_MOD:
				((RSAPublicKey)pubKey).setModulus(buffer, ISO7816.OFFSET_CDATA, bytesRead);
				return;
			case AP_KEY_PUB_EXP:
				((RSAPublicKey)pubKey).setExponent(buffer, ISO7816.OFFSET_CDATA, bytesRead);
				return;
			case AP_KEY_PRI_MOD:
				((RSAPrivateKey)priKey).setModulus(buffer, ISO7816.OFFSET_CDATA, bytesRead);
				return;
			case AP_KEY_PRI_EXP:
				((RSAPrivateKey)priKey).setExponent(buffer, ISO7816.OFFSET_CDATA, bytesRead);
				return;
			case AP_KEY_SECRET:
				((AESKey)priKey).setKey(buffer, ISO7816.OFFSET_CDATA);
				return;
			case AP_AGREEMENT_KEY_LEN:
				short kLen = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
				if (kLen == (short)224) {
					kaPair = ec224Kp;
				} else if (kLen == (short)256) {
					kaPair = ec256Kp;
				} else if (kLen == (short)384) {
					kaPair = ec384Kp;
				} else {
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				}
				return;
			}
		} catch (CryptoException ce) {
			ISOException.throwIt(getCptException(ce));
		}
	}
	private static short getCptException(CryptoException ce) {
		return (short)(CPT_EX_SHORT | (ce.getReason() & 0x0f));
	}
	private static boolean initializeAesKey(AESKey key, byte[] km) {
		try {
			//short keyLen = (short)(key.getSize() / 8);
			if (km == null || km.length == 0) {
				return false;
			}
			short keyLen = (short)(km.length);
			for (short i = 0; i < keyLen; i++) {
				//testDataEepromBuffer[i] = (byte)(i & 0xff);
				km[i] = (byte)(i & 0xff);
			}
			key.setKey(km, (short)0);
			return key.isInitialized();
		} catch (CryptoException e) {
			ISOException.throwIt(getCptException(e));
		}
		return false;
	}
	private  boolean initializeTestEcDh(KeyAgreement ka, ECPrivateKey pri) {
		// if key agreement, verify that the specified EC key has been initialized
		if (!pri.isInitialized()) {
			ISOException.throwIt((short)(CPT_EX_SHORT | CPT_CE_UNITIALIZED_KEY));
		}
		try {
			ka.init(pri);
			return true;
		} catch (CryptoException ce) {
			algos[activeTestAlgorithm] = (byte)(ce.getReason() & 0x0F);
			ISOException.throwIt((short)(CPT_EX_SHORT | ce.getReason()));
		} catch (Exception ex) {
			ISOException.throwIt((short)(CPT_EX_SHORT | 0x77));
		}
		return false;
	}
	private void getAlgoParams(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short algo = (short)(buffer[ISO7816.OFFSET_P2]);
		short paramId = (short)(buffer[ISO7816.OFFSET_P1]);
		if (paramId >= MAX_ALGO_PARAMS ) {
			ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
		}
		//setTestBuffers(DATA_BUF, RESULTS_BUF);
		
		switch (algo) {
		case ALG_EC224: 
			kaPair = ec224Kp;
			pubKey = kaPair.getPublic();
			priKey = kaPair.getPrivate();
			break;
		case ALG_EC256: 
			kaPair = ec256Kp;
			pubKey = ec256pub;
			priKey = ec256pri;
			break;
		case ALG_EC384: 
			kaPair = ec384Kp;
			pubKey = ec384pub;
			priKey = ec384pri;
			break;
		case ALG_RSA1:
			kaPair = rsa1024Kp;
			pubKey = rsa1024pub;
			priKey = rsa1024pri;
			break;
		case ALG_RSA2:
			kaPair = rsa2048Kp;
			pubKey = rsa2048pub;
			priKey = rsa2048pri;
			break;
		case ALG_RSA3:
			kaPair = rsa3072Kp;
			pubKey = rsa3072pub;
			priKey = rsa3072pri;
			break;
		case ALG_AES128:
			priKey = aes128;
			break;
		case ALG_AES192:
			priKey = aes192;
			break;
		case ALG_AES256:
			priKey = aes256;
			break;
		default:
			break;
		}
		try {
			switch (paramId) {
			case AP_EC_DOMAIN_A:
				currResultsDataSize = ((ECPublicKey)pubKey).getA(currTestResults, (short)0);
				break;
			case AP_EC_DOMAIN_B:
				currResultsDataSize = ((ECPublicKey)pubKey).getB(currTestResults, (short)0);
				break;
			case AP_EC_DOMAIN_FIELD:
				currResultsDataSize = ((ECPublicKey)pubKey).getField(currTestResults, (short)0);
				break;
			case AP_EC_DOMAIN_G:
				currResultsDataSize = ((ECPublicKey)pubKey).getG(currTestResults, (short)0);
				break;
			case AP_EC_DOMAIN_K:
				short kVal = ((ECPublicKey)pubKey).getK();
				Util.setShort(currTestResults, (short)0, kVal);
				currResultsDataSize = 2;
				break;
			case AP_EC_DOMAIN_R:
				currResultsDataSize = ((ECPublicKey)pubKey).getR(currTestResults, (short)0);
				break;
			case AP_EC_DOMAIN_PRI_S:
				currResultsDataSize = ((ECPrivateKey)priKey).getS(currTestResults, (short)0);
				break;
			case AP_EC_DOMAIN_PUB_W:
	//			if (!((ECPublicKey)pubKey).isInitialized()) {
	//				((KeyPair)kaPair).genKeyPair();
	//			}
				currResultsDataSize = ((ECPublicKey)kaPair.getPublic()).getW(currTestResults, (short)0);
				//currResultsDataSize = ((ECPublicKey)pubKey).getW(currTestResults, (short)0);k
				break;
			case AP_KEY_PUB_MOD:
				currResultsDataSize = ((RSAPublicKey)pubKey).getModulus(currTestResults, (short)0);
				break;
			case AP_KEY_PUB_EXP:
				currResultsDataSize = ((RSAPublicKey)pubKey).getExponent(currTestResults, (short)0);
				break;
			case AP_KEY_PRI_MOD:
				currResultsDataSize = ((RSAPrivateKey)priKey).getModulus(currTestResults, (short)0);
				break;
			case AP_KEY_PRI_EXP:
				currResultsDataSize = ((RSAPrivateKey)priKey).getExponent(currTestResults, (short)0);
				break;
			case AP_KEY_SECRET:
				currResultsDataSize = (short)((AESKey)priKey).getKey(currTestResults, (short)0);
				break;
			case AP_AGREEMENT_KEY_LEN:
				if (kaPair == null) {
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				}
				if (!((ECPublicKey)pubKey).isInitialized()) {
					((KeyPair)kaPair).genKeyPair();
				}
				short kaLen = kaPair.getPublic().getSize();
				Util.setShort(currTestResults, (short)0, kaLen);
				currResultsDataSize = 2;
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
					
			}
		} catch (CryptoException ce) {
			ISOException.throwIt(getCptException(ce));
		}
	}
private void initTestData(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		activeTestId = (short)(buffer[ISO7816.OFFSET_P2] & 0xf0);
		activeTestAlgorithm = (short)(buffer[ISO7816.OFFSET_P2] & 0x0f);
		if ((activeTestId >> 4) > N_IDS || activeTestAlgorithm > N_ALGO_IDS) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		if (activeTestId == TID_KEY_AGREEMENT_HASHED) {
			// if key agreement, verify that the specified EC key has been initialized
//			if (algos[activeTestAlgorithm] == CAP_SUCCESS) {
				try {
					switch(activeTestAlgorithm) {
					case ALG_EC224:
						initializeTestEcDh(ecSvdpDh224, (ECPrivateKey)ec224pri);
						break;
					case ALG_EC256:
						initializeTestEcDh(ecSvdpDh256, (ECPrivateKey)ec256pri);
						break;
					case ALG_EC384:
						initializeTestEcDh(ecSvdpDh384, (ECPrivateKey)ec384pri);
						break;
					default:
						ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
					}
				} catch (CryptoException ce) {
					algos[ALG_EC_SVDP_DH] = (byte)(ce.getReason() & 0x0F);
					ISOException.throwIt((short)(CPT_EX_SHORT | (ce.getReason() & 0x0f)));
				} 
//				catch (Exception ex) {
//					ISOException.throwIt((short)(CPT_EX_SHORT | 0x78));
//				}
//			}
		}
		short dataSource = (short)(buffer[ISO7816.OFFSET_P1] & TDS_INIT_MASK);
		setTestBuffers(DATA_BUF, RESULTS_BUF); // condition here based on input.
		if (dataSource == TDS_INIT_CMD) {
			//try {
			// Read source data for the test from the APDU command data
			currTestDataSize = apdu.setIncomingAndReceive();
			Util.arrayCopyNonAtomic(apdu.getBuffer(), ISO7816.OFFSET_CDATA, currTestData, (short)0, currTestDataSize);
			nCurrTestDataBlks = 1;
			//} 
			//catch (Exception ex) {
			//	ISOException.throwIt((short)(CPT_EX_SHORT | currTestDataSize));
			//}
		} else {
			// Initialize test data based on P1 & P2
			short blkSize = (short)(algoBlkSizeMap[activeTestAlgorithm]);
			short nBlks = (short)(buffer[ISO7816.OFFSET_P1] & 0x3F);
			short initDataSize = (short)(blkSize * nBlks);
			if (initDataSize > maxTestDataSize) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			switch(dataSource){
			case TDS_INIT_00:
				for (short i = 0; i < initDataSize; i++) {
					currTestData[i] = 0;
				}
				break;
			case TDS_INIT_INC:
				for (short j = 0; j < nBlks; j++) {
					for (short i = 0; i < blkSize; i += 2) {
						currTestData[j * blkSize + i] = (byte)(j & 0xff);
						currTestData[j * blkSize + i + 1] = (byte)(i & 0xff);
					}
				}
				break;
			case TDS_INIT_RAND:
				if (algos[ALG_SEC_RAND] != 0) {
					ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
				}
				srng.generateData(currTestData, (short)0, initDataSize);
				break;
			}
			currTestDataSize = initDataSize;
			nCurrTestDataBlks = nBlks;
			//setResultBuffFromTest();
		}
	}
	private void keyGenTest(KeyPair kp, short algo, short count) {
		for (short i = 0; i < count; i++) {
			kp.genKeyPair();
		}
	}
	private void performTest(APDU apdu) {
		if (activeTestId < 0) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		byte[] buffer = apdu.getBuffer();
		short numBytes = (short)(buffer[ISO7816.OFFSET_LC] & 0xff);
		short numIterations = (short)(((buffer[ISO7816.OFFSET_P1] & 0x3F) << 8) +
		                      (buffer[ISO7816.OFFSET_P2] & 0xFF));
		short bytesRead = 0;
		/* Do we want to do this???
		if (((buffer[ISO7816.OFFSET_P1] & (PT_P1_DATA_SRC)) & 0xff) == 
			                                (PT_DATA_SRC_BUF & 0xff)) {
			// test data (if required) is in test buffer
			if (numBytes > 0) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			
		
		} else {
			// test data (if required) in APDU command data
			bytesRead = (short)(apdu.setIncomingAndReceive() & 0xff);
			if (numBytes != bytesRead) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
		}
		*/
		// At this point any incoming data should be in the buffer array
		switch (activeTestId) {
		case TID_NOOP:
			// For no-op set activeSendBuffer to the input data;
			// numiterations ignored
			return;
			
		/*
		case TID_WRITE:
			
			(buffer[ISO7816.OFFSET_P2] & 0xf0);
			
			if (bytesRead > 0) {
				return;
			}
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			*/
		case TID_READ:
			/*
			short outSize = apdu.setOutgoing();
			apdu.setOutgoingLength(currTestDataSize);
			short firstSendSize = BLK_SIZE_256;
			if (firstSendSize < currTestDataSize) {
				firstSendSize = currTestDataSize;
			}
			*/
			//ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
			// numiterations ignored for cmds that send data
			setResultBuffFromTest();
			sendData(apdu);
			return;
		case TID_SIGN:
			try {
				switch (activeTestAlgorithm) {
				case ALG_RSA1:
					signTest(rsaSig, rsa1024pri, Signature.MODE_SIGN, numIterations);
					return;
				case ALG_RSA2:
					signTest(rsaSig, rsa2048pri, Signature.MODE_SIGN, numIterations);
					return;
				case ALG_RSA3:
					signTest(rsaSig, rsa3072pri, Signature.MODE_SIGN, numIterations);
					return;
				case ALG_EC224:
					signTest(ecSig, rsa1024pri, Signature.MODE_SIGN, numIterations);
					return;
				case ALG_EC256:
					signTest(ecSig, rsa1024pri, Signature.MODE_SIGN, numIterations);
					return;
				case ALG_EC384:
					signTest(ecSig, rsa1024pri, Signature.MODE_SIGN, numIterations);
					return;
					
				default:
					ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
				}
			} catch (CryptoException ce) {
				ISOException.throwIt(getCptException(ce));
			}
			break;
		case TID_KEY_GEN:
			byte jcAlg = 0;
			//if (algos[activeTestAlgorithm] != 0) {
			//	ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
			//}
			try {
				switch (activeTestAlgorithm) {
				case ALG_RSA1:
					keyGenTest(rsa1024Kp, ALG_RSA1, numIterations);
					return;
				case ALG_RSA2:
					keyGenTest(rsa2048Kp, ALG_RSA2, numIterations);
					return;
				case ALG_RSA3:
					keyGenTest(rsa3072Kp, ALG_RSA3, numIterations);
					return;
				case ALG_EC224:
					keyGenTest(ec224Kp, ALG_EC224, numIterations);
					return;
				case ALG_EC256:
					keyGenTest(ec256Kp, ALG_EC256, numIterations);
					return;
				case ALG_EC384:
					keyGenTest(ec384Kp, ALG_EC384, numIterations);
					return;
					
				default:
					ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
				}
			} catch (CryptoException ce) {
				ISOException.throwIt(getCptException(ce));
			}
			
		case TID_COMPUTE:
			switch (activeTestAlgorithm) {
			case ALG_SHA1:
			case ALG_SHA256:
			case ALG_SHA384:
				MessageDigest md;
				if (activeTestAlgorithm == ALG_SHA1) {
					md = sha1Digest;
				} else if (activeTestAlgorithm == ALG_SHA256) {
					md = sha256Digest;
				} else {
					md = sha384Digest;
				}
				for (short i = 0; i < numIterations; i++) {
					md.doFinal(currTestData, (short)0, currTestDataSize,
						   currTestResults, (short)0);
				}
				currResultsDataSize = (short)(md.getLength() & 0xff);
				return;
			case ALG_AES128:
				doAesCipher(apdu, aes128, Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, numIterations);
				return;
			case ALG_AES192:
				doAesCipher(apdu, aes192, Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, numIterations);
				return;
			case ALG_AES256:
				doAesCipher(apdu, aes256, Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, numIterations);
				return;
			default:				
				ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
			}
		case TID_KEY_AGREEMENT_HASHED:
			if (numIterations == 0) {
				numIterations = 1;
			}
			try {
				switch (activeTestAlgorithm) {
				case ALG_EC224:
					currResultsDataSize = doEcDh(ecSvdpDh224, numIterations);
					return;
				case ALG_EC256:
					currResultsDataSize = doEcDh(ecSvdpDh256, numIterations);
					return;
				case ALG_EC384:
					currResultsDataSize = doEcDh(ecSvdpDh384, numIterations);
					return;
				default:
					ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
				}
			} catch (CryptoException ce) {
				ISOException.throwIt((short)(CPT_EX_SHORT | ce.getReason()));
			}
			
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		
		}
	}
	private void signTest(Signature sig, Key key, byte mode, short numIterations) {
		try {
			sig.init(key, mode);
			sig.sign(currTestData, (short)0, currTestDataSize, currTestResults, (short)0);
		} catch (CryptoException ce) {
			ISOException.throwIt(getCptException(ce));
		}
	}
	private short doEcDh(KeyAgreement ka, short numIterations) {
		short singleIterationSize = 0;
		for (short i = 0; i < numIterations; i++) {
			singleIterationSize = ka.generateSecret(currTestData, (short)0, currTestDataSize, currTestResults, (short)0);
		}
		return singleIterationSize;
	}
	private void doAesCipher(APDU apdu, Key activeKey, byte aesAlgo, short numIterations) {
		try {
			if (!activeKey.isInitialized()) {
				ISOException.throwIt((short)((CPT_EX_SHORT | CAP_NOT_INITIALIZED) & 0xff));
			}
			for (short i = 0; i < numIterations; i++) {
				Cipher cipher = Cipher.getInstance(aesAlgo, false);
				byte mode = Cipher.MODE_DECRYPT;
				if (activeTestId == TID_COMPUTE) {
					mode = Cipher.MODE_ENCRYPT;
				}
				cipher.init(activeKey, mode);
				// (for cbc mode) cipher.init(activeKey, mode, aesIv, (short)0, (short)16);
				currResultsDataSize = cipher.doFinal(currTestData, (short)0, currTestDataSize, currTestResults, (short)0);
			}
		 
		} catch (CryptoException ce) {
			ISOException.throwIt(getCptException(ce));
		}
	}
	private void sendTestDataBuffer(APDU apdu) {
		//short remaining = currTestDataSendOffset -
	}
	private void sendTestResults(APDU apdu) {
		
	}
	private void saveData(APDU apdu) {
		
	}
	private void sendData(APDU apdu) {
		// Always from result buff (should refactor testBuff/resultsBuff to incoming/outgoing? send/Receive?
		// get bytes remaining to be sent.
		// Sanity check on active buffer source (activeSendBuffer)
		if (currTestResults == null) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		//short buffOffset = bufferCtl[activeSendBuffer][BUF_CURR_OFFSET];
		short available = (short)(currResultsDataSize - currTestResultsReadOffset);
		if (available < 0) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		boolean multiResponse = available > MAX_SEND_SIZE;
		short sendLen = multiResponse ? MAX_SEND_SIZE : available;
		
		apdu.setOutgoing();
		apdu.setOutgoingLength(sendLen);
		apdu.sendBytesLong(currTestResults, currTestResultsReadOffset, sendLen);
		currTestResultsReadOffset += sendLen;
		available -= sendLen;
		if (available == 0) {
			// reset buffer if done
			currTestResultsReadOffset = 0;
			return;
		}
		short nextSendSize = (available > MAX_SEND_SIZE) ? MAX_SEND_SIZE_INDICATOR : available; 
		short sw_available = (short)(0x6100 | nextSendSize);
		ISOException.throwIt(sw_available);	
	}
}
