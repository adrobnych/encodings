
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

public class DHScenario {

	KeyAgreement aKeyAgree;
	KeyAgreement bKeyAgree;
	byte[] aPairBytes;
	byte[] bPairBytes; 

	BigInteger p512;
	BigInteger g512;

	void initPandG() throws Exception{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
		paramGen.init(512); // number of bits
		AlgorithmParameters params = paramGen.generateParameters();
		DHParameterSpec dhSpec = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);

		p512 = dhSpec.getP();
		g512 = dhSpec.getG();
	}

	void aSide()  throws Exception{
		//Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		DHParameterSpec dhParams = new DHParameterSpec(p512, g512);
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");

		keyGen.initialize(dhParams, new SecureRandom());

		aKeyAgree = KeyAgreement.getInstance("DH", "BC");
		KeyPair aPair = keyGen.generateKeyPair();
		aPairBytes = aPair.getPublic().getEncoded();

		aKeyAgree.init(aPair.getPrivate());

	}

	void bSide()  throws Exception{
		
		DHParameterSpec dhParams = new DHParameterSpec(p512, g512);
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");

		keyGen.initialize(dhParams, new SecureRandom());

		bKeyAgree = KeyAgreement.getInstance("DH", "BC");
		KeyPair bPair = keyGen.generateKeyPair();
		bPairBytes = bPair.getPublic().getEncoded();

		bKeyAgree.init(bPair.getPrivate());

	}

	public static void main(String[] args) throws Exception {
		
		DHScenario scenario = new DHScenario();
		
		scenario.initPandG();
		scenario.aSide();
		scenario.bSide();
		
		MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");

		// generate full secret on A side
		PublicKey bPublicKey = 
			    KeyFactory.getInstance("DH", "BC").generatePublic(new X509EncodedKeySpec(scenario.bPairBytes));
		scenario.aKeyAgree.doPhase(bPublicKey, true);
		System.out.println(toHex(scenario.aKeyAgree.generateSecret()));
		
		// generate full secret on B side
		PublicKey aPublicKey = 
			    KeyFactory.getInstance("DH", "BC").generatePublic(new X509EncodedKeySpec(scenario.aPairBytes));
		scenario.bKeyAgree.doPhase(aPublicKey, true);
		System.out.println(toHex(scenario.bKeyAgree.generateSecret()));
	}

	private static String toHex(byte [] bytes){
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02X ", b));
		}
		return sb.toString();
	}
}
