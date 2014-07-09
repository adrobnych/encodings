import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

public class BasicDHSample {

  public static void main(String[] args) throws Exception {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
    paramGen.init(512); // number of bits
    AlgorithmParameters params = paramGen.generateParameters();
    DHParameterSpec dhSpec = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);

    BigInteger p512 = dhSpec.getP();
    BigInteger g512 = dhSpec.getG();
    //int l = dhSpec.getL();
    
    DHParameterSpec dhParams = new DHParameterSpec(p512, g512);
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");

    keyGen.initialize(dhParams, new SecureRandom());

    KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");
    KeyPair aPair = keyGen.generateKeyPair();
    KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", "BC");
    KeyPair bPair = keyGen.generateKeyPair();
    
    System.out.println(toHex(aPair.getPublic().getEncoded()));
    System.out.println(toHex(bPair.getPublic().getEncoded()));
    
    aKeyAgree.init(aPair.getPrivate());
    bKeyAgree.init(bPair.getPrivate());

    aKeyAgree.doPhase(bPair.getPublic(), true);
    bKeyAgree.doPhase(aPair.getPublic(), true);

    MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
    System.out.println(toHex(aKeyAgree.generateSecret()));
    System.out.println(toHex(bKeyAgree.generateSecret()));   //hash.digest(bKeyAgree.generateSecret())
  }
  
  private static String toHex(byte [] bytes){
	  StringBuilder sb = new StringBuilder();
	  for (byte b : bytes) {
		  sb.append(String.format("%02X ", b));
	  }
	  return sb.toString();
  }
}