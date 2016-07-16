import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Scanner;

public class Test {
	public static void main(String args[]) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException{
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		CertAuth noobCA;
		File f = new File("noobpriv.key");
		if(f.exists()){
			// CA exists
			System.out.println("Existing CA opened");
			Certificate mycert = Certificate.readCertFromFile("noobCAcert.cert");
			PrivateKey myprivkey = readPrivateKeyFromFile("noobpriv.key");
			noobCA = new CertAuth("Noob CA", mycert, myprivkey);
		}else{
			// run first time
			System.out.println("New CA opened");
			KeyPair kp = kpg.genKeyPair();
			Certificate noobcert = CertAuth.generateSSC(kp.getPublic(), "Noob CA");
			Certificate.saveCertToFile("noobCAcert.cert", noobcert);
			savePrivKeyToFile("noobpriv.key", kp.getPrivate());
			noobCA = new CertAuth("Noob CA", noobcert, kp.getPrivate());
			
		}
		
		
		Scanner in = new Scanner(System.in);
		while(true){
			System.out.println("1: Request new Certificate");
			System.out.println("2: Validate Certificate");
			System.out.println("3: Exit");
			
			int resp = Integer.parseInt(in.nextLine());
			
			switch(resp){
			case 1:
				KeyPair kp = kpg.generateKeyPair();
				Certificate newCert = noobCA.generateNewCertificate(kp.getPublic());
				String sign = newCert.generateSignature(noobCA.myPrivKey);
				newCert.setSignature(sign);
				Certificate.saveCertToFile(newCert.issuedTo + ".cert", newCert);
				savePrivKeyToFile(newCert.issuedTo + ".key", kp.getPrivate());
				break;
			case 2:
				System.out.println("Enter cert file name");
				String filename = in.nextLine();
				Certificate cert = Certificate.readCertFromFile(filename);
				System.out.println(cert.getCertBlob());
				boolean result = cert.validateCert(noobCA.mycert.pubKey);
				if(result == true){
					System.out.println("This is a valid Certificate");
				}else{
					System.err.println("Error : Invalid Certificate");
				}
				break;
			default: 
				in.close();
				return;
			}
		}
		
		
	}

	public static void savePrivKeyToFile(String fileName,PrivateKey privateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory fact = KeyFactory.getInstance("RSA");
//		RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(),
//				RSAPublicKeySpec.class);
		RSAPrivateKeySpec priv = fact.getKeySpec(privateKey,
				RSAPrivateKeySpec.class);
		ObjectOutputStream oout = new ObjectOutputStream(
				new BufferedOutputStream(new FileOutputStream(fileName)));
		try {
			oout.writeObject(priv.getModulus());
			oout.writeObject(priv.getPrivateExponent());
		} catch (Exception e) {
			throw new IOException("Unexpected error", e);
		} finally {
			oout.close();
		}
	}
	

	public static PrivateKey readPrivateKeyFromFile(String filename){
		try {
			ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename));
			BigInteger m = (BigInteger) ois.readObject();
		    BigInteger e = (BigInteger) ois.readObject();
		    RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
		    KeyFactory fact = KeyFactory.getInstance("RSA");
		    PrivateKey privKey = fact.generatePrivate(keySpec);
		    ois.close();
		    return privKey;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return null;
	}
	

}
