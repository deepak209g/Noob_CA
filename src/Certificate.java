import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Certificate {
	Date serialNumber;
	String algoUsed;
	String issuerName;
	Date validFrom;
	Date validTo;
	String issuedTo;
	PublicKey pubKey;
	String signature;
	public Certificate(Date currentDate, String algoUsed, String issuerName, java.util.Date currentDate2, java.util.Date validTo2,
			String issuedTo, PublicKey pubKey) {
		super();
		this.serialNumber = currentDate;
		this.algoUsed = algoUsed;
		this.issuerName = issuerName;
		this.validFrom = currentDate2;
		this.validTo = validTo2;
		this.issuedTo = issuedTo;
		this.pubKey = pubKey;
	}
	
	
	
	public String generateSignature(PrivateKey pkey){
		
		String ciphertext = null;
        // ENCRYPT using the PUBLIC key
        try {
        	String hash = this.generateDigest();
    		final Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, pkey);
	        byte[] encryptedBytes = cipher.doFinal(hash.getBytes());
	        ciphertext = new String(Base64.getEncoder().encode(encryptedBytes));
	        
        } catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

 catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return ciphertext;
	}

	public static void saveCertToFile(String fileName, Certificate cert) throws FileNotFoundException, IOException{


		ObjectOutputStream oout = new ObjectOutputStream(
				new BufferedOutputStream(new FileOutputStream(fileName)));
		try {
			KeyFactory fact = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec pub = fact.getKeySpec(cert.pubKey,
					RSAPublicKeySpec.class);
			oout.writeObject(cert.serialNumber);
			oout.writeObject(cert.algoUsed);
			oout.writeObject(cert.issuerName);
			oout.writeObject(cert.validFrom);
			oout.writeObject(cert.validTo);
			oout.writeObject(cert.issuedTo);
			oout.writeObject(pub.getModulus());
			oout.writeObject(pub.getPublicExponent());
			oout.writeObject(cert.signature);
		} catch (Exception e) {
			throw new IOException("Unexpected error", e);
		} finally {
			oout.close();
		}
	}

	public void setSignature(String sign){
		this.signature = sign;
	}
	
	public String generateDigest(){
		MessageDigest md;
		String blob = this.getCertBlob();
		try {
			md = MessageDigest.getInstance("SHA");
			 md.update(blob.getBytes());
			 byte digest[] = md.digest();
			 String temp = new String(digest);
			 return temp;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	
	
	public boolean validateCert(PublicKey publicKey){
        
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
	        byte[] ciphertextBytes = Base64.getDecoder().decode(this.signature.getBytes());
	        byte[] decryptedBytes = cipher.doFinal(ciphertextBytes);
	        String olddigest = new String(decryptedBytes);
			String newdigest = this.generateDigest();
			if(newdigest.equals(olddigest)){
				return true;
			}else{
				return false;
			}
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
        
	}
	
	public String getCertBlob(){
		StringBuilder sb = new StringBuilder();
		sb.append(this.algoUsed);
		sb.append(this.issuedTo);
		sb.append(this.issuerName);
		sb.append(this.pubKey.toString());
		sb.append(this.serialNumber.toString());
		sb.append(this.validFrom.toString());
		sb.append(this.validTo.toString());
		return sb.toString();
	}
	public static Certificate readCertFromFile(String filename){
		ObjectInputStream ois;
		try {
			ois = new ObjectInputStream(new FileInputStream(filename));
			Date snum = (Date) ois.readObject();
			String algoUsed = (String) ois.readObject();
			String issuerName = (String) ois.readObject();
			Date validFrom = (Date) ois.readObject();
			Date validTo = (Date) ois.readObject();
			String issuedTo = (String)ois.readObject();
			BigInteger m = (BigInteger) ois.readObject();
			BigInteger e = (BigInteger) ois.readObject();
			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
			KeyFactory fact = KeyFactory.getInstance("RSA");
			PublicKey pubKey = fact.generatePublic(keySpec);
			String sign = (String) ois.readObject();
			Certificate temp = new Certificate(snum, algoUsed, issuerName, validTo, validFrom, issuedTo, pubKey);
			temp.setSignature(sign);
			ois.close();
			return temp;
			
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (InvalidKeySpecException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return null;


	}

}
