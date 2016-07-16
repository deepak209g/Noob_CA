import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Calendar;
import java.util.Date;
import java.util.Scanner;

public class CertAuth {
	String name;
	Certificate mycert;
	PrivateKey myPrivKey;
	
	public CertAuth(String name){
		this.name = name;
	}
	
	public CertAuth(String name, Certificate cert, PrivateKey myKey){
		this.name = name;
		this.mycert = cert;
		this.myPrivKey = myKey;
	}
	
	public static Certificate generateSSC(PublicKey publickey, String name){
		Date currentDate = new Date();		 
		Calendar cal = Calendar.getInstance();
		cal.setTime(currentDate);
		cal.add(Calendar.DATE, 180); // add 10 days
		Date validTo = cal.getTime();
		Certificate cert = new Certificate(currentDate, "RSA", name, currentDate, validTo, name, publickey);
		return cert;
	}
	public Certificate generateNewCertificate(PublicKey publickey){
		Scanner sc = new Scanner(System.in);
		System.out.println("Enter you name");
		String issuedTo = sc.nextLine();
		Date currentDate = new Date();		 
		Calendar cal = Calendar.getInstance();
		cal.setTime(currentDate);
		cal.add(Calendar.DATE, 180); // add 10 days
		Date validTo = cal.getTime();
		Certificate cert = new Certificate(currentDate, "RSA", this.name, currentDate, validTo, issuedTo, publickey);
		sc.close();
		return cert;
	}
	
	public static void signCert(Certificate cert, PrivateKey CAprivatekey){
		String sign = cert.generateSignature(CAprivatekey);
		cert.setSignature(sign);
	}
}
