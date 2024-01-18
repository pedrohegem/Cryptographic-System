import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Certificate;
import java.security.DigestInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class Main {
	
	public static boolean program = true;
	public static Scanner inputReader = new Scanner(System.in);
	public static Options options = new Options();
	// Constant salt
	public static byte[] salt3 = new byte[] {0x7d, 0x60, 0x43, 0x5f, 0x02, (byte) 0xe9, (byte) 0xe0, (byte) 0xae};
	
	/**
	 * Generates both public and private keys and store them into two different .txt files
	 * Use RSA algorithm to generate the key pair.
	 * @throws Exception
	 */
	public static void generateKeys() throws Exception {
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA","BC");
		kpg.initialize(512); // 512 bits keys
		KeyPair keypair = kpg.generateKeyPair();
		System.out.println("Private and public keys generated.\n");
		
		// Store them into files
		FileOutputStream fKr = new FileOutputStream("privateKey.txt");
		FileOutputStream fKu = new FileOutputStream("publicKey.txt");
		
		
		ByteArrayOutputStream bs = new ByteArrayOutputStream();
		ObjectOutputStream os = new ObjectOutputStream (bs);
		os.writeObject(keypair.getPublic());
		os.close();
		byte[] publicKey = bs.toByteArray();
		fKu.write(publicKey);
		bs.close();
		
		bs = new ByteArrayOutputStream();
		os = new ObjectOutputStream (bs);
		os.writeObject(keypair.getPrivate());
		os.close();
		byte[] privateKey = bs.toByteArray();
		fKr.write(privateKey);
		bs.close();

		fKu.close();
		fKr.close();	
		
	}
	
	/**
	 * Load and returns private key stored in "privateKey.txt" file
	 * @return PrivateKey kr
	 */
	public static PrivateKey getPrivateKey() {
		PrivateKey kr = null;
		try {
			FileInputStream fIn = new FileInputStream("privateKey.txt");
			byte[] key = fIn.readAllBytes();

			ByteArrayInputStream bs = new ByteArrayInputStream(key);
			ObjectInputStream is = new ObjectInputStream(bs);
			kr = (PrivateKey) is.readObject();
			is.close();
			fIn.close();
			bs.close();
		} catch (ClassNotFoundException e) {
		} catch (IOException e) {
		}
		return kr;
	}
	
	/**
	 * Load and returns public key stored in "publicKey.txt" file
	 * @return PublicKey ku
	 */
	public static PublicKey getPublicKey() {
		PublicKey ku = null;
		try {
			FileInputStream fIn = new FileInputStream("publicKey.txt");
			byte[] key = fIn.readAllBytes();

			ByteArrayInputStream bs = new ByteArrayInputStream(key);
			ObjectInputStream is = new ObjectInputStream(bs);
			ku = (PublicKey) is.readObject();
			is.close();
			fIn.close();
			bs.close();
		} catch (ClassNotFoundException e) {
		} catch (IOException e) {
		}
		return ku;
	}
	
	/**
	 * Generates a sign using users private key and use it to sign a file
	 * @throws Exception
	 */
	public static void signFile() throws Exception {
		int i;
		byte[] buff = new byte[8];
		
		System.out.println("Enter your file path: \n");
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		
		String inFilePath = br.readLine();
		String outFilePath = inFilePath.substring(0,inFilePath.lastIndexOf('.')) + ".sig";
		
		// Read input File
		FileInputStream fIn = new FileInputStream(inFilePath);
		byte[] inFile = fIn.readAllBytes();
		fIn.close();
		
		// Select algorithm to sign
		String algorithm = selectSignAlgorithm();
		
		// Generate sign
		Signature dsa = Signature.getInstance(algorithm);
		dsa.initSign(getPrivateKey());
		dsa.update(inFile);
		byte[] sign = dsa.sign();
		
		// Store sign into header
		Header header = new Header(options.OP_SIGNED, options.OP_NONE_ALGORITHM, algorithm, sign);
		
		FileOutputStream fOut = new FileOutputStream(outFilePath);
		header.save(fOut);
		
		// Write output file
		fIn = new FileInputStream(inFilePath);
		while((i = fIn.read(buff)) != -1) {
			fOut.write(buff, 0, i);
		}
		
		System.out.println("Successfully signed file. \n");
			
		fOut.close();
		fIn.close();
	}
	
	/**
	 * Allow the user to select an algorithm to sign
	 * @return selected algorithm
	 */
	public static String selectSignAlgorithm() {
		String algorithm = "";
		
		System.out.print("Select an algorithm: \n");
		for(int i = 0; i < options.signAlgorithms.length; i++) {
			System.out.printf(i+1 +"- "+options.signAlgorithms[i]+"\n");
		}
		algorithm = options.signAlgorithms[inputReader.nextInt()-1];
		System.out.printf("Algorithm: " + algorithm + "\n");
		
		return algorithm;
	}
	
	/**
	 * Verifies a signed file using signer's public key
	 * @throws Exception
	 */
	public static void verifySign() throws Exception {		
		
		int i;
		byte[] buff = new byte[8];
		
		System.out.println("Enter your file path: \n");
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		
		String inFilePath = br.readLine();
		FileInputStream fIn = new FileInputStream(inFilePath);
		String outFilePath = inFilePath.substring(0,inFilePath.lastIndexOf('.')) + ".unsig";
		
		// Load sign from header and calculate new sign
		Header header = new Header();
		header.load(fIn);	
		byte[] inFile = fIn.readAllBytes();
		Signature dsa = Signature.getInstance(header.getAlgorithm2());
		dsa.initVerify(getPublicKey());
		dsa.update(inFile);
		fIn.close();
		
		//Read second time to write the input file into the output one
		fIn = new FileInputStream(inFilePath);
		header.load(fIn);
		FileOutputStream fOut = new FileOutputStream(outFilePath);
		
		// Write output file
		while((i = fIn.read(buff)) != -1) {
			fOut.write(buff, 0, i);
		}
		fOut.close();
		
		// Verify sign
		if(dsa.verify(header.getData())) {
			System.out.println("Verified Sign. \n");
		} else {
			System.out.println("NOT Verified Sign. \n");
		}		
	}
	
	/**
	 * Encrypt a file using Public Key Encryption
	 * @throws Exception
	 */
	public static void EncryptPublic () throws Exception {
		int i;
		byte[] buff = new byte[53];
		
		System.out.println("Enter your file path: \n");
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		
		String inFilePath = br.readLine();
		String outFilePath = inFilePath.substring(0,inFilePath.lastIndexOf('.')) + ".cif";
		
		FileInputStream fIn = new FileInputStream(inFilePath);
		FileOutputStream fOut = new FileOutputStream(outFilePath);
		
		Cipher c = Cipher.getInstance(Options.publicAlgorithms[0]);
		c.init(c.ENCRYPT_MODE, getPublicKey());
		
		Header header = new Header(options.OP_PUBLIC_CIPHER, Options.publicAlgorithms[0], options.OP_NONE_ALGORITHM, salt3);
		header.save(fOut);
		
		while ((i = fIn.read(buff)) != -1) {
			byte out[] = c.doFinal(buff, 0, i);
			fOut.write(out);
		}

		fOut.close();
		fIn.close();
		
		System.out.println("Encrypted file using RSA/ECB/PKCS1Padding.\n");
		
	}
	
	/**
	 * Decrypt a file using the private key
	 * @throws Exception
	 */
	public static void DecryptPrivate() throws Exception {
		int i;
		byte[] buff = new byte[64];
		
		System.out.println("Enter your file path: \n");
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		
		String inFilePath = br.readLine();
		String outFilePath = inFilePath.substring(0,inFilePath.lastIndexOf('.')) + ".decif";
		
		FileInputStream fIn = new FileInputStream(inFilePath);
		FileOutputStream fOut = new FileOutputStream(outFilePath);
		
		// Load Header from input file
		Header header = new Header();
		header.load(fIn);
		
		//Initialize cipher
		Cipher c = Cipher.getInstance(header.getAlgorithm1());
		c.init(c.DECRYPT_MODE, getPrivateKey());
		
		while ((i = fIn.read(buff)) != -1) {
			byte out[] = c.doFinal(buff,0,i);
			fOut.write(out);
		}

		fOut.close();
		fIn.close();
		
		System.out.println("Decrypted file with success.\n");
	}
	
	/**
	 * List the content of a Key Storage
	 */
	public static void ListStorage() throws Exception {
		System.out.println("Enter your key storage path: ");
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		String nFile_load =  br.readLine();
		FileInputStream fis = new FileInputStream(nFile_load);
		
		System.out.println("Password: ");
		String password = br.readLine();
		char[] passwd = password.toCharArray();
		
		//Loading Storage
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(fis, passwd);
		
		Enumeration e = ks.aliases();
		
		int i = 1;
		
		while (e.hasMoreElements()) {
			String alias = (String)e.nextElement();
			if(ks.isKeyEntry(alias)) {
				System.out.println("==== Key Storage ====:");
				System.out.println("Key #"+i);
				System.out.println("-Name: "+alias);
				System.out.println("-Type: "+ks.getType());
				System.out.println("-Creation :"+ks.getCreationDate(alias).toString());
				i++;
			}
		}
		fis.close();
	}
	
	/**
	 * Import a key pair (public and private key) from a Key Storage into two different
	 * text files.
	 * @return PrivateKey kr
	 */
	public static void ImportKeys() throws Exception {
		System.out.println("Enter your Key Storage path: ");
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		String nFile_load =  br.readLine();
		FileInputStream fis = new FileInputStream(nFile_load);
		
		System.out.println("Password: ");
		String password = br.readLine();
		char[] passwd = password.toCharArray();
		
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(fis, passwd);
		
		Enumeration e = ks.aliases();
		
		FileOutputStream fPublic = new FileOutputStream("publicKey.txt");
		FileOutputStream fPrivate = new FileOutputStream("privateKey.txt");

		System.out.println("Enter your key alias:");
		String alias = br.readLine();
		if(ks.isKeyEntry(alias)) {
			System.out.println("Enter your key pair password:");
			String passwordKey = br.readLine();
			char[] passwdKey = passwordKey.toCharArray();
			
			PrivateKey kr = (PrivateKey) ks.getKey(alias, passwdKey);
			java.security.cert.Certificate cert = ks.getCertificate(alias);
			PublicKey ku = cert.getPublicKey();
			
			ByteArrayOutputStream bs = new ByteArrayOutputStream();
			ObjectOutputStream os = new ObjectOutputStream (bs);
			os.writeObject(ku);
			os.close();
			byte[] bytes = bs.toByteArray();
			fPublic.write(bytes);
			bs.close();
			
			bs = new ByteArrayOutputStream();
			os = new ObjectOutputStream (bs);
			os.writeObject(kr);
			os.close();
			bytes = bs.toByteArray();
			fPrivate.write(bytes);
			bs.close();
		}else {
			System.out.println("Couldn't find a key pair that matches the input alias");
		}
		fPublic.close();
		fPrivate.close();
	}

	/**
	 * Main function that manages all case scenarios of this program.
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		
		// Add provider to Security file
		Security.addProvider(new BouncyCastleProvider());
		
		while(program) {
			System.out.println("-- 5th SRT Assignment--");			
			System.out.println("1 - Generate public and private keys\n" + "2 - Sign file\n" + "3 - Verify Sign\n" + "4 - Encrypt with Public Key\n" +  "5 - Decrypt with Private Key\n" + "6 - List Key Storage\n"+ "7 - Import Storage Keys\n"+"8 - Exit");
			
			int userMode = inputReader.nextInt();
			switch(userMode) {
			case 1:
				generateKeys();			
				break;
			case 2:
				signFile();
				break;
			case 3:
				verifySign();
				break;
			case 4:
				EncryptPublic();
				break;
			case 5:
				DecryptPrivate();
				break;
			case 6:
				ListStorage();
				break;
			case 7:
				ImportKeys();
				break;
			case 8:
				System.out.print("........... Exiting...........\n");
				program = false;
				break;
			}
		}
		inputReader.close();
	}
}
