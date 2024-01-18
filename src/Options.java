
/**
 * <p> Descripci�n: Pr�cticas de Seguridad </p>
 * <p> Copyright: Copyright (c) 2002-18 </p>
 * <p> Empresa: DISIT de la UEx </p>
 * @author Lorenzo M. Mart�nez Bravo
 * @version 1.0
 */

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 * <p>Define opciones de proteccion de ficheros con algoritmos criptograficos, asi
 * como constantes (arrays) con los nombres de los diferentes tipos de algoritmos
 * utilizables.
 * </p>
 */
public class Options implements Serializable {
	/**
	 * Algoritmo de cifrado simetrico elegido
	 */
	protected String symmetricalCipher;
	/**
	 * Algoritmo de autenticacion elegido
	 */
	protected String authenticator;
	
	/**
	 * Constantes que representan las diferentes operaciones criptograficas aplicables a un objeto:
	 * -Cifrado sim�trico
	 * -Hash/Mac
	 * -Cifrado de clave publica
	 * -Firma digital
	 */
	public final static byte OP_NONE 				= 0;
	public final static byte OP_SYMMETRIC_CIPHER 	= 1;
	public final static byte OP_HASH_MAC 			= 10;
	public final static byte OP_PUBLIC_CIPHER 		= 20;
	public final static byte OP_SIGNED 				= 30;
	/**
	 * Ningun algoritmo
	 */
	public final static String OP_NONE_ALGORITHM = "none"; 
	/**
	 * Nombres estandares de algoritmos de cifrado simetrico y publico
	 */
	public final static String cipherAlgorithms[] = { "none", "PBEWithMD5AndDES", "PBEWithMD5AndTripleDES",
			"PBEWithSHA1AndDESede", "PBEWithSHA1AndRC2_40", "RSA/ECB/PKCS1Padding" };
	/**
	 * Nombres estandares de algoritmos de autenticacion hash, mac y firma digital
	 */
	public final static String authenticationAlgorithms[] = { "none", "MD2", "MD5", "SHA-1", "SHA-256", "SHA-384",
			"SHA-512", "HmacMD5", "HmacSHA1", "HmacSHA256", "HmacSHA384", "HmacSHA512", "SHA1withRSA", "MD2withRSA",
			"MD5withRSA", "SHA224withRSA", "SHA256withRSA", "SHA384withRSA","SHA512withRSA" };
	/**
	 * Nombres estandares de algoritmos de autenticacion hash
	 */
	public final static String hashAlgorithms[] = { "MD2", "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512" };
	/**
	 * Nombres estandares de algoritmos de autenticacion MAC
	 */
	public final static String macAlgorithms[] = { "HmacMD5", "HmacSHA1", "HmacSHA256", "HmacSHA384", "HmacSHA512" };
	/**
	 * Nombres estandares de algoritmos de cifrado simetrico PBE
	 */
	public final static String symmetricalAlgorithms[] = { "PBEWithMD5AndDES", "PBEWithMD5AndTripleDES",
			"PBEWithSHA1AndDESede", "PBEWithSHA1AndRC2_40" };
	/**
	 * Nombres estandares de algoritmos de cifrado publico
	 */
	public final static String publicAlgorithms[] = { "RSA/ECB/PKCS1Padding" };
	/**
	 * Nombres estandares de algoritmos de autenticacion hash y MAC
	 */
	public final static String hashmacAlgorithms[] = { "MD2", "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512",
			"HmacMD5", "HmacSHA1", "HmacSHA256", "HmacSHA384", "HmacSHA512" };
	/**
	 * Nombres estandares de algoritmos de firma digital
	 */
	public final static String signAlgorithms[] = { "SHA1withRSA", "MD2withRSA", "MD5withRSA",
			"SHA224withRSA", "SHA256withRSA", "SHA384withRSA","SHA512withRSA"};

	
	 /**
     * Constructor que obtiene una instancia de <code>Options</code>
	 * @return nueva instancia de <code>Options</code> con valores por defecto
	 */
	public Options() {
		setSymmetricalCipher(symmetricalAlgorithms[0]);
		setAuthenticator(hashmacAlgorithms[0]); 
	}
	
	/**
     * Constructor que obtiene una instancia de <code>Options</code>
	 * @param cipher el algoritmo de cifrado
	 * @param authenticator el algoritmo de autenticacion
	 * @return una instancia de <code>Options</code>
	 */	
	public Options(String cipher, String authenticator) {
		this.symmetricalCipher = cipher;
		this.authenticator = authenticator;
	}

	public String getSymmetricalCipher() {
		return symmetricalCipher;
	}

	public void setSymmetricalCipher(String cipher) {
		this.symmetricalCipher = cipher;
	}

	public String getAuthenticator() {
		return authenticator;
	}

	public void setAuthenticator(String authenticator) {
		this.authenticator = authenticator;
	}
	
	/**
     * Carga una instancia de <code>Options</code> desde un fichero
	 * @param fileName nombre del fichero
	 * @return una instancia de <code>Options</code>, cargada desde fichero o <code>null</code>.
	 * @throws IOException si se produce cualquier error al acceder al fichero	 
	 * @throws ClassNotFoundException si no se encuentra la clase
	 */	
	public static Options load(String fileName) throws IOException, ClassNotFoundException  {
		Options oo = null;		
		FileInputStream fi = new FileInputStream(fileName);
		ObjectInputStream o = new ObjectInputStream(fi);
		oo = (Options)o.readObject();
		o.close();
		return oo;
	}
	
	/**
     * Salva la instancia de <code>Options</code> en un fichero
	 * @param fileName nombre del fichero 
	 * @return <code>true</code> la operacion tiene exito, o <code>false</code> en caso contrario.
	 * @throws IOException si se produce cualquier error al acceder al fichero
	 */	
	public boolean save(String fileName) throws IOException {
		boolean breturn=true;
		FileOutputStream fo = new FileOutputStream(fileName);
		ObjectOutputStream o = new ObjectOutputStream(fo);
		o.writeObject(this);
		o.close();		
		return breturn;
	}
	
	/**
     * Comprueba si un algoritmo pertenece a una lista (tipo de algoritmos)
	 * @param type lista de algoritmos
	 * @param algorithm algoritmo a comprobar
	 * @return <code>true</code> el algoritmo pertenece al tipo, o <code>false</code> en caso contrario.
	 */
	public static boolean isTypeAlgorithm(String[] type, String algorithm) {
		int i = search(type, algorithm);
		return (i != -1);
	}
	
	/**
     * Busca un String en un array de String
	 * @param stringList lista de Strings
	 * @param item String a buscar
	 * @return posicion de <code>item</code> en <code>stringList</code> si la encuentra, -1 en caso contrario
	 */
	public static int search(String stringList[], String item) {
		int i;
		for (i = stringList.length - 1; i != -1; i--)
			if (stringList[i].compareTo(item) == 0)
				break;
		return i;
	}
}