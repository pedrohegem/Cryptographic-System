
import java.io.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;


/**
 * Clase b�sica para la gesti�n de una cabecera que se a�ade los mensajes cifrados (ficheros).
 * Permite almacenar datos de forma de array de bytes.
 * La cabecera estar� cifrada con una clave fija.
 * Formato de la cabecera:
 * --------------------------------------------------------
 * |Longitud (2 bytes)|Datos (array de 'longitud bytes', cifrados) ...        |  
 * --------------------------------------------------------
 */
public class BasicHeader {
	 /**
	  * M�ximna Longitud de los datos cifrados.   
	 */
	private final static short MAXHEADERLENGTH = 1000;
	private final static byte[] CIPHER_KEY = {0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	
  /**
   * Longitud de los datos cifrados.   
   */
  private short length;
  
  /**
   * Datos almacenados en la cabcera. basicData.length() < length  
   */
  private byte basicData[];

  /**
   * Constructor por defecto.    
   */
  public BasicHeader() {
      length = 0;
	  basicData   = new byte[0];	
  }
  /**
   * Constructor. Inicia los atributos con valores suministrados.
   * @param  basicData   - Datos a almacenar en la cabecera 
   */
  public BasicHeader(byte[] basicData) {
	  setbasicData(basicData);
  }


  /**
   * @return the basicData
   */
  protected byte[] getbasicData() {
  	return basicData;
  }
  /**
   * @param basicData the basicData to set
   */
  protected void setbasicData(byte[] basicData) {
  	this.basicData = basicData;
  	length = (short)basicData.length;
  }
  
  /**
   * Intenta cargar los datos de una cabecera desde un InputStream ya abierto.   
   * Si tiene exito, los datos quedan en la clase.
   * @param r el InputStream abierto.
   * @throws Exception  Si ocurre un error de entrada o salida.
   * @return true si la carga es correcta, false en otro caso
   */
  protected boolean load(InputStream is) throws Exception {
	  boolean breturn = false;
	  DataInputStream dis = new DataInputStream(is);
	  length = dis.readShort(); // Leer la longutud de los datos
	  if ((length>0) && (length<MAXHEADERLENGTH)) {
		  byte buffer[] = new byte[length];
		  if(is.read(buffer)==length) {
			  // Descifrar datos
			  byte[] decryptData = decrypt(buffer);
			  setbasicData(decryptData);
			  breturn = true;
		  }
      }
	  return breturn;
  }

/**
   * Intenta guardar la cabecera actual en un OutputStream ya abierto.
   * @param fos el OutputStream abierto
   * @throws Exception  Si ocurre un error de entrada o salida.
   * @return true si tiene exito, false en otro caso
   */
  protected boolean save(OutputStream os) throws Exception {
	  boolean breturn=false;
	  DataOutputStream dos = new DataOutputStream(os);
	  // Cifrar los datos
      byte [] encryptData = encrypt(basicData);
      dos.writeShort(encryptData.length); // Escribir la longutud de los datos cifrados
      // Escribir los datos
	  os.write(encryptData, 0, encryptData.length);
      os.flush();
      breturn = true;
      return breturn;
  }

  private byte[] encrypt(byte[] in) throws Exception {
	  byte[] keyBytes = CIPHER_KEY;
      SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
      Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
      cipher.init(Cipher.ENCRYPT_MODE, key);
      byte[] out = cipher.doFinal(in);
	  return out;
  }
  
  private byte[] decrypt(byte[] in) throws Exception {
	  byte[] keyBytes = CIPHER_KEY;
      SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
      Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
      cipher.init(Cipher.DECRYPT_MODE, key);
      byte[] out = cipher.doFinal(in);
	  return out;
  }
  
  /**
   * Prueba el funcionamiento de la clase, creando una cabecera, guardandola en un   
   * fichero y recuperandola posteriomente.
   * 
   */
  public void test() {
    try {
    	String fileName = "basicheader.prueba"; 
        FileOutputStream fos = new FileOutputStream(fileName);
        save(fos);
        fos.close();

        BasicHeader fh2= new BasicHeader();
        FileInputStream fis = new FileInputStream(fileName);
        if (fh2.load(fis)){
        	System.out.println("Le�do, Longitud: " +fh2.getbasicData().length);
        	System.out.print  ("Le�do, Data     : ");
        	for(byte i=0;i<fh2.getbasicData().length;i++)
        		System.out.print(String.format("0x%h ", fh2.getbasicData()[i]));
        }
        else
        	System.out.println("Error en la carga");
        fis.close();
    }
    catch (Exception e) {e.printStackTrace(); };
  }
  
  /**
   * Programa principal para prueba
   * 
   */
  public static void main(String args[]){
	  byte basicData[] = {1,2,3,4,5,6,7,8,9,10};
	  BasicHeader bh = new BasicHeader(basicData);
	  bh.test();
  }
  
}//BasicHeader