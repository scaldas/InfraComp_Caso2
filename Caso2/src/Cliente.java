import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
/**
 * --------------------------------Infraestructura Computacional--------------------------------
 * -----------Sistema de Gestion Empresarial y Operativa de una Compañia Transportadora---------
 * ---------------------------------Caso 2 - Canales Seguros------------------------------------
 * --------------------------Ana Maria Cardenas, Sebastian Caldas-------------------------------
 */

/**
 * Cliente
 * Se encarga de llevar a cabo todo el protocolo de comunicacion de un Cliente.
 */

public class Cliente{
	
	// -----------------------------------------------------------------
	// Constantes para comunicacion
	// -----------------------------------------------------------------

	public final static String IP_SERVIDOR = "infracomp.virtual.uniandes.edu.co";
	//public final static String IP_SERVIDOR = "localhost";
	public final static int PUERTO_SERVIDOR = 443;

	// -----------------------------------------------------------------
	// Constantes de algoritmos
	// -----------------------------------------------------------------
	public final static String DES = "DES";
	public final static String AES = "AES";
	public final static String Blowfish = "Blowfish";
	public final static String RC4 = "RC4";
	public final static String RSA = "RSA";
	public final static String HMACMD5 = "HMACMD5";
	public final static String HMACSHA1 = "HMACSHA1";
	public final static String HMACSHA256 = "HMACSHA256";

	// -----------------------------------------------------------------
	// Atributos
	// -----------------------------------------------------------------

	/**
	 * Algoritmo simetrico escogido.
	 */
	private String simetrico;
	
	/**
	 * Algoritmo asimetrico escogido.
	 */
	private String asimetrico;
	
	/**
	 * Algoritmo HMAC escogido.
	 */
	private String hash;

	/**
	 * Socket de comunicacion con el Servidor.
	 */
	private Socket clientSocket;
	
	/**
	 * Escritor sobre el socket.
	 */
	private PrintStream writer;
	
	/**
	 * Lectores sobre el socket.
	 */
	private BufferedReader reader;
	private InputStream input;
	
	/**
	 * Implementacion de los algoritmos de seguridad.
	 */
	private Algoritmos algoritmos;
	
	/**
	 * Implementacion de la conversion a hexadecimal.
	 */
	private HexaManager hexaManager;
	
	/**
	 * Constructor
	 * @param simetrico Algoritmo simetrico a utilizar
	 * @param asimetrico Algortimo asimetrico a utilizar
	 * @param hash Algoritmo hmac a utilizar
	 */
	public Cliente(String simetrico, String asimetrico, String hash)
	{
		this.simetrico = simetrico;
		this.asimetrico = asimetrico;
		this.hash = hash;
		
		try 
		{
			clientSocket = new Socket(IP_SERVIDOR, PUERTO_SERVIDOR);
			writer = new PrintStream(clientSocket.getOutputStream());
			input = clientSocket.getInputStream();
	        reader = new BufferedReader(new InputStreamReader(input));
		} 
		catch (IOException e) 
		{
			System.out.println("Error inicializando el socket.");
		e.printStackTrace();
		}

		algoritmos = new Algoritmos( );
		hexaManager = new HexaManager( );
	}

	/**
	 * Implementacion del protocolo de comunicacion
	 * @param posicion Posicion a enviar al Servidor
	 * @throws Falla si el protocolo no se cumple tal y como se especifico. 
	 * 			El mensaje de la excepcion indica el momento del fallo
	 */
	public void ejecutarComunicacion(String posicion) throws Exception
	{
		//Etapa 1: Seleccion de Algoritmos e Inicio de Sesion
		writer.println("HOLA");
		String respuesta = reader.readLine( );
		
		if(!respuesta.equals("INICIO"))
		{
			throw new Exception("Mensaje no definido: Se esperaba INICIO y se recibio " + respuesta);
		}
	
		writer.println("ALGORITMOS:" + simetrico + ":" + asimetrico + ":" + hash);
		respuesta = reader.readLine( );
		
		if(!respuesta.equals("ESTADO:OK"))
		{
			if(respuesta.equals("ESTADO:ERROR"))
				throw new Exception("El servidor reporta un error en los algoritmos: " + respuesta);
			else
				throw new Exception("Mensaje no definido: Se esperaba ESTADO:OK o ESTADO:ERROR y se recibio " + respuesta);
		}		
		
		//Etapa 2: Autenticacion del cliente
		//Se envia el certificado autofirmado al Servidor
		writer.println("CERCLNT");
	
		KeyPair llavesAsimetricas = algoritmos.generarLlavesAsimetricas(asimetrico);
		X509Certificate certificadoCliente = algoritmos.generarCertificado(llavesAsimetricas);
	
		byte[] bytesCertificadoCliente = certificadoCliente.getEncoded();
		writer.write(bytesCertificadoCliente);
		writer.flush();
	
		//Etapa 3: Autenticacion del Servidor
		//Se recibe el certificado del Servidor
		respuesta = reader.readLine( );
		if(!respuesta.equals("CERTSRV"))
		{
			throw new Exception("Mensaje no definido: Se esperaba CERTSRV y se recibio " + respuesta);
		}
	
		int bufferSize = 520;
		byte[] bytesCertificadoServidor = new byte[bufferSize];
		input.read(bytesCertificadoServidor, 0, bufferSize);
		CertificateFactory creador = CertificateFactory.getInstance("X.509");
		InputStream inputCertificado = new ByteArrayInputStream(bytesCertificadoServidor);
		X509Certificate certificadoServidor = (X509Certificate)creador.generateCertificate(inputCertificado);
		
		//Se recibe la llave simetrica para la comunicacion
		respuesta = reader.readLine();
		if(!respuesta.split(":")[0].equals("INIT"))
		{
			throw new Exception("Mensaje no definido: Se esperaba INIT y se recibio " + respuesta);
		}	

		byte[] bytes_encriptados = hexaManager.fromHexa(respuesta.split(":")[1]);
		
		byte[] bytes_llave_simetrica =  algoritmos.desencripcionAsimetrica(bytes_encriptados, 
				llavesAsimetricas.getPrivate(), asimetrico);
		
		SecretKey llave_simetrica = new SecretKeySpec(bytes_llave_simetrica, 0, bytes_llave_simetrica.length, simetrico);
    
		//Etapa 4: Reporte y manejo de la actualizacion
		String datos = posicion;
       
		byte[] datos_encriptados = algoritmos.encriptacionSimetrica(datos.getBytes(), llave_simetrica, simetrico);
		String mensaje_encriptado = hexaManager.toHexa(datos_encriptados);
    
    	writer.println("ACT1:" + mensaje_encriptado);
       
    	byte[] hmac = algoritmos.hmac(datos.getBytes(), llave_simetrica, hash);
    	byte[] hmac_encriptado = algoritmos.encripcionAsimetrica(hmac, certificadoServidor.getPublicKey(), asimetrico);
    	String mensaje_hmac = hexaManager.toHexa(hmac_encriptado);

	    writer.println("ACT2:" + mensaje_hmac);
	    respuesta = reader.readLine();
		
	    if(!respuesta.equals("RTA:OK"))
		{
			if(respuesta.equals("RTA:ERROR"))
				throw new Exception("El servidor reporta un error en la comunicacion: " + respuesta);
			else
				throw new Exception("Mensaje no definido: Se esperaba RTA:OK o RTA:ERROR y se recibio " + respuesta);
		}
	    else
	    	System.out.println("Comunicacion exitosa: " + respuesta);
	}
	
	/**
	 * Cierra el socket de comunicacion con el Servidor
	 * @pre Ya se inicializo el socket
	 * @pos El socket queda cerrado
	 */
	public void cerrarSocket( ) throws IOException
	{
	    clientSocket.close( );
	}
	
	/**
	 * Main
	 */
	public static void main(String[] args)  
	{
		//En esta implementacion se usan los algoritmos:
		//DES para simetrico
		//RSA para asimetrico
		//HMACSHA256 para HMAC
		//Sin embargo, la implementacion de Algoritmos responde a cualquiera de los declarados como constante
		Cliente cliente = new Cliente(DES, RSA, HMACSHA256);
		try
		{
			//La posicion a enviar es la dada como ejemplo en el caso
			cliente.ejecutarComunicacion("41 24.2028, 2 10.4418");
			//Esta implementacion solo envia un dato al Servidor e inmediatamente cierra el socket
			cliente.cerrarSocket( );
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}
		
}
