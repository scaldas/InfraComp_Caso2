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


public class Cliente{
	
	//public final static String IP_SERVIDOR = "infracomp.virtual.uniandes.edu.co";
	public final static String IP_SERVIDOR = "localhost";
	public final static int PUERTO_SERVIDOR = 443;

	private String simetrico;
	private String asimetrico;
	private String hash;

	private Socket clientSocket;
	private PrintStream writer;
	private BufferedReader reader;
	private InputStream input;
	
	private Algoritmos algoritmos;
	
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
	}

	public void ejecutarComunicacion( ) throws Exception
	{
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
	
		writer.println("CERCLNT");
	
		KeyPair llavesAsimetricas = algoritmos.generarLlavesAsimetricas(asimetrico);
		X509Certificate certificadoCliente = algoritmos.generarCertificado(llavesAsimetricas);
	
		byte[] bytesCertificadoCliente = certificadoCliente.getEncoded();
		writer.write(bytesCertificadoCliente);
		writer.flush();
	
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
	
		respuesta = reader.readLine();
		if(!respuesta.split(":")[0].equals("INIT"))
		{
			throw new Exception("Mensaje no definido: Se esperaba INIT y se recibio " + respuesta);
		}	
	
		byte[] bytes_encriptados = new byte[respuesta.split(":")[1].length() / 2];
		for (int i = 0; i < bytes_encriptados.length; i++) {
			bytes_encriptados[i] = ((byte)Integer.parseInt(respuesta.split(":")[1].substring(i * 2, (i + 1) * 2), 16));
		}
    
		byte[] bytes_llave_simetrica =  algoritmos.desencripcionAsimetrica(bytes_encriptados, 
				llavesAsimetricas.getPrivate(), asimetrico);
    
		SecretKey llave_simetrica = new SecretKeySpec(bytes_llave_simetrica, 0, bytes_llave_simetrica.length, simetrico);
    
		String datos = "<Posicion>";
       
		byte[] datos_encriptados =algoritmos.encriptacionSimetrica(datos.getBytes(), llave_simetrica, simetrico);
		String mensaje_encriptado = "";
		for (int i = 0; i < datos_encriptados.length; i++) {
			String g = Integer.toHexString((char)datos_encriptados[i] & 0xFF);
			mensaje_encriptado = mensaje_encriptado + (g.length() == 1 ? "0" : "") + g;
		}
    
    	writer.println("ACT1:" + mensaje_encriptado);
       
 
    	byte[] hmac = algoritmos.hmac(datos.getBytes(), llave_simetrica, hash);
    	byte[] hmac_encriptado = algoritmos.encripcionAsimetrica(hmac, certificadoServidor.getPublicKey(), asimetrico);
    	String mensaje_hmac = "";
	    for (int i = 0; i < hmac_encriptado.length; i++) {
	    	String g = Integer.toHexString((char)hmac_encriptado[i] & 0xFF);
	    	mensaje_hmac = mensaje_hmac + (g.length() == 1 ? "0" : "") + g;
	    }
	    writer.println("ACT2:" + mensaje_hmac);
	    System.out.println(reader.readLine());

	    clientSocket.close();
	}

	public static void main(String[] args) throws Exception 
	{
		Cliente cliente = new Cliente("DES", "RSA", "HMACMD5");
		cliente.ejecutarComunicacion( );
	}
		
}
