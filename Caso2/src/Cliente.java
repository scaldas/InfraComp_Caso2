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


public class Cliente{
	
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
		
		int bufferSize = clientSocket.getReceiveBufferSize();
		byte[] bytesCertificadoServidor = new byte[bufferSize];
	    input.read(bytesCertificadoServidor, 0, bufferSize);
		CertificateFactory creador = CertificateFactory.getInstance("X.509");
		InputStream inputCertificado = new ByteArrayInputStream(bytesCertificadoServidor);
		X509Certificate certificadoServidor = (X509Certificate)creador.generateCertificate(inputCertificado);
		
		System.out.println("Papaya: " + certificadoServidor);
		clientSocket.close();
	}
	
	public static void main(String[] args) throws Exception 
	{
		Cliente cliente = new Cliente("DES", "RSA", "HMACMD5");
		cliente.ejecutarComunicacion( );
	}
		
}
