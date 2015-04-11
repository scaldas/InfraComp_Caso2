import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
/**
 * --------------------------------Infraestructura Computacional--------------------------------
 * -----------Sistema de Gestion Empresarial y Operativa de una Compañia Transportadora---------
 * ---------------------------------Caso 2 - Canales Seguros------------------------------------
 * --------------------------Ana Maria Cardenas, Sebastian Caldas-------------------------------
 */

/**
 * Algoritmos
 * Se encarga de implementar todos los algoritmos de seguridad.
 */
public class Algoritmos 
{
	/**
	 * Genera las llaves asimetricos para la comunicacion con el Servidor.
	 * @param asimetrico Algoritmo asimetrico escogido
	 */
	public KeyPair generarLlavesAsimetricas(String asimetrico) throws NoSuchAlgorithmException
	{
		KeyPairGenerator generador = KeyPairGenerator.getInstance(asimetrico);
		generador.initialize(1024, new SecureRandom());
		KeyPair llavesAsimetricas = generador.generateKeyPair();	
		return llavesAsimetricas;
	}
	
	/**
	 * Genera el certificado del Cliente.
	 * @param llavesAsimetricas Llaves asimetricas del cliente
	 * 			La publica ira asociada al certificado
	 * 			La privada firmara el certificado
	 */
	public X509Certificate generarCertificado(KeyPair llavesAsimetricas) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, SignatureException
	{
		X509V3CertificateGenerator generador = new X509V3CertificateGenerator();
		
		generador.setSerialNumber(BigInteger.valueOf(1020788794));
		
		//El certificado dura dos meses
		generador.setNotBefore(new Date(System.currentTimeMillis() - 2678400000L));
		generador.setNotAfter(new Date(System.currentTimeMillis() + 2678400000L));

		//Nombre del asociado a la llave privada que firma el certificado
		//CardenasCaldas INC es la entidad que firma tal certificado, en realidad deberia ser una entidad certificadora
		generador.setIssuerDN(new X500Principal("CN=CardenasCaldasINC"));
		
		//Nombre del asociado a la llave publica que se adjunta al certificado
		//CardenasCaldas INC esta autofirmando, entonces ambas llaves se asocian a el
		generador.setSubjectDN(new X500Principal("CN=CardenasCaldasINC"));
		generador.setPublicKey(llavesAsimetricas.getPublic());
		
		//Algoritmo para la firma. Se usa SHA pues MD5 ya se considera inseguro
		//Al usar SHA256WITHRSAENCRYPTION obtengo un java.security.NoSuchAlgorithmException
		generador.setSignatureAlgorithm("SHA256WITHRSA");
				
		X509Certificate certificado = generador.generate(llavesAsimetricas.getPrivate());
		return certificado;
	}
	
	/**
	 * Desencripta usando una llave asimetrica.
	 * @param mensaje_desencriptar Bytes del mensaje a desencriptar
	 * @param llave_asimetrica Llave asimetrica con la que se descifrara
	 * @param algoritmo Algortimo asimetrico para hacer la desencripcion
	 */
	public  byte[] desencripcionAsimetrica (byte[] mensaje_desencriptar, Key llave_asimetrica, String algoritmo) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		if (algoritmo.equals(Cliente.DES)|| algoritmo.equals(Cliente.AES))
			algoritmo += "/ECB/PKCS5Padding";
		Cipher cipher = Cipher.getInstance(algoritmo);
		cipher.init(2, llave_asimetrica);
		return cipher.doFinal(mensaje_desencriptar);
	}

	/**
	 * Encripta usando una llave asimetrica.
	 * @param mensaje_encriptar Bytes del mensaje a encriptar
	 * @param llave_asimetrica Llave asimetrica con la que se cifrara
	 * @param algoritmo Algortimo asimetrico para hacer la encripcion
	 */
	public byte[] encriptacionSimetrica(byte[] mensaje_encriptar,
		SecretKey llave_simetrica, String algoritmo) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		if (algoritmo.equals(Cliente.DES)|| algoritmo.equals(Cliente.AES))
				algoritmo += "/ECB/PKCS5Padding";
		Cipher cipher = Cipher.getInstance(algoritmo);
		cipher.init(1, llave_simetrica);
		return cipher.doFinal(mensaje_encriptar);

	}

	/**
	 * Calcula el HMAC del mensaje.
	 * @param bytes_mensaje Bytes del mensaje del cual se quiere el HMAC
	 * @param llave_simetrica Llave simetrica que se usara para producir el HMAC
	 * @param hash Algortimo para producir el HMAC
	 */
	public byte[] hmac(byte[] bytes_mensaje, SecretKey llave_simetrica, String hash) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac mac = Mac.getInstance(hash);
		mac.init(llave_simetrica);
		byte[] bytes = mac.doFinal(bytes_mensaje);
		return bytes;
	}
	
	/**
	 * Encripta usando una llave simetrica.
	 * @param mensaje_encriptar Bytes del mensaje a encriptar
	 * @param llave_simetrica Llave simetrica con la que se cifrara
	 * @param algoritmo Algortimo simetrico para hacer la encripcion
	 */
	public byte[] encripcionAsimetrica(byte[] mensaje_encriptar, Key llave_simetrica, String algoritmo)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
	{
		Cipher cipher = Cipher.getInstance(algoritmo);
		cipher.init(1, llave_simetrica);
		return cipher.doFinal(mensaje_encriptar);
	}
}
