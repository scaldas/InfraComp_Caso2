import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class Algoritmos 
{
	public KeyPair generarLlavesAsimetricas(String asimetrico) throws NoSuchAlgorithmException
	{
		KeyPairGenerator generador = KeyPairGenerator.getInstance(asimetrico);
		generador.initialize(1024, new SecureRandom());
		KeyPair llavesAsimetricas = generador.generateKeyPair();	
		return llavesAsimetricas;
	}
	
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
		
		//generador.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
		//generador.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(160));
		//generador.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
		//generador.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(1, "test@test.test")));
		
		X509Certificate certificado = generador.generate(llavesAsimetricas.getPrivate());
		return certificado;
	}
	
	
}
