/**
 * --------------------------------Infraestructura Computacional--------------------------------
 * -----------Sistema de Gestion Empresarial y Operativa de una Compañia Transportadora---------
 * ---------------------------------Caso 2 - Canales Seguros------------------------------------
 * --------------------------Ana Maria Cardenas, Sebastian Caldas-------------------------------
 */

/**
 * HexaManager
 * Se encarga de pasar a y desde hexadecimal.
 */
public class HexaManager {
	
	/**
	 * Convierte el mensaje a hexadecimal
	 * @param mensajeEncriptado Mensaje a convertir en hexadecimal
	 */
	public String toHexa(byte[] mensajeEncriptado)
	{
		String rta = "";
	    for (int i = 0; i < mensajeEncriptado.length; i++) {
	    	String g = Integer.toHexString((char)mensajeEncriptado[i] & 0xFF);
	    	rta = rta + (g.length() == 1 ? "0" : "") + g;
	    }
		return rta;
	}
	
	/**
	 * Convierte el mensaje desde hexadecimal
	 * @param respuestaEncriptada Mensaje a convertir desde hexadecimal
	 */
	public byte[] fromHexa(String respuestaEncriptada)
	{
		byte[] bytes_encriptados = new byte[respuestaEncriptada.length()/2];
		for (int i = 0; i < bytes_encriptados.length; i++) {
			bytes_encriptados[i] =((byte)Integer.parseInt(respuestaEncriptada.substring(i * 2, (i + 1) * 2), 16));
		}
		return bytes_encriptados;
	}
}
