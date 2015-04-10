
public class HexaManager {
	
	public String toHexa(byte[] mensajeEncriptado)
	{
		String rta = "";
	    for (int i = 0; i < mensajeEncriptado.length; i++) {
	    	String g = Integer.toHexString((char)mensajeEncriptado[i] & 0xFF);
	    	rta = rta + (g.length() == 1 ? "0" : "") + g;
	    }
		return rta;
	}
	
	public byte[] fromHexa(String respuestaEncriptada)
	{
		byte[] bytes_encriptados = new byte[respuestaEncriptada.length()/2];
		for (int i = 0; i < bytes_encriptados.length; i++) {
			bytes_encriptados[i] =((byte)Integer.parseInt(respuestaEncriptada.substring(i * 2, (i + 1) * 2), 16));
		}
		return bytes_encriptados;
	}
}
