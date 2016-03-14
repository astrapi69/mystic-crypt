package de.alpharogroup;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.NoSuchPaddingException;

import de.alpharogroup.crypto.BaseDecryptor;

public class SimpleBaseDecryptor extends BaseDecryptor<Integer, Integer>
{

	private static final long serialVersionUID = 1L;

	public SimpleBaseDecryptor(final String privateKey)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException
	{
		super(privateKey);
	}


	@Override
	public Integer decrypt(final Integer encypted) throws Exception
	{
		final byte[] buf = new byte[1];
        buf[0] = (byte)(encypted.intValue());
        System.out.println(buf.length);
        final byte[] utf8 = this.cipher.doFinal(buf);
		return (int)utf8[0];
	}

}
