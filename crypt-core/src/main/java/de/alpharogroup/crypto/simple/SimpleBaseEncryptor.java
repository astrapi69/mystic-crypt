package de.alpharogroup.crypto.simple;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.NoSuchPaddingException;

import de.alpharogroup.crypto.core.BaseEncryptor;

public class SimpleBaseEncryptor extends BaseEncryptor<Integer, Integer>
{

	private static final long serialVersionUID = 1L;

	public SimpleBaseEncryptor(final String privateKey)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(privateKey);
	}

	@Override
	public Integer encrypt(final Integer toEncrypt) throws Exception
	{
		final byte[] buf = new byte[1];
        buf[0] = (byte)(toEncrypt.intValue());
        final byte[] utf8 = this.cipher.doFinal(buf);
		return (int)utf8[0];
	}

}
