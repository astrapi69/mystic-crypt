package de.alpharogroup;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.NoSuchPaddingException;

import de.alpharogroup.crypto.BaseEncryptor;

public class SimpleBaseEncryptor extends BaseEncryptor<Integer, Integer>
{

	private static final long serialVersionUID = 1L;

	public SimpleBaseEncryptor(final String privateKey)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException
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
