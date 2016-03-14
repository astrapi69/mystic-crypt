package de.alpharogroup;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import de.alpharogroup.crypto.AbstractCryptor;
import de.alpharogroup.crypto.interfaces.StreamEncryptor;

public class BaseStreamEncryptor extends AbstractCryptor implements StreamEncryptor
{

	/**
	 *
	 */
	private static final long serialVersionUID = 1L;

	public BaseStreamEncryptor(final String privateKey)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException
	{
		super(privateKey);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected final int getOperationMode()
	{
		return Cipher.ENCRYPT_MODE;
	}

	@Override
	public int encrypt(final int toEncrypt) throws Exception
	{
		final byte[] buf = new byte[1];
        buf[0] = (byte)(toEncrypt);
        final byte[] utf8 = this.cipher.doFinal(buf);
		return utf8[0];
	}

	@Override
	public byte[] encrypt(final byte[] toEncrypt) throws Exception
	{
		final byte[] utf8 = this.cipher.doFinal(toEncrypt);
		return utf8;
	}

}
