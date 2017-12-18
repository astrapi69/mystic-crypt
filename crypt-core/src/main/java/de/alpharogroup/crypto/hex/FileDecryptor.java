package de.alpharogroup.crypto.hex;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import de.alpharogroup.crypto.core.AbstractFileDecryptor;
import de.alpharogroup.crypto.model.CryptModel;

public class FileDecryptor extends AbstractFileDecryptor
{

	public FileDecryptor(final CryptModel<Cipher, String> model)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(model);
	}

	private static final long serialVersionUID = 1L;

	@Override
	public File decrypt(final File encrypted) throws Exception
	{
		// TODO Auto-generated method stub
		return null;
	}


}
