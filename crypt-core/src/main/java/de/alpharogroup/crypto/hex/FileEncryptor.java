package de.alpharogroup.crypto.hex;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import de.alpharogroup.crypto.core.AbstractFileEncryptor;
import de.alpharogroup.crypto.io.CryptoCipherInputStream;
import de.alpharogroup.crypto.model.CryptModel;

public class FileEncryptor extends AbstractFileEncryptor
{

	private static final long serialVersionUID = 1L;

	public FileEncryptor(final CryptModel<Cipher, String> model)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(model);
	}

	@Override
	public File encrypt(final File toEncrypt) throws Exception
	{

		final InputStream fis = new FileInputStream(toEncrypt);
		final CryptoCipherInputStream cis = new CryptoCipherInputStream(fis,
			getModel().getCipher());
		final File encryptedFile = newEncryptedFile(".", "encrypted.txt");

		final FileOutputStream out = new FileOutputStream(encryptedFile);

		int c;

		while ((c = cis.read()) != -1)
		{
			out.write(c);
		}

		cis.close();
		out.close();
		return encryptedFile;
	}

	protected File newEncryptedFile(final String parent, final String child) {
		return new File(parent, child);
	}

}
