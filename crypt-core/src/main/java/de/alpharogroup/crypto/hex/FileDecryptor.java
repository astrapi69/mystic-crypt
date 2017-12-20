package de.alpharogroup.crypto.hex;

import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.io.FilenameUtils;

import de.alpharogroup.crypto.core.AbstractFileDecryptor;
import de.alpharogroup.crypto.io.CryptoCipherOutputStream;
import de.alpharogroup.crypto.model.CryptModel;

public class FileDecryptor extends AbstractFileDecryptor
{

	private static final long serialVersionUID = 1L;

	private File decryptedFile;


	public FileDecryptor(final CryptModel<Cipher, String> model)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(model);
	}

	public FileDecryptor(final CryptModel<Cipher, String> model, File decryptedFile)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		this(model);
		this.decryptedFile = decryptedFile;
	}


	@Override
	public File decrypt(final File encrypted) throws Exception
	{
		if(decryptedFile == null) {
			decryptedFile = newDecryptedFile(encrypted.getParent(), encrypted.getName()+".decrypted");
		}

		final FileOutputStream decryptedOut = new FileOutputStream(decryptedFile);
		final CryptoCipherOutputStream cos = new CryptoCipherOutputStream(decryptedOut,
			getModel().getCipher());
		final InputStream fileInputStream = new FileInputStream(encrypted);

		int c;
		while ((c = fileInputStream.read()) != -1)
		{
			cos.write(c);
		}

		fileInputStream.close();
		cos.close();
		return decryptedFile;
	}

	protected File newDecryptedFile(final String parent, final String child) {
		return new File(parent, child);
	}

}
