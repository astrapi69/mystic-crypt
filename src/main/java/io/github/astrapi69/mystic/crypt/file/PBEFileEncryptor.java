/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package io.github.astrapi69.mystic.crypt.file;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.Normalizer;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.io.FilenameUtils;

import io.github.astrapi69.crypt.data.factory.CipherFactory;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.crypt.data.model.CryptObjectDecorator;
import io.github.astrapi69.file.delete.DeleteFileExtensions;
import io.github.astrapi69.mystic.crypt.core.AbstractFileEncryptor;
import io.github.astrapi69.mystic.crypt.decorator.CryptObjectDecoratorExtensions;
import io.github.astrapi69.mystic.crypt.io.CryptoCipherInputStream;

/**
 * The class {@link PBEFileEncryptor} can encrypt files with the given crypt model.
 */
public class PBEFileEncryptor extends AbstractFileEncryptor
{

	/** The constant for the default encrypted file extension */
	public static final String DEFAULT_ENCRYPTED_FILE_EXTENSION = ".enc";
	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;
	/**
	 * If this flag is true the given file that will be given for encryption will be deleted and
	 * only the encrypted file will be the result, otherwise both files will not be deleted
	 */
	private final boolean deleteFileAfterEncryption;
	/** The encrypted file. */
	private File encryptedFile;
	/** The encrypted file extension */
	private String encryptedFileExtension = DEFAULT_ENCRYPTED_FILE_EXTENSION;

	/**
	 * Instantiates a new {@link PBEFileEncryptor} object with the given {@link CryptModel}
	 *
	 * @param model
	 *            the model
	 * @throws InvalidKeyException
	 *             the invalid key exception
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             the no such padding exception
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public PBEFileEncryptor(final CryptModel<Cipher, String, String> model)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		this(model, null);
	}

	@Override
	public byte[] encrypt(byte[] toEncrypt) throws Exception
	{
		throw new UnsupportedOperationException("");
	}

	/**
	 * Instantiates a new {@link PBEFileEncryptor} object with the given {@link CryptModel} and the
	 * given file
	 *
	 * @param model
	 *            the model
	 * @param encryptedFile
	 *            The file that is the target of the result from the encryption, if null the default
	 *            file will be created. If null the name convention is given name of the file that
	 *            has to be encrypted with the extension '.enc'.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             the no such padding exception
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public PBEFileEncryptor(final CryptModel<Cipher, String, String> model,
		final File encryptedFile)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		this(model, encryptedFile, DEFAULT_ENCRYPTED_FILE_EXTENSION);
	}

	/**
	 * Instantiates a new {@link PBEFileEncryptor} object with the given {@link CryptModel} and the
	 * given file
	 *
	 * @param model
	 *            the model
	 * @param encryptedFile
	 *            The file that is the target of the result from the encryption, if null the default
	 *            file will be created. If null the name convention is given name of the file that
	 *            has to be encrypted with the extension '.enc'.
	 * @param encryptedFileExtension
	 *            the encrypted file extension
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             the no such padding exception
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public PBEFileEncryptor(final CryptModel<Cipher, String, String> model,
		final File encryptedFile, String encryptedFileExtension)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		this(model, encryptedFile, encryptedFileExtension, false);
	}

	/**
	 * Instantiates a new {@link PBEFileEncryptor} object with the given {@link CryptModel} and the
	 * given file
	 *
	 * @param model
	 *            the model
	 * @param encryptedFile
	 *            The file that is the target of the result from the encryption, if null the default
	 *            file will be created. If null the name convention is given name of the file that
	 *            has to be encrypted with the extension '.enc'.
	 * @param encryptedFileExtension
	 *            the encrypted file extension
	 * @param deleteFileAfterEncryption
	 *            if this flag is true the given file that will be given for encryption will be
	 *            deleted and only the encrypted file will be the result, otherwise both files will
	 *            not be deleted
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             the no such padding exception
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public PBEFileEncryptor(final CryptModel<Cipher, String, String> model,
		final File encryptedFile, final String encryptedFileExtension,
		final boolean deleteFileAfterEncryption)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(model);
		this.encryptedFile = encryptedFile;
		this.encryptedFileExtension = encryptedFileExtension;
		this.deleteFileAfterEncryption = deleteFileAfterEncryption;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public File encrypt(final File toEncrypt) throws Exception
	{
		if (encryptedFile == null)
		{
			final String filename = FilenameUtils.getBaseName(toEncrypt.getName());
			encryptedFile = newEncryptedFile(toEncrypt.getParent(),
				filename + encryptedFileExtension);
		}
		List<CryptObjectDecorator<String>> decorators = getModel().getDecorators();
		if (decorators != null && !decorators.isEmpty())
		{
			for (int i = 0; i < decorators.size(); i++)
			{
				CryptObjectDecoratorExtensions.decorateFile(toEncrypt, decorators.get(i));
			}
		}
		try (
			CryptoCipherInputStream cis = new CryptoCipherInputStream(
				new FileInputStream(toEncrypt), getModel().getCipher());
			OutputStream out = new FileOutputStream(encryptedFile))
		{
			int c;
			while ((c = cis.read()) != -1)
			{
				out.write(c);
			}
		}
		if (this.deleteFileAfterEncryption)
		{
			DeleteFileExtensions.delete(toEncrypt);
		}
		return encryptedFile;
	}

	/**
	 *
	 * Factory method for creating the new decrypted {@link File} if it is not exists. This method
	 * is invoked in the constructor from the derived classes and can be overridden so users can
	 * provide their own version of creating the new decrypted {@link File}
	 *
	 * @param parent
	 *            the parent directory
	 * @param child
	 *            the file name
	 * @return the new {@link File} object
	 */
	protected File newEncryptedFile(final String parent, final String child)
	{
		return new File(parent, child);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Cipher newCipher(final String privateKey, final String algorithm, final byte[] salt,
		final int iterationCount, final int operationMode)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		String normalizedPassword = Normalizer.normalize(privateKey, Normalizer.Form.NFC);
		final Cipher cipher = CipherFactory.newPBECipher(normalizedPassword.toCharArray(),
			operationMode, algorithm);
		return cipher;
	}
}
