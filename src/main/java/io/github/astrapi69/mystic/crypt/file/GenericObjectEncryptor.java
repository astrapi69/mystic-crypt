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

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;

import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.mystic.crypt.core.AbstractObjectEncryptor;

/**
 * The class {@link GenericObjectEncryptor} can encrypt files with the given crypt model.
 *
 * @param <T>
 *            the generic type of the object to encrypt
 *
 * @param <D>
 *            the generic type of the decorator objects
 */
public class GenericObjectEncryptor<T, D> extends AbstractObjectEncryptor<T, D>
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/** The encrypted file. */
	private File encryptedFile;

	/**
	 * Instantiates a new file encryptor.
	 *
	 * @param model
	 *            the model
	 * @param encryptedFile
	 *            is the target of the result from the encryption, if null the default file will be
	 *            created. If null the name convention is given name of the file that has to be
	 *            encrypted with the extension '.enc'.
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
	public GenericObjectEncryptor(final CryptModel<Cipher, String, D> model,
		final File encryptedFile)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(model);
		Objects.requireNonNull(encryptedFile);
		this.encryptedFile = encryptedFile;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public File encrypt(final T toEncrypt) throws Exception
	{
		Objects.requireNonNull(toEncrypt);
		onBeforeEncrypt(toEncrypt);
		onEncrypt(toEncrypt);
		onAfterEncrypt(toEncrypt);
		return encryptedFile;
	}

	/**
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
	 * Method to be called after encryption. It handles any post-encryption processing
	 *
	 * @param toEncrypt
	 *            the generic object to encrypt
	 */
	protected void onAfterEncrypt(final T toEncrypt)
	{
		Objects.requireNonNull(toEncrypt);
	}

	/**
	 * Method to be called before encryption. It handles any pre-encryption processing
	 *
	 * @param toEncrypt
	 *            the generic object to encrypt
	 */
	protected void onBeforeEncrypt(final T toEncrypt)
	{
		Objects.requireNonNull(toEncrypt);
	}

	private void onEncrypt(final T toEncrypt) throws IOException
	{
		Objects.requireNonNull(toEncrypt);
		Cipher cipher = getModel().getCipher();
		try (
			CipherOutputStream cipherOutputStream = new CipherOutputStream(
				new BufferedOutputStream(new FileOutputStream(this.encryptedFile)), cipher);
			ObjectOutputStream outputStream = new ObjectOutputStream(cipherOutputStream);)
		{
			outputStream.writeObject(toEncrypt);
		}
	}

	@Override
	protected Cipher newCipher(String key, String algorithm, byte[] salt, int iterationCount,
		int operationMode)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		return super.newCipher(key, algorithm, salt, iterationCount, operationMode);
	}

	@Override
	public byte[] encrypt(byte[] toEncrypt) throws Exception
	{
		return new byte[0];
	}
}
