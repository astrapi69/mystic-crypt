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
package io.github.astrapi69.crypto.key;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import io.github.astrapi69.crypto.algorithm.KeyPairWithModeAndPaddingAlgorithm;
import io.github.astrapi69.crypto.api.FileEncryptor;
import io.github.astrapi69.crypto.core.AbstractEncryptor;
import io.github.astrapi69.crypto.decorator.CryptObjectDecoratorExtensions;
import io.github.astrapi69.crypto.factories.CipherFactory;
import io.github.astrapi69.crypto.io.CryptoCipherInputStream;
import io.github.astrapi69.crypto.model.CryptModel;
import io.github.astrapi69.crypto.model.CryptObjectDecorator;
import org.apache.commons.io.FilenameUtils;

/**
 * The class {@link PublicKeyFileEncryptor} can encrypt a byte array with his public key.
 */
public class PublicKeyFileEncryptor extends AbstractEncryptor<Cipher, PublicKey, String>
	implements
		FileEncryptor
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/** The encrypted file. */
	private File encryptedFile;

	/**
	 * Instantiates a new {@link PublicKeyFileEncryptor} with the given {@link CryptModel}.
	 *
	 * @param model
	 *            The crypt model.
	 *
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public PublicKeyFileEncryptor(final CryptModel<Cipher, PublicKey, String> model)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		this(model, null);
	}

	/**
	 * Instantiates a new {@link PublicKeyFileEncryptor} with the given {@link CryptModel}.
	 *
	 * @param model
	 *            The crypt model.
	 * @param encryptedFile
	 *            The file that is the target of the result from the encryption, if null the default
	 *            file will be created. If null the name convention is given name of the file that
	 *            has to be encrypted with the extension '.enc'.
	 *
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public PublicKeyFileEncryptor(final CryptModel<Cipher, PublicKey, String> model,
		final File encryptedFile)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(model);
		this.encryptedFile = encryptedFile;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public File encrypt(File toEncrypt) throws Exception
	{
		if (encryptedFile == null)
		{
			final String filename = FilenameUtils.getBaseName(toEncrypt.getName());
			encryptedFile = newEncryptedFile(toEncrypt.getParent(), filename + ".enc");
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
		return encryptedFile;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String newAlgorithm()
	{
		if (getModel().getAlgorithm() == null)
		{
			getModel().setAlgorithm(
				KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA1AndMGF1Padding);
		}
		return getModel().getAlgorithm().getAlgorithm();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Cipher newCipher(final PublicKey key, final String algorithm, final byte[] salt,
		final int iterationCount, final int operationMode)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		final Cipher cipher = CipherFactory.newCipher(algorithm);
		cipher.init(operationMode, key);
		return cipher;
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

}
