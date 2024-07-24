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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;

import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.mystic.crypt.core.AbstractObjectDecryptor;

/**
 * The class {@link GenericObjectDecryptor} can decrypt files from the given crypt model bean
 *
 * @param <R>
 *            the generic type of the object to decrypt
 * @param <D>
 *            the generic type of the decorator objects
 */
public class GenericObjectDecryptor<R, D> extends AbstractObjectDecryptor<R, D>
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new {@link GenericObjectDecryptor}
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
	public GenericObjectDecryptor(final CryptModel<Cipher, String, D> model)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(model);
	}

	@Override
	protected Cipher newCipher(String key, String algorithm, byte[] salt, int iterationCount,
		int operationMode)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		return super.newCipher(key, algorithm, salt, iterationCount, operationMode);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public R decrypt(final File encrypted) throws Exception
	{
		Objects.requireNonNull(encrypted);
		onBeforeDecrypt(encrypted);
		R genericObject = onDecrypt(encrypted);
		onAfterDecrypt(encrypted);
		return genericObject;
	}

	/**
	 * Method to be called after decryption. It handles any post-decryption processing
	 *
	 * @param encrypted
	 *            the encrypted file
	 */
	protected void onAfterDecrypt(final File encrypted)
	{
		Objects.requireNonNull(encrypted);
	}

	/**
	 * Method to be called before decryption. It handles any pre-decryption processing.
	 *
	 * @param encrypted
	 *            the encrypted file
	 */
	protected void onBeforeDecrypt(final File encrypted)
	{
		Objects.requireNonNull(encrypted);
	}

	@SuppressWarnings("unchecked")
	private R onDecrypt(final File encrypted) throws IOException, ClassNotFoundException
	{
		Objects.requireNonNull(encrypted);
		R genericObject = null;
		Cipher cipher = getModel().getCipher();
		try (
			CipherInputStream cipherInputStream = new CipherInputStream(
				new BufferedInputStream(new FileInputStream(encrypted)), cipher);
			ObjectInputStream inputStream = new ObjectInputStream(cipherInputStream);)
		{
			genericObject = (R)inputStream.readObject();
			inputStream.close();
		}
		return genericObject;
	}

}
