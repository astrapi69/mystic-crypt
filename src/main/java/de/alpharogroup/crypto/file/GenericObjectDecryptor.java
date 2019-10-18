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
package de.alpharogroup.crypto.file;

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

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;

import de.alpharogroup.crypto.core.AbstractObjectDecryptor;
import de.alpharogroup.crypto.model.CryptModel;
import lombok.NonNull;

/**
 * The class {@link GenericObjectDecryptor} can decrypt files from the given crypt model bean
 *
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
	 *             is thrown if initialization of the cypher object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public GenericObjectDecryptor(final CryptModel<Cipher, String, D> model)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(model);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public R decrypt(final @NonNull File encrypted) throws Exception
	{
		onBeforeDecrypt(encrypted);
		R genericObject = onDecrypt(encrypted);
		onAfterDecrypt(encrypted);
		return genericObject;
	}


	protected void onBeforeDecrypt(final @NonNull File encrypted) {

	}

	@SuppressWarnings("unchecked")
	private R onDecrypt(final @NonNull File encrypted) throws IOException, ClassNotFoundException {
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

	protected void onAfterDecrypt(final @NonNull File encrypted) {

	}

}
