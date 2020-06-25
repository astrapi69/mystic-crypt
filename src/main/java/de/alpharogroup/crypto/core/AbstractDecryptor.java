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
package de.alpharogroup.crypto.core;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import de.alpharogroup.crypto.api.Cryptor;
import de.alpharogroup.crypto.model.CryptModel;

/**
 * The abstract class {@link AbstractDecryptor} can be extended for providing
 * the decrypting feature.
 *
 * @param <C> the generic type of the cipher
 * @param <K> the generic type of the key
 * @param <T> the generic type of the decorator objects
 */
public abstract class AbstractDecryptor<C, K, T> extends AbstractCryptor<C, K, T> implements Cryptor {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Constructor with the given {@link CryptModel}.
	 *
	 * @param model The crypt model.
	 * @throws InvalidAlgorithmParameterException is thrown if initialization of the
	 *                                            cipher object fails.
	 * @throws NoSuchPaddingException             is thrown if instantiation of the
	 *                                            SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException            is thrown if generation of the
	 *                                            SecretKey object fails.
	 * @throws NoSuchAlgorithmException           is thrown if instantiation of the
	 *                                            SecretKeyFactory object fails.
	 * @throws InvalidKeyException                is thrown if initialization of the
	 *                                            cipher object fails.
	 * @throws NoSuchAlgorithmException           is thrown if instantiation of the
	 *                                            SecretKeyFactory object fails.
	 * @throws UnsupportedEncodingException       is thrown if the named charset is
	 *                                            not supported.
	 */
	public AbstractDecryptor(final CryptModel<C, K, T> model)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, UnsupportedEncodingException {
		super(model);
	}

	/**
	 * Constructor with a key.
	 *
	 * @param key The key.
	 * @throws InvalidAlgorithmParameterException is thrown if initialization of the
	 *                                            cipher object fails.
	 * @throws NoSuchPaddingException             is thrown if instantiation of the
	 *                                            SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException            is thrown if generation of the
	 *                                            SecretKey object fails.
	 * @throws NoSuchAlgorithmException           is thrown if instantiation of the
	 *                                            SecretKeyFactory object fails.
	 * @throws InvalidKeyException                is thrown if initialization of the
	 *                                            cipher object fails.
	 * @throws NoSuchAlgorithmException           is thrown if instantiation of the
	 *                                            SecretKeyFactory object fails.
	 * @throws UnsupportedEncodingException       is thrown if the named charset is
	 *                                            not supported.
	 */
	public AbstractDecryptor(final K key) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
		super(key);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int newOperationMode() {
		return Cipher.DECRYPT_MODE;
	}

}
