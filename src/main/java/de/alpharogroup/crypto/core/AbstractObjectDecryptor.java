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

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import de.alpharogroup.crypto.api.GenericObjectDecryptor;
import de.alpharogroup.crypto.factories.CipherFactory;
import de.alpharogroup.crypto.factories.KeySpecFactory;
import de.alpharogroup.crypto.model.CryptModel;

/**
 * The abstract class {@link AbstractObjectDecryptor} provides a base
 * implementation for decrypting {@link File} objects.
 *
 * @param <D> the generic type of the decorator objects
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public abstract class AbstractObjectDecryptor<R, D> extends AbstractDecryptor<Cipher, String, D>
		implements GenericObjectDecryptor<R> {

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
	public AbstractObjectDecryptor(final CryptModel<Cipher, String, D> model)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, UnsupportedEncodingException {
		super(model);
	}

	/**
	 * Constructor with a private key.
	 *
	 * @param privateKey The private key.
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
	public AbstractObjectDecryptor(final String privateKey)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, UnsupportedEncodingException {
		super(privateKey);
	}

	/**
	 * Factory method for creating a new {@link Cipher} from the given parameters.
	 * This method is invoked in the constructor from the derived classes and can be
	 * overridden so users can provide their own version of a new {@link Cipher}
	 * from the given parameters.
	 *
	 * @param operationMode the operation mode
	 * @param key           the key
	 * @param paramSpec     the param spec
	 * @param alg           the alg
	 * @return the cipher
	 *
	 * @throws NoSuchAlgorithmException           is thrown if instantiation of the
	 *                                            SecretKeyFactory object fails.
	 * @throws NoSuchPaddingException             is thrown if instantiation of the
	 *                                            cipher object fails.
	 * @throws InvalidKeyException                is thrown if initialization of the
	 *                                            cipher object fails.
	 * @throws InvalidAlgorithmParameterException is thrown if initialization of the
	 *                                            cipher object fails.
	 */
	protected Cipher newCipher(final int operationMode, final SecretKey key, final AlgorithmParameterSpec paramSpec,
			final String alg) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException {
		return CipherFactory.newCipher(operationMode, key, paramSpec, alg);
	}

	/**
	 * Factory method for creating a new {@link Cipher} from the given parameters.
	 * This method is invoked in the constructor from the derived classes and can be
	 * overridden so users can provide their own version of a new {@link Cipher}
	 * from the given parameters.
	 *
	 * @param privateKey     the private key
	 * @param algorithm      the algorithm
	 * @param salt           the salt.
	 * @param iterationCount the iteration count
	 * @param operationMode  the operation mode for the new cipher object
	 * @return the cipher
	 *
	 * @throws NoSuchAlgorithmException           is thrown if instantiation of the
	 *                                            SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException            is thrown if generation of the
	 *                                            SecretKey object fails.
	 * @throws NoSuchPaddingException             is thrown if instantiation of the
	 *                                            cipher object fails.
	 * @throws InvalidKeyException                is thrown if initialization of the
	 *                                            cipher object fails.
	 * @throws InvalidAlgorithmParameterException is thrown if initialization of the
	 *                                            cipher object fails.
	 * @throws UnsupportedEncodingException       is thrown if the named charset is
	 *                                            not supported.
	 */
	@Override
	protected Cipher newCipher(final String privateKey, final String algorithm, final byte[] salt,
			final int iterationCount, final int operationMode)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, UnsupportedEncodingException {
		final KeySpec keySpec = newKeySpec(privateKey, salt, iterationCount);
		final SecretKeyFactory factory = newSecretKeyFactory(algorithm);
		final SecretKey key = factory.generateSecret(keySpec);
		final AlgorithmParameterSpec paramSpec = newAlgorithmParameterSpec(salt, iterationCount);
		return newCipher(operationMode, key, paramSpec, key.getAlgorithm());
	}

	/**
	 * Factory method for creating a new {@link KeySpec} from the given private key.
	 * This method is invoked in the constructor from the derived classes and can be
	 * overridden so users can provide their own version of a new {@link KeySpec}
	 * from the given private key.
	 *
	 * @param privateKey     the private key
	 * @param salt           the salt
	 * @param iterationCount the iteration count
	 * @return the new {@link KeySpec} from the given private key.
	 */
	protected KeySpec newKeySpec(final String privateKey, final byte[] salt, final int iterationCount) {
		return KeySpecFactory.newPBEKeySpec(privateKey, salt, iterationCount);
	}

}
