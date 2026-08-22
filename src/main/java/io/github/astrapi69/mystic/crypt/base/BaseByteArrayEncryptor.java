/*
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
package io.github.astrapi69.mystic.crypt.base;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.lang3.ArrayUtils;

import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.mystic.crypt.algorithm.MysticSymmetricAlgorithm;
import io.github.astrapi69.mystic.crypt.core.AbstractByteArrayEncryptor;
import io.github.astrapi69.random.number.RandomByteFactory;

/**
 * The class {@link BaseByteArrayEncryptor} can encrypt a byte array with his symmetric key
 */
public class BaseByteArrayEncryptor extends AbstractByteArrayEncryptor
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new {@link BaseByteArrayEncryptor} with the given {@link CryptModel} object
	 *
	 * @param model
	 *            The crypt model
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
	public BaseByteArrayEncryptor(final CryptModel<Cipher, SecretKey, String> model)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(model);
	}

	/**
	 * Instantiates a new {@link BaseByteArrayEncryptor} with the given {@link SecretKey} object
	 *
	 * @param symmetricKey
	 *            The symmetric key.
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
	public BaseByteArrayEncryptor(final SecretKey symmetricKey)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(symmetricKey);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] encrypt(final byte[] toEncrypt) throws Exception
	{
		final String algorithm = newAlgorithm();
		if (needsRandomNonce(algorithm))
		{
			// a fresh nonce must be generated for every encryption with this transformation
			final byte[] iv = RandomByteFactory.randomByteArray(NONCE_LENGTH);
			final Cipher cipher = newSymmetricCipher(model.getKey(), algorithm, iv,
				newOperationMode());
			return ArrayUtils.addAll(iv, cipher.doFinal(toEncrypt));
		}
		Cipher cipher = newCipher(model.getKey());
		final byte[] encrypted = cipher.doFinal(toEncrypt);
		return encrypted;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Cipher newCipher(final SecretKey key, final String algorithm, final byte[] salt,
		final int iterationCount, final int operationMode)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		final byte[] iv = needsRandomNonce(algorithm)
			? RandomByteFactory.randomByteArray(NONCE_LENGTH)
			: null;
		return newSymmetricCipher(key, algorithm, iv, operationMode);
	}

	/**
	 * Builds a new {@link Cipher} for the given transformation. For GCM the given {@code iv} is
	 * used to build a {@link GCMParameterSpec}; for ChaCha20-Poly1305 it is used to build a plain
	 * {@link IvParameterSpec}; for any other transformation the {@code iv} is ignored and the
	 * cipher is initialized without parameters, as before.
	 *
	 * @param key
	 *            the key
	 * @param algorithm
	 *            the full cipher transformation
	 * @param iv
	 *            the initialization vector/nonce, or {@code null} for a transformation that doesn't
	 *            need one
	 * @param operationMode
	 *            the operation mode for the new cipher object
	 * @return the initialized cipher
	 */
	private Cipher newSymmetricCipher(final SecretKey key, final String algorithm, final byte[] iv,
		final int operationMode) throws NoSuchAlgorithmException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException
	{
		final Cipher cipher = Cipher.getInstance(algorithm);
		if (isGcmTransformation(algorithm))
		{
			cipher.init(operationMode, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
		}
		else if (isChaCha20Poly1305Transformation(algorithm))
		{
			cipher.init(operationMode, key, new IvParameterSpec(iv));
		}
		else
		{
			cipher.init(operationMode, key);
		}
		return cipher;
	}

	/**
	 * Checks if the given transformation is the GCM transformation used as the default.
	 *
	 * @param algorithm
	 *            the transformation to check
	 * @return true if it is the GCM transformation
	 */
	private static boolean isGcmTransformation(final String algorithm)
	{
		return MysticSymmetricAlgorithm.AES_GCM_NO_PADDING.getAlgorithm().equals(algorithm);
	}

	/**
	 * Checks if the given transformation is the ChaCha20-Poly1305 transformation.
	 *
	 * @param algorithm
	 *            the transformation to check
	 * @return true if it is the ChaCha20-Poly1305 transformation
	 */
	private static boolean isChaCha20Poly1305Transformation(final String algorithm)
	{
		return MysticSymmetricAlgorithm.CHACHA20_POLY1305.getAlgorithm().equals(algorithm);
	}

	/**
	 * Checks if the given transformation requires a fresh random nonce/IV to be generated for every
	 * encryption and prepended to the ciphertext.
	 *
	 * @param algorithm
	 *            the transformation to check
	 * @return true if a fresh nonce is required
	 */
	private static boolean needsRandomNonce(final String algorithm)
	{
		return isGcmTransformation(algorithm) || isChaCha20Poly1305Transformation(algorithm);
	}

	/**
	 * The length in bytes of a nonce/initialization vector (96-bit, shared by GCM per NIST SP
	 * 800-38D and by ChaCha20-Poly1305 per RFC 8439).
	 */
	private static final int NONCE_LENGTH = 12;

	/** The length in bits of the GCM authentication tag. */
	private static final int GCM_TAG_LENGTH_BITS = 128;

}
