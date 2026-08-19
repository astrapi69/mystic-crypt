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
package io.github.astrapi69.mystic.crypt.hex;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.ArrayUtils;

import io.github.astrapi69.check.Check;
import io.github.astrapi69.crypt.api.algorithm.AesAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.Algorithm;
import io.github.astrapi69.crypt.data.factory.KeySpecFactory;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.crypt.data.model.CryptObjectDecorator;
import io.github.astrapi69.mystic.crypt.algorithm.MysticSymmetricAlgorithm;
import io.github.astrapi69.mystic.crypt.core.AbstractStringEncryptor;
import io.github.astrapi69.mystic.crypt.decorator.CryptObjectDecoratorExtensions;
import io.github.astrapi69.random.number.RandomByteFactory;

/**
 * The class {@link HexableEncryptor} is the pendant class of {@link HexableDecryptor} and encrypts
 * given String objects that can be decrypted with {@link HexableDecryptor}. For an example see the
 * unit test.
 */
public class HexableEncryptor extends AbstractStringEncryptor
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new {@link HexableEncryptor} from the given {@link CryptModel} parameter
	 *
	 * @param model
	 *            The crypt model
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
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public HexableEncryptor(final CryptModel<Cipher, String, String> model)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(model);
	}

	/**
	 * Instantiates a new {@link HexableEncryptor} from the given parameters.
	 *
	 * @param privateKey
	 *            the private key
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
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public HexableEncryptor(final String privateKey)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		this(privateKey, MysticSymmetricAlgorithm.AES_GCM_NO_PADDING);
	}

	@Override
	public byte[] encrypt(byte[] toEncrypt) throws Exception
	{
		throw new UnsupportedOperationException("");
	}

	/**
	 * Instantiates a new {@link HexableEncryptor} from the given parameters.
	 *
	 * @param privateKey
	 *            The private key.
	 * @param algorithm
	 *            the algorithm
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
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public HexableEncryptor(final String privateKey, final Algorithm algorithm)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(privateKey);
		Check.get().notNull(algorithm, "algorithm");
		getModel().setAlgorithm(algorithm);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @throws InvalidKeyException
	 *             the invalid key exception is thrown if initialization of the cipher object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown by get the byte array of the private key String object fails or if the
	 *             named charset is not supported.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws IllegalBlockSizeException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws BadPaddingException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 */
	@Override
	public String encrypt(final String string) throws InvalidKeyException,
		UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException,
		IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
	{
		List<CryptObjectDecorator<String>> decorators = getModel().getDecorators();
		String decoratedString = string;
		if (decorators != null && !decorators.isEmpty())
		{
			for (int i = 0; i < decorators.size(); i++)
			{
				decoratedString = CryptObjectDecoratorExtensions
					.decorateWithStringDecorator(decoratedString, decorators.get(i));
			}
		}
		final byte[] utf8 = decoratedString.getBytes(StandardCharsets.UTF_8);
		final String algorithm = newAlgorithm();
		final byte[] output;
		if (needsRandomNonce(algorithm))
		{
			// a fresh nonce must be generated for every encryption with this transformation; the
			// cipher cached at construction time (if any) must never be reused across calls
			final byte[] iv = RandomByteFactory.randomByteArray(NONCE_LENGTH);
			final Cipher cipher = newSymmetricCipher(getModel().getKey(), algorithm, iv,
				Cipher.ENCRYPT_MODE);
			output = ArrayUtils.addAll(iv, cipher.doFinal(utf8));
		}
		else
		{
			output = getModel().getCipher().doFinal(utf8);
		}
		final char[] original = Hex.encodeHex(output, false);
		return new String(original);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String newAlgorithm()
	{
		if (getModel().getAlgorithm() == null)
		{
			getModel().setAlgorithm(MysticSymmetricAlgorithm.AES_GCM_NO_PADDING);
		}
		return getModel().getAlgorithm().getAlgorithm();
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
		final byte[] iv = needsRandomNonce(algorithm)
			? RandomByteFactory.randomByteArray(NONCE_LENGTH)
			: null;
		return newSymmetricCipher(privateKey, algorithm, iv, operationMode);
	}

	/**
	 * Builds a new {@link Cipher} for the given transformation. For GCM the given {@code iv} is
	 * used to build a {@link GCMParameterSpec}; for ChaCha20-Poly1305 it is used to build a plain
	 * {@link IvParameterSpec}; for any other (legacy) transformation the {@code iv} is ignored and
	 * the cipher is initialized without parameters, as before.
	 *
	 * @param privateKey
	 *            the private key
	 * @param algorithm
	 *            the full cipher transformation, e.g. {@code "AES/GCM/NoPadding"} or the legacy
	 *            bare {@code "AES"}
	 * @param iv
	 *            the initialization vector/nonce, or {@code null} for a transformation that doesn't
	 *            need one
	 * @param operationMode
	 *            the operation mode for the new cipher object
	 * @return the initialized cipher
	 */
	private Cipher newSymmetricCipher(final String privateKey, final String algorithm,
		final byte[] iv, final int operationMode) throws NoSuchAlgorithmException,
		NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		final SecretKeySpec skeySpec = KeySpecFactory.newSecretKeySpec(
			privateKey.getBytes(StandardCharsets.UTF_8), AesAlgorithm.AES.getAlgorithm());
		final Cipher cipher = Cipher.getInstance(algorithm);
		if (isGcmTransformation(algorithm))
		{
			cipher.init(operationMode, skeySpec, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
		}
		else if (isChaCha20Poly1305Transformation(algorithm))
		{
			cipher.init(operationMode, skeySpec, new IvParameterSpec(iv));
		}
		else
		{
			cipher.init(operationMode, skeySpec);
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
	 * Checks if the given transformation is the ChaCha20-Poly1305 transformation. Note that a
	 * ChaCha20 key must be exactly 32 bytes - unlike AES, which accepts 16/24/32 - so the
	 * {@code privateKey} String's UTF-8 byte length must be exactly 32 when using this
	 * transformation.
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
