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
package de.alpharogroup.crypto.aes;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

import de.alpharogroup.check.Check;
import de.alpharogroup.crypto.algorithm.AesAlgorithm;
import de.alpharogroup.crypto.algorithm.Algorithm;
import de.alpharogroup.crypto.core.BaseStringEncryptor;

/**
 * The class {@link HexEncryptor} is the pendant class of {@link HexDecryptor} and encrypts given
 * String objects that can be decrypted with {@link HexDecryptor}. For an example see the unit test.
 */
public class HexEncryptor extends BaseStringEncryptor
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new {@link HexEncryptor} from the given parameters.
	 *
	 * @param privateKey
	 *            The private key.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public HexEncryptor(final String privateKey)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		this(privateKey, AesAlgorithm.AES);
	}

	/**
	 * Instantiates a new {@link HexEncryptor} from the given parameters.
	 *
	 * @param privateKey
	 *            The private key.
	 * @param algorithm
	 *            the algorithm
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public HexEncryptor(final String privateKey, final Algorithm algorithm)
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
	 *             the invalid key exception is thrown if initialization of the cypher object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown by get the byte array of the private key String object fails or if the
	 *             named charset is not supported.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws IllegalBlockSizeException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws BadPaddingException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 */
	@Override
	public String encrypt(final String string)
		throws InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException,
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		final byte[] utf8 = string.getBytes("UTF-8");
		final byte[] encrypt = getModel().getCipher().doFinal(utf8);
		final char[] original = Hex.encodeHex(encrypt, false);
		return new String(original);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String newAlgorithm()
	{
		getModel().setAlgorithm(AesAlgorithm.AES);
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
		final SecretKeySpec skeySpec = new SecretKeySpec(privateKey.getBytes("UTF-8"),
			getModel().getAlgorithm().getAlgorithm());
		final Cipher cipher = Cipher.getInstance(getModel().getAlgorithm().getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		return cipher;
	}

}
