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
package io.github.astrapi69.crypto.hex;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import de.alpharogroup.check.Check;
import io.github.astrapi69.crypto.algorithm.AesAlgorithm;
import io.github.astrapi69.crypto.algorithm.Algorithm;
import io.github.astrapi69.crypto.core.AbstractStringDecryptor;
import io.github.astrapi69.crypto.decorator.CryptObjectDecoratorExtensions;
import io.github.astrapi69.crypto.factories.SecretKeyFactoryExtensions;
import io.github.astrapi69.crypto.model.CryptModel;
import io.github.astrapi69.crypto.model.CryptObjectDecorator;

/**
 * The class {@link HexableDecryptor} is the pendant class of {@link HexableEncryptor} and decrypts
 * given String objects that was encrypted with {@link HexableEncryptor}. For an example see the
 * unit test.
 */
public class HexableDecryptor extends AbstractStringDecryptor
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new {@link HexableDecryptor} from the given {@link CryptModel} parameter
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
	public HexableDecryptor(final CryptModel<Cipher, String, String> model)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(model);
	}
	/**
	 * Instantiates a new {@link HexableDecryptor} from the given parameters.
	 *
	 * @param privateKey
	 *            The private key.
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
	public HexableDecryptor(final String privateKey)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		this(privateKey, AesAlgorithm.AES);
	}

	/**
	 * Instantiates a new {@link HexableDecryptor} from the given parameters.
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
	public HexableDecryptor(final String privateKey, final Algorithm algorithm)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(privateKey);
		Check.get().notNull(algorithm, "algorithm");
		getModel().setAlgorithm(algorithm);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String decrypt(final String encypted) throws Exception
	{
		final byte[] dec = HexExtensions.decodeHex(encypted.toCharArray());
		final byte[] utf8 = getModel().getCipher().doFinal(dec);
		String string = new String(utf8, StandardCharsets.UTF_8);
		List<CryptObjectDecorator<String>> decorators = getModel().getDecorators();
		if (decorators != null && !decorators.isEmpty())
		{
			for (int i = decorators.size() - 1; 0 <= i; i--)
			{
				string = CryptObjectDecoratorExtensions.undecorateWithStringDecorator(string,
					decorators.get(i));
			}
		}
		return string;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String newAlgorithm()
	{
		if (getModel().getAlgorithm() == null)
		{
			getModel().setAlgorithm(AesAlgorithm.AES);
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
		final SecretKeySpec skeySpec = SecretKeyFactoryExtensions
			.newSecretKeySpec(privateKey.getBytes(StandardCharsets.UTF_8), algorithm);
		final Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(operationMode, skeySpec);
		return cipher;
	}

}
