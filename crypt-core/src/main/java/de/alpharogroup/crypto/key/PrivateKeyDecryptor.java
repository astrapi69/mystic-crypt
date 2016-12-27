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
package de.alpharogroup.crypto.key;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import de.alpharogroup.crypto.algorithm.KeyPairWithModeAndPaddingAlgorithm;
import de.alpharogroup.crypto.core.AbstractCryptor;
import de.alpharogroup.crypto.factories.CipherFactory;
import de.alpharogroup.crypto.interfaces.ByteArrayDecryptor;
import de.alpharogroup.crypto.model.CryptModel;

/**
 * The class {@link PrivateKeyDecryptor} decrypts encrypted byte array the was encrypted with the
 * public key of the pendant private key of this class.
 */
public class PrivateKeyDecryptor extends AbstractCryptor<Cipher, PrivateKey>
	implements
		ByteArrayDecryptor
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new {@link PrivateKeyDecryptor} with the given {@link CryptModel}.
	 *
	 * @param model
	 *            The crypt model.
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
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public PrivateKeyDecryptor(final CryptModel<Cipher, PrivateKey> model)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(model);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String newAlgorithm()
	{
		if ( getModel().getAlgorithm() == null) {
			return KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA1AndMGF1Padding.getAlgorithm();
		}
		return getModel().getAlgorithm().getAlgorithm();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Cipher newCipher(final PrivateKey key, final String algorithm, final byte[] salt,
		final int iterationCount, final int operationMode)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		final Cipher cipher = CipherFactory.newCipher(algorithm);
		cipher.init(operationMode, key);
		return cipher;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] decrypt(final byte[] encrypted) throws Exception
	{
		final byte[] decrypted = getModel().getCipher().doFinal(encrypted);
		return decrypted;
	}

}
