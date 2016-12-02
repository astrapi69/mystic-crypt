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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import org.apache.commons.codec.binary.Hex;

import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.algorithm.Algorithm;
import de.alpharogroup.crypto.interfaces.Encryptor;

/**
 * Instantiates a new hex encryptor.
 */
@NoArgsConstructor
public class HexEncryptor implements Encryptor
{

	/**
	 * The Cipher object.
	 */
	@Getter
	@Setter
	private Cipher cipher = null;

	/**
	 * The private key.
	 */
	@Getter
	@Setter
	private String privateKey = null;

	/**
	 * The algorithm.
	 */
	@Getter
	@Setter
	private Algorithm algorithm = Algorithm.AES;

	/**
	 * The flag initialized that indicates if the cypher is initialized for decryption.
	 *
	 * @return true, if is initialized
	 */
	@Getter(value = AccessLevel.PRIVATE)
	private boolean initialized;

	/**
	 * Default constructor.
	 *
	 * @param privateKey
	 *            The private key.
	 */
	public HexEncryptor(final String privateKey)
	{
		this.setPrivateKey(privateKey);
	}

	/**
	 * Default constructor.
	 *
	 * @param privateKey
	 *            The private key.
	 * @param algorithm
	 *            the algorithm
	 */
	public HexEncryptor(final String privateKey, final Algorithm algorithm)
	{
		this.setPrivateKey(privateKey);
		this.algorithm = algorithm;
	}

	/**
	 * Encrypt the given String.
	 *
	 * @param string
	 *            The String to encrypt.
	 * @return The encrypted String.
	 * @throws InvalidKeyException
	 *             the invalid key exception is thrown if initialization of the cypher object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown by get the byte array of the private key String object fails.
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
	public String encrypt(final String string) throws InvalidKeyException,
		UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException,
		IllegalBlockSizeException, BadPaddingException
	{
		initialize();
		final byte[] utf8 = string.getBytes("UTF-8");
		final byte[] encrypt = this.cipher.doFinal(utf8);
		final char[] original = Hex.encodeHex(encrypt, false);
		return new String(original);
	}

	/**
	 * Initializes the {@link HexEncryptor} object.
	 *
	 * @throws UnsupportedEncodingException
	 *             is thrown by get the byte array of the private key String object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeyException
	 *             the invalid key exception is thrown if initialization of the cypher object fails.
	 */
	private void initialize() throws UnsupportedEncodingException, NoSuchAlgorithmException,
		NoSuchPaddingException, InvalidKeyException
	{
		if (!isInitialized())
		{
			byte[] key;
			if (this.getPrivateKey() != null)
			{
				key = this.getPrivateKey().getBytes("UTF-8");
			}
			else
			{
				key = CryptConst.PRIVATE_KEY.getBytes("UTF-8");
			}
			final SecretKeySpec skeySpec = new SecretKeySpec(key, algorithm.getAlgorithm());
			this.cipher = Cipher.getInstance(algorithm.getAlgorithm());
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		}
	}

}
