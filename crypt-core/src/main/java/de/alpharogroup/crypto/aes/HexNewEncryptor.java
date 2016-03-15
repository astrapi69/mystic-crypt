/**
 * Copyright (C) 2007 Asterios Raptis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
import de.alpharogroup.crypto.algorithm.Algorithm;
import de.alpharogroup.crypto.core.BaseEncryptor;
import lombok.Getter;
import lombok.Setter;

/**
 * Instantiates a new hex encryptor.
 */
public class HexNewEncryptor extends BaseEncryptor<String, String>
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * The algorithm.
	 */
	@Getter
	@Setter
	private Algorithm algorithm;


	/**
	 * Default constructor.
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
	public HexNewEncryptor(final String privateKey) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		this(privateKey, Algorithm.AES);
	}

	/**
	 * Default constructor.
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
	public HexNewEncryptor(final String privateKey, final Algorithm algorithm) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(privateKey);
		Check.get().notNull(algorithm, "algorithm");
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
	 *             is thrown by get the byte array of the private key String object fails or  if the named charset is not supported.
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
		final byte[] utf8 = string.getBytes("UTF-8");
		final byte[] encrypt = this.cipher.doFinal(utf8);
		final char[] original = Hex.encodeHex(encrypt, false);
		return new String(original);
	}

	@Override
	protected String newAlgorithm()
	{
		algorithm = Algorithm.AES;
		return algorithm.getAlgorithm();
	}

	@Override
	protected Cipher newCipher(final String privateKey, final String algorithm, final byte[] salt, final int iterationCount,
		final int operationMode) throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{

		final SecretKeySpec skeySpec = new SecretKeySpec(privateKey.getBytes("UTF-8"), this.algorithm.getAlgorithm());
		this.cipher = Cipher.getInstance(this.algorithm.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		return cipher;
	}

}
