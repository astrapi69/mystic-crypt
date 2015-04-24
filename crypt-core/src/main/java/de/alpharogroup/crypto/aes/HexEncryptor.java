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
import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.algorithm.Algorithm;
import de.alpharogroup.crypto.interfaces.Encryptor;

import org.apache.commons.codec.binary.Hex;

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
	public HexEncryptor(final String privateKey, Algorithm algorithm)
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
	 * @see net.sourceforge.jaulp.crypto.interfaces.Encryptor#encrypt(java.lang.String)
	 */
	public String encrypt(final String string) throws InvalidKeyException,
		UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException,
		IllegalBlockSizeException, BadPaddingException
	{
		initialize();
		final byte[] utf8 = string.getBytes("UTF-8");
		final byte[] encrypt = this.cipher.doFinal(utf8);
		char[] original = Hex.encodeHex(encrypt, false);
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
			SecretKeySpec skeySpec = new SecretKeySpec(key, algorithm.getAlgorithm());
			this.cipher = Cipher.getInstance(algorithm.getAlgorithm());
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		}
	}

}
