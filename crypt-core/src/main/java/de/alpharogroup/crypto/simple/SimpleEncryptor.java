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
package de.alpharogroup.crypto.simple;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import lombok.AccessLevel;
import lombok.Getter;

import org.apache.commons.codec.binary.Base64;

import de.alpharogroup.check.Check;
import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.interfaces.Encryptor;

/**
 * A simple Encryptor object.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public class SimpleEncryptor implements Encryptor
{

	/**
	 * The Cipher object.
	 */
	private Cipher cipher;

	/**
	 * The private key.
	 */
	@Getter
	private String privateKey;

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
	public SimpleEncryptor(final String privateKey)
	{
		Check.get().notEmpty(privateKey, "privateKey");
		this.privateKey = privateKey;
	}

	/**
	 * Encrypt the given String.
	 * 
	 * @param string
	 *            The String to encrypt.
	 * @return The encrypted String.
	 * @throws UnsupportedEncodingException
	 *             is thrown if get the bytes from the given String object fails.
	 * @throws BadPaddingException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws IllegalBlockSizeException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cypher object fails.
	 *
	 * @see de.alpharogroup.crypto.interfaces.Encryptor#encrypt(java.lang.String)
	 */
	@Override
	public String encrypt(final String string) throws UnsupportedEncodingException,
		IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
		NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidAlgorithmParameterException
	{
		initialize();
		final byte[] utf8 = string.getBytes(CryptConst.ENCODING);
		final byte[] encrypt = this.cipher.doFinal(utf8);
		final String encrypted = new Base64().encodeToString(encrypt);
		return encrypted;
	}

	/**
	 * Initializes the {@link SimpleEncryptor} object.
	 * 
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cypher object fails.
	 */
	private void initialize() throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		if (!isInitialized())
		{
			final KeySpec keySpec;
			if (this.getPrivateKey() != null)
			{
				keySpec = new PBEKeySpec(this.getPrivateKey().toCharArray());
			}
			else
			{
				keySpec = new PBEKeySpec(CryptConst.PRIVATE_KEY.toCharArray());
			}
			final SecretKeyFactory factory = SecretKeyFactory
				.getInstance(CryptConst.PBEWITH_MD5AND_DES);
			final SecretKey key = factory.generateSecret(keySpec);
			this.cipher = Cipher.getInstance(key.getAlgorithm());
			final AlgorithmParameterSpec paramSpec = new PBEParameterSpec(CryptConst.SALT,
				CryptConst.ITERATIONCOUNT);
			this.cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
			initialized = true;
		}
	}
}
