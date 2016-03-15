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
import de.alpharogroup.crypto.interfaces.Decryptor;

/**
 * A simple Decryptor implementation.
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class SimpleDecryptor implements Decryptor
{

	/**
	 * The Cipher object.
	 */
	private Cipher cipher;

	/**
	 * The private key.
	 */
	@Getter
	private final String privateKey;

	/**
	 * The flag initialized that indicates if the cypher is initialized for decryption.
	 *
	 * @return true, if is initialized
	 */
	@Getter(value = AccessLevel.PRIVATE)
	private boolean initialized;

	/**
	 * Constructor with a private key.
	 *
	 * @param privateKey
	 *            The private key.
	 */
	public SimpleDecryptor(final String privateKey)
	{
		Check.get().notEmpty(privateKey, "privateKey");
		this.privateKey = privateKey;
	}

	/**
	 * Decrpyt the given encrypted String.
	 * 
	 * @param encypted
	 *            The String to decrypt.
	 * @throws BadPaddingException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws IllegalBlockSizeException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if creation of String object fails.
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
	 * @see de.alpharogroup.crypto.interfaces.Decryptor#decrypt(java.lang.String)
	 */
	@Override
	public String decrypt(final String encypted) throws IllegalBlockSizeException,
		BadPaddingException, UnsupportedEncodingException, InvalidKeyException,
		NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidAlgorithmParameterException
	{
		initialize();
		final byte[] dec = Base64.decodeBase64(encypted);
		final byte[] utf8 = this.cipher.doFinal(dec);
		return new String(utf8, CryptConst.ENCODING);
	}

	/**
	 * Initializes the {@link SimpleDecryptor} object.
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
			KeySpec keySpec = null;
			if (this.getPrivateKey() != null)
			{
				keySpec = new PBEKeySpec(this.getPrivateKey().toCharArray());
			}
			if (this.getPrivateKey() == null)
			{
				keySpec = new PBEKeySpec(CryptConst.PRIVATE_KEY.toCharArray());
			}
			final SecretKeyFactory factory = SecretKeyFactory
				.getInstance(CryptConst.PBEWITH_MD5AND_DES);
			final SecretKey key = factory.generateSecret(keySpec);
			this.cipher = Cipher.getInstance(key.getAlgorithm());
			final AlgorithmParameterSpec paramSpec = new PBEParameterSpec(CryptConst.SALT,
				CryptConst.ITERATIONCOUNT);
			this.cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
			initialized = true;
		}
	}
}
