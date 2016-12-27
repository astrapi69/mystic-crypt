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

import org.apache.commons.codec.binary.Base64;

import de.alpharogroup.check.Check;
import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.interfaces.StringDecryptor;
import lombok.AccessLevel;
import lombok.Getter;

/**
 * The class {@link SimpleDecryptor} is a simple {@link StringDecryptor} implementation.
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class SimpleDecryptor implements StringDecryptor
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
	 * Instantiates a new {@link SimpleDecryptor} with the given private key.
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
	 * {@inheritDoc}
	 */
	@Override
	public String decrypt(final String encypted)
		throws IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException,
		InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException
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
				.getInstance(CryptConst.PBE_WITH_MD5_AND_DES);
			final SecretKey key = factory.generateSecret(keySpec);
			this.cipher = Cipher.getInstance(key.getAlgorithm());
			final AlgorithmParameterSpec paramSpec = new PBEParameterSpec(CryptConst.SALT,
				CryptConst.ITERATIONCOUNT);
			this.cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
			initialized = true;
		}
	}
}
