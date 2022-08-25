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
package io.github.astrapi69.mystic.crypt.simple;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import io.github.astrapi69.crypt.api.Cryptor;
import io.github.astrapi69.crypt.api.StringEncryptor;
import io.github.astrapi69.crypt.api.compound.CompoundAlgorithm;

/**
 * The class {@link SimpleEncryptor} is a simple {@link StringEncryptor} implementation.
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class SimpleEncryptor implements StringEncryptor, Cryptor
{

	/**
	 * The private key.
	 */
	private final String privateKey;
	/**
	 * The Cipher object.
	 */
	private Cipher cipher;
	/**
	 * The flag initialized that indicates if the cipher is initialized for decryption.
	 *
	 * @return true, if is initialized
	 */
	private boolean initialized;

	/**
	 * Instantiates a new {@link SimpleEncryptor} with the given private key.
	 *
	 * @param privateKey
	 *            The private key.
	 */
	public SimpleEncryptor(final String privateKey)
	{
		Objects.requireNonNull(privateKey);
		this.privateKey = privateKey;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String encrypt(final String string)
		throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException,
		InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException
	{
		initialize();
		final byte[] utf8 = string.getBytes(StandardCharsets.UTF_8.name());
		final byte[] encrypt = this.cipher.doFinal(utf8);
		final String encrypted = Base64.getEncoder().encodeToString(encrypt);
		return encrypted;
	}

	public String getPrivateKey()
	{
		return this.privateKey;
	}

	/**
	 * Initializes the {@link SimpleEncryptor} object.
	 *
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 */
	private void initialize() throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		if (!isInitialized())
		{
			final KeySpec keySpec = new PBEKeySpec(this.getPrivateKey().toCharArray());

			final SecretKeyFactory factory = SecretKeyFactory
				.getInstance(CompoundAlgorithm.PBE_WITH_MD5_AND_DES.getAlgorithm());
			final SecretKey key = factory.generateSecret(keySpec);
			this.cipher = Cipher.getInstance(key.getAlgorithm());
			final AlgorithmParameterSpec paramSpec = new PBEParameterSpec(CompoundAlgorithm.SALT,
				CompoundAlgorithm.ITERATIONCOUNT);
			this.cipher.init(newOperationMode(), key, paramSpec);
			initialized = true;
		}
	}

	private boolean isInitialized()
	{
		return this.initialized;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int newOperationMode()
	{
		return Cipher.ENCRYPT_MODE;
	}
}
