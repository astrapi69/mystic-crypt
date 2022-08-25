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
package io.github.astrapi69.mystic.crypt.pw;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.Normalizer;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import io.github.astrapi69.crypt.api.ByteArrayEncryptor;
import io.github.astrapi69.crypt.api.Cryptor;
import io.github.astrapi69.crypt.api.compound.CompoundAlgorithm;
import io.github.astrapi69.crypt.data.factory.CipherFactory;
import io.github.astrapi69.throwable.RuntimeExceptionDecorator;

/**
 * The class {@link PasswordByteEncryptor} is a simple {@link ByteArrayEncryptor} implementation.
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class PasswordByteEncryptor implements ByteArrayEncryptor, Cryptor
{

	/**
	 * The Cipher object.
	 */
	private Cipher cipher;

	/**
	 * The flag initialized that indicates if the cipher is initialized for encryption
	 *
	 * @return true, if is initialized
	 */
	private boolean initialized;

	/**
	 * The normalized password.
	 */
	private String normalizedPassword;

	/**
	 * Instantiates a new {@link PasswordByteEncryptor} with the given password
	 *
	 * @param password
	 *            The password
	 */
	public PasswordByteEncryptor(final String password)
	{
		Objects.requireNonNull(password);
		String normalizedPassword = Normalizer.normalize(password, Normalizer.Form.NFC);
		this.normalizedPassword = normalizedPassword;
		RuntimeExceptionDecorator.decorate(() -> initialize());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] encrypt(byte[] toEncrypt) throws Exception
	{
		Objects.requireNonNull(toEncrypt);
		byte[] encryptedBytes;
		synchronized (this.cipher)
		{
			encryptedBytes = this.cipher.doFinal(toEncrypt);
		}
		return encryptedBytes;
	}

	/**
	 * Resets the password
	 */
	public synchronized void resetPassword()
	{
		this.normalizedPassword = null;
	}

	/**
	 * Initializes the {@link PasswordByteEncryptor} object.
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
	private synchronized void initialize() throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		if (!isInitialized())
		{
			this.cipher = CipherFactory.newPBECipher(this.normalizedPassword.toCharArray(),
				newOperationMode(), CompoundAlgorithm.PBE_WITH_MD5_AND_DES.getAlgorithm());
			resetPassword();
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
