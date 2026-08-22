/*
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

import java.text.Normalizer;
import java.util.Objects;

import javax.crypto.Cipher;

import org.apache.commons.lang3.ArrayUtils;

import io.github.astrapi69.crypt.api.ByteArrayEncryptor;
import io.github.astrapi69.crypt.api.Cryptor;

/**
 * The class {@link PasswordByteEncryptor} is a simple {@link ByteArrayEncryptor} implementation.
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class PasswordByteEncryptor implements ByteArrayEncryptor, Cryptor
{

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
		this.normalizedPassword = Normalizer.normalize(password, Normalizer.Form.NFC);
	}

	/**
	 * {@inheritDoc}
	 *
	 * <p>
	 * A fresh, random salt is generated and prepended to the returned bytes on every call.
	 */
	@Override
	public byte[] encrypt(byte[] toEncrypt) throws Exception
	{
		Objects.requireNonNull(toEncrypt);
		byte[] salt = PbeCipherSupport.newSalt();
		Cipher cipher = PbeCipherSupport.newCipher(normalizedPassword, newOperationMode(), salt);
		byte[] encryptedBytes;
		synchronized (this)
		{
			encryptedBytes = cipher.doFinal(toEncrypt);
		}
		return ArrayUtils.addAll(salt, encryptedBytes);
	}

	/**
	 * Resets the password, wiping it from memory. Since the password is now needed on every
	 * {@link #encrypt(byte[])} call rather than only once at construction, calling this makes any
	 * subsequent {@code encrypt} call fail.
	 */
	public synchronized void resetPassword()
	{
		this.normalizedPassword = null;
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
