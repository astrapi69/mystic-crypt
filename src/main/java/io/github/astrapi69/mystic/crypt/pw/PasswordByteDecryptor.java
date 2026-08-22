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

import io.github.astrapi69.crypt.api.ByteArrayDecryptor;
import io.github.astrapi69.crypt.api.Cryptor;

/**
 * The class {@link PasswordByteDecryptor} is a simple {@link ByteArrayDecryptor} implementation
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class PasswordByteDecryptor implements ByteArrayDecryptor, Cryptor
{

	/**
	 * The normalized password.
	 */
	private String normalizedPassword;

	/**
	 * Instantiates a new {@link PasswordByteDecryptor} with the given password
	 *
	 * @param password
	 *            The password
	 */
	public PasswordByteDecryptor(final String password)
	{
		Objects.requireNonNull(password);
		this.normalizedPassword = Normalizer.normalize(password, Normalizer.Form.NFC);
	}

	/**
	 * {@inheritDoc}
	 *
	 * <p>
	 * The salt is read from the first bytes of {@code encryptedBytes}, matching what
	 * {@link PasswordByteEncryptor#encrypt(byte[])} prepends.
	 */
	@Override
	public byte[] decrypt(byte[] encryptedBytes) throws Exception
	{
		Objects.requireNonNull(encryptedBytes);
		if (encryptedBytes.length < PbeCipherSupport.SALT_LENGTH)
		{
			throw new IllegalArgumentException("encrypted data too short to contain a salt prefix");
		}
		byte[] salt = ArrayUtils.subarray(encryptedBytes, 0, PbeCipherSupport.SALT_LENGTH);
		byte[] cipherBytes = ArrayUtils.subarray(encryptedBytes, PbeCipherSupport.SALT_LENGTH,
			encryptedBytes.length);
		Cipher cipher = PbeCipherSupport.newCipher(normalizedPassword, newOperationMode(), salt);
		final byte[] decryptedBytes;
		synchronized (this)
		{
			decryptedBytes = cipher.doFinal(cipherBytes);
		}
		return decryptedBytes;
	}

	/**
	 * Resets the password, wiping it from memory. Since the password is now needed on every
	 * {@link #decrypt(byte[])} call rather than only once at construction, calling this makes any
	 * subsequent {@code decrypt} call fail.
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
		return Cipher.DECRYPT_MODE;
	}

}
