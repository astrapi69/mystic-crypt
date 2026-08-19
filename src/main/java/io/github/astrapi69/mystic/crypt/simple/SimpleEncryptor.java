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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.Cipher;

import io.github.astrapi69.crypt.api.Cryptor;
import io.github.astrapi69.crypt.api.StringEncryptor;
import io.github.astrapi69.mystic.crypt.pw.PasswordByteEncryptor;

/**
 * The class {@link SimpleEncryptor} is a simple {@link StringEncryptor} implementation.
 *
 * <p>
 * Thin composition over {@link PasswordByteEncryptor} (the same pattern
 * {@code PasswordStringEncryptor} already uses), which now supplies the actual, secure PBE cipher
 * construction.
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
	 * The delegate that does the actual encryption work.
	 */
	private final PasswordByteEncryptor encryptor;

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
		this.encryptor = new PasswordByteEncryptor(privateKey);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String encrypt(final String string) throws Exception
	{
		final byte[] utf8 = string.getBytes(StandardCharsets.UTF_8);
		final byte[] encrypt = this.encryptor.encrypt(utf8);
		return Base64.getEncoder().encodeToString(encrypt);
	}

	/**
	 * Gets private key.
	 *
	 * @return the private key
	 */
	public String getPrivateKey()
	{
		return this.privateKey;
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
