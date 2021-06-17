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
package io.github.astrapi69.crypto.pw;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * The class {@link PasswordStringEncryptor} can encrypt String objects with the given password.
 * Internally it decorates the {@link PasswordByteEncryptor}
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class PasswordStringEncryptor
{
	/**
	 * The {@link PasswordByteEncryptor} object
	 */
	private final PasswordByteEncryptor encryptor;

	/**
	 * Instantiates a new {@link PasswordStringEncryptor} with the given password
	 *
	 * @param password
	 *            The password
	 */
	public PasswordStringEncryptor(final String password)
	{
		this.encryptor = new PasswordByteEncryptor(password);
	}

	/**
	 * Encrypt the given {@link String} object
	 *
	 * @param toEncrypt
	 *            The {@link String} object to encrypt
	 * @return The encrypted {@link String} object
	 * @throws Exception
	 *             is thrown if encryption fails.
	 */
	public String encrypt(String toEncrypt) throws Exception
	{
		final byte[] utf8 = toEncrypt.getBytes(StandardCharsets.UTF_8.name());
		byte[] encrypt = this.encryptor.encrypt(utf8);
		final String encrypted = Base64.getEncoder().encodeToString(encrypt);
		return encrypted;
	}
}
