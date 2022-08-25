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

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * The class {@link PasswordStringDecryptor} can decrypt encrypted String objects with the given
 * password. Internally it decorates the {@link PasswordByteDecryptor}
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class PasswordStringDecryptor
{

	/**
	 * The {@link PasswordByteDecryptor} object
	 */
	private final PasswordByteDecryptor decryptor;

	/**
	 * Instantiates a new {@link PasswordStringDecryptor} with the given password
	 *
	 * @param password
	 *            The password
	 */
	public PasswordStringDecryptor(final String password)
	{
		this.decryptor = new PasswordByteDecryptor(password);
	}

	/**
	 * Decrypt the given encrypted {@link String} object
	 *
	 * @param encrypted
	 *            The {@link String} object to decrypt
	 * @return The decrypted {@link String} object
	 * @throws Exception
	 *             is thrown if decryption fails.
	 */
	public String decrypt(final String encrypted) throws Exception
	{
		final byte[] dec = Base64.getDecoder().decode(encrypted);
		final byte[] utf8 = this.decryptor.decrypt(dec);
		return new String(utf8, StandardCharsets.UTF_8.name());
	}
}
