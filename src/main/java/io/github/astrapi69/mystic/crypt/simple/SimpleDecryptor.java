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
import io.github.astrapi69.crypt.api.StringDecryptor;
import io.github.astrapi69.mystic.crypt.pw.PasswordByteDecryptor;

/**
 * The class {@link SimpleDecryptor} is a simple {@link StringDecryptor} implementation.
 *
 * <p>
 * Thin composition over {@link PasswordByteDecryptor} (the same pattern
 * {@code PasswordStringDecryptor} already uses), which now supplies the actual, secure PBE cipher
 * construction.
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class SimpleDecryptor implements StringDecryptor, Cryptor
{

	/**
	 * The private key.
	 */
	private final String privateKey;

	/**
	 * The delegate that does the actual decryption work.
	 */
	private final PasswordByteDecryptor decryptor;

	/**
	 * Instantiates a new {@link SimpleDecryptor} with the given private key.
	 *
	 * @param privateKey
	 *            The private key.
	 */
	public SimpleDecryptor(final String privateKey)
	{
		Objects.requireNonNull(privateKey);
		this.privateKey = privateKey;
		this.decryptor = new PasswordByteDecryptor(privateKey);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String decrypt(final String encypted) throws Exception
	{
		final byte[] dec = Base64.getDecoder().decode(encypted);
		final byte[] utf8 = this.decryptor.decrypt(dec);
		return new String(utf8, StandardCharsets.UTF_8);
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
		return Cipher.DECRYPT_MODE;
	}
}
