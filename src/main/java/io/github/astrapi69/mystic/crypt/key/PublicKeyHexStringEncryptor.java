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
package io.github.astrapi69.mystic.crypt.key;

import java.security.PublicKey;
import java.util.Objects;

import org.apache.commons.codec.binary.Hex;

import io.github.astrapi69.throwable.RuntimeExceptionDecorator;

/**
 * The class {@link PublicKeyHexStringEncryptor} can encrypt and hex characters with the given
 * public key <br>
 * <br>
 */
public final class PublicKeyHexStringEncryptor
{

	/**
	 * The decorated encryptor object
	 */
	private final PublicKeyStringEncryptor encryptor;

	/**
	 * Instantiates a new {@link PublicKeyHexStringEncryptor} object with the given
	 * {@link PublicKey}
	 *
	 * @param publicKey
	 *            the public key
	 */
	public PublicKeyHexStringEncryptor(final PublicKey publicKey)
	{
		Objects.requireNonNull(publicKey);
		this.encryptor = RuntimeExceptionDecorator
			.decorate(() -> new PublicKeyStringEncryptor(publicKey));
	}

	/**
	 * Encrypt the given {@link String} object
	 *
	 * @param string
	 *            The {@link String} to encrypt
	 * @return The encrypted {@link String}
	 *
	 * @throws Exception
	 *             is thrown if encryption fails
	 */
	public String encrypt(final String string) throws Exception
	{
		final byte[] encrypt = this.encryptor.encrypt(string);
		final char[] original = Hex.encodeHex(encrypt, false);
		return new String(original);
	}
}
