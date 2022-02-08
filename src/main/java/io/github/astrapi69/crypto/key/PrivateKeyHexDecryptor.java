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
package io.github.astrapi69.crypto.key;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Objects;

import io.github.astrapi69.crypto.hex.HexExtensions;
import io.github.astrapi69.throwable.RuntimeExceptionDecorator;

/**
 * The class {@link PrivateKeyHexDecryptor} decrypts encrypted characters the was encrypted with the
 * public key of the pendant private key of this class. <br>
 * <br>
 */
public final class PrivateKeyHexDecryptor
{

	/**
	 * The decorated decryptor object
	 */
	private final PrivateKeyDecryptor decryptor;

	/**
	 * Instantiates a new {@link PrivateKeyHexDecryptor} with the given {@link PrivateKey}
	 *
	 * @param privateKey
	 *            The private key
	 */
	public PrivateKeyHexDecryptor(final PrivateKey privateKey)
	{
		Objects.requireNonNull(privateKey);
		this.decryptor = RuntimeExceptionDecorator
			.decorate(() -> new PrivateKeyDecryptor(privateKey));
	}

	/**
	 * Decrypt the given encrypted {@link String}
	 *
	 * @param encypted
	 *            The encrypted {@link String} to decrypt
	 * @return The decrypted {@link String}
	 * @throws Exception
	 *             is thrown if decryption fails.
	 */
	public String decrypt(final String encypted) throws Exception
	{
		final byte[] dec = HexExtensions.decodeHex(encypted.toCharArray());
		final byte[] utf8 = this.decryptor.decrypt(dec);
		return new String(utf8, StandardCharsets.UTF_8);
	}

}
