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
package io.github.astrapi69.mystic.crypt.key;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

import org.apache.commons.codec.binary.Hex;

/**
 * Encrypts a {@link String} with an ec public key and renders the result as hex.
 * <p>
 * The ec counterpart of {@link PublicKeyHexEncryptor}, in the same shape, so a caller that offers
 * both wires them alike. What this produces is opened by {@link EcPrivateKeyHexDecryptor}.
 */
public final class EcPublicKeyHexEncryptor
{

	/** The decorated encryptor object */
	private final EcPublicKeyEncryptor encryptor;

	/**
	 * Instantiates a new {@link EcPublicKeyHexEncryptor} object with the given ec {@link PublicKey}
	 *
	 * @param publicKey
	 *            the ec public key
	 * @throws IllegalArgumentException
	 *             if the given key is not an ec key
	 */
	public EcPublicKeyHexEncryptor(final PublicKey publicKey)
	{
		this.encryptor = new EcPublicKeyEncryptor(publicKey);
	}

	/**
	 * Encrypt the given {@link String} object
	 *
	 * @param string
	 *            The {@link String} to encrypt
	 * @return The encrypted {@link String} as hex
	 * @throws Exception
	 *             is thrown if encryption fails
	 */
	public String encrypt(final String string) throws Exception
	{
		final byte[] utf8 = string.getBytes(StandardCharsets.UTF_8);
		final byte[] encrypted = this.encryptor.encrypt(utf8);
		return new String(Hex.encodeHex(encrypted, true));
	}
}
