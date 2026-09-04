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
import java.security.PrivateKey;

import org.apache.commons.codec.binary.Hex;

/**
 * Decrypts a hex {@link String} that {@link EcPublicKeyHexEncryptor} produced with the matching ec
 * public key.
 * <p>
 * The ec counterpart of {@link PrivateKeyHexDecryptor}, in the same shape.
 */
public final class EcPrivateKeyHexDecryptor
{

	/** The decorated decryptor object */
	private final EcPrivateKeyDecryptor decryptor;

	/**
	 * Instantiates a new {@link EcPrivateKeyHexDecryptor} object with the given ec
	 * {@link PrivateKey}
	 *
	 * @param privateKey
	 *            the ec private key
	 * @throws IllegalArgumentException
	 *             if the given key is not an ec key
	 */
	public EcPrivateKeyHexDecryptor(final PrivateKey privateKey)
	{
		this.decryptor = new EcPrivateKeyDecryptor(privateKey);
	}

	/**
	 * Decrypt the given hex {@link String} object
	 *
	 * @param encrypted
	 *            The hex {@link String} to decrypt
	 * @return The decrypted {@link String}
	 * @throws Exception
	 *             is thrown if the input is no hex, was not encrypted for this key, or was changed
	 *             after encryption
	 */
	public String decrypt(final String encrypted) throws Exception
	{
		final byte[] bytes = Hex.decodeHex(encrypted.toCharArray());
		return new String(this.decryptor.decrypt(bytes), StandardCharsets.UTF_8);
	}
}
