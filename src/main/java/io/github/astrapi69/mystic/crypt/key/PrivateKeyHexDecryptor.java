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

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Objects;

import javax.crypto.Cipher;

import io.github.astrapi69.crypt.api.algorithm.Algorithm;
import io.github.astrapi69.crypt.data.hex.HexExtensions;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.throwable.RuntimeExceptionDecorator;

/**
 * The class {@link PrivateKeyHexDecryptor} decrypts encrypted characters the was encrypted with the
 * public key of the pendant private key of this class.
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
	 * Instantiates a new {@link PrivateKeyHexDecryptor} with the given {@link PrivateKey} and an
	 * explicit symmetric transformation. Use this to decrypt data whose symmetric leg was encrypted
	 * with an explicitly configured, non-default transformation.
	 *
	 * @param privateKey
	 *            The private key
	 * @param symmetricAlgorithm
	 *            the symmetric transformation that was used to encrypt the payload
	 */
	public PrivateKeyHexDecryptor(final PrivateKey privateKey, final Algorithm symmetricAlgorithm)
	{
		Objects.requireNonNull(privateKey);
		Objects.requireNonNull(symmetricAlgorithm);
		this.decryptor = RuntimeExceptionDecorator.decorate(() -> new PrivateKeyDecryptor(
			CryptModel.<Cipher, PrivateKey, byte[]> builder().key(privateKey).build(),
			symmetricAlgorithm));
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
