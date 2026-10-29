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
package io.github.astrapi69.mystic.crypt.hex;

import javax.crypto.Cipher;

import io.github.astrapi69.check.Check;
import io.github.astrapi69.crypt.api.algorithm.Algorithm;
import io.github.astrapi69.crypt.data.model.CryptModel;

/**
 * Builds the model of {@link HexableEncryptor} and {@link HexableDecryptor} for a key and an
 * explicit algorithm
 */
final class HexableModels
{

	private HexableModels()
	{
	}

	/**
	 * The model for the given key and algorithm. The algorithm has to be in the model before
	 * {@code AbstractCryptor} builds the cipher: set afterwards, the cipher stayed the one built
	 * for the AES/GCM default while the model named another algorithm (#210)
	 *
	 * @param privateKey
	 *            the private key
	 * @param algorithm
	 *            the algorithm
	 * @return the model
	 */
	static CryptModel<Cipher, String, String> of(final String privateKey, final Algorithm algorithm)
	{
		Check.get().notNull(algorithm, "algorithm");
		return CryptModel.<Cipher, String, String> builder().key(privateKey).algorithm(algorithm)
			.build();
	}
}
