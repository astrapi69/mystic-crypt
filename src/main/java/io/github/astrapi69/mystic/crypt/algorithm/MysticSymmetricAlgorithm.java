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
package io.github.astrapi69.mystic.crypt.algorithm;

import io.github.astrapi69.crypt.api.algorithm.Algorithm;

/**
 * The enum {@link MysticSymmetricAlgorithm} provides symmetric cipher transformations not (yet)
 * available as named constants in crypt-api's {@code AesAlgorithm} enum.
 */
public enum MysticSymmetricAlgorithm implements Algorithm
{

	/** The enum constant for the 'AES/GCM/NoPadding' transformation */
	AES_GCM_NO_PADDING("AES/GCM/NoPadding"),

	/**
	 * The enum constant for the 'ChaCha20-Poly1305' transformation, natively supported by the JDK
	 * (SunJCE). An authenticated cipher like AES/GCM/NoPadding, typically faster in software on
	 * platforms without AES hardware acceleration (e.g. older ARM chips).
	 */
	CHACHA20_POLY1305("ChaCha20-Poly1305");

	/** The algorithm. */
	private final String algorithm;

	MysticSymmetricAlgorithm(final String algorithm)
	{
		this.algorithm = algorithm;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getAlgorithm()
	{
		return this.algorithm;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString()
	{
		return getAlgorithm();
	}
}
