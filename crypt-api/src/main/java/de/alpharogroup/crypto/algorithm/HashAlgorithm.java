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
package de.alpharogroup.crypto.algorithm;

import lombok.Getter;

/**
 * The enum {@link HashAlgorithm} represents the one-way conversion hash algorithms.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public enum HashAlgorithm implements Algorithm
{

	/** The enum constant for SHA-1 algorithm. */
	SHA_1("SHA-1"),

	/** The enum constant for SHA-256 algorithm. */
	SHA_256("SHA-256"),

	/** The enum constant for SHA-384 algorithm. */
	SHA_384("SHA-384"),

	/** The enum constant for SHA-512 algorithm. */
	SHA_512("SHA-512"),

	/** The enum constant for SHA1 algorithm. */
	SHA1("SHA1"),

	/** The enum constant for SHA256 algorithm. */
	SHA256("SHA256"),

	/** The enum constant for SHA384 algorithm. */
	SHA384("SHA384"),

	/** The enum constant for SHA512 algorithm. */
	SHA512("SHA512");

	/** The algorithm. */
	@Getter
	private final String algorithm;

	/**
	 * Instantiates a new {@link HashAlgorithm} object.
	 *
	 * @param algorithm
	 *            the algorithm.
	 */
	private HashAlgorithm(final String algorithm)
	{
		this.algorithm = algorithm;
	}

}