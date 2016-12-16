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

/**
 * The enum {@link Algorithm} defines the MessageDigest Algorithm plus the KeyGenerator Algorithm AES.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public enum Algorithm
{

	/** The enum constant for MD2 algorithm. */
	MD2("MD2"),

	/** The enum constant for MD4 algorithm. */
	MD4("MD4"),

	/** The enum constant for MD5 algorithm. */
	MD5("MD5"),

	/** The enum constant for SHA-1 algorithm. */
	SHA_1("SHA-1"),

	/** The enum constant for SHA-256 algorithm. */
	SHA_256("SHA-256"),

	/** The enum constant for SHA-384 algorithm. */
	SHA_384("SHA-384"),

	/** The enum constant for SHA-512 algorithm. */
	SHA_512("SHA-512"),

	/** The enum constant for AES algorithm. */
	AES("AES"),

	/** The enum constant for RSA algorithm. */
	RSA("RSA");

	/** The algorithm. */
	private final String algorithm;

	/**
	 * Instantiates a new Algorithm object.
	 *
	 * @param algorithm
	 *            the algorithm.
	 */
	Algorithm(final String algorithm)
	{
		this.algorithm = algorithm;
	}

	/**
	 * Gets the algorithm.
	 *
	 * @return the algorithm
	 */
	public String getAlgorithm()
	{
		return algorithm;
	}
}
