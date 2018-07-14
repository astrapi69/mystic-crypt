/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto.algorithm;

import lombok.Getter;

/**
 * The enum {@link SunJCEAlgorithm} defines the algorithm specified by the SunJCE security provider.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public enum SunJCEAlgorithm implements Algorithm
{

	/** The DES algorithm. */
	DES("DES"),

	/** The DESede algorithm. */
	DESede("DESede"),

	/** The PBEWithMD5AndDES algorithm. */
	PBEWithMD5AndDES("PBEWithMD5AndDES"),

	/** The Blowfish algorithm. */
	Blowfish("Blowfish");

	/** The algorithm. */
	@Getter
	private final String algorithm;

	/**
	 * Instantiates a new {@link SunJCEAlgorithm} object.
	 *
	 * @param algorithm
	 *            the algorithm.
	 */
	private SunJCEAlgorithm(final String algorithm)
	{
		this.algorithm = algorithm;
	}

}
