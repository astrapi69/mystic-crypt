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

import java.security.SecureRandom;

import lombok.Getter;

/**
 * The enum {@link RngAlgorithm} provides algorithms for generation of random number generator (RNG)
 * that are used with the {@link SecureRandom} object. <br>
 * <br>
 * Note: See what algorithm can be used with your operating system. <br>
 * For more info see: <a href=
 * "https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#SecureRandomImp">https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#SecureRandomImp</a>
 *
 */
public enum RngAlgorithm implements Algorithm
{

	/** The Native PRNG. */
	NativePRNG("NativePRNG"),
	/** The Native PRNG blocking. */
	NativePRNGBlocking("NativePRNGBlocking"),
	/** The Native PRNG non blocking. */
	NativePRNGNonBlocking("NativePRNGNonBlocking"),
	/** The pkcs11. */
	PKCS11("PKCS11"),
	/** The sha1prng. */
	SHA1PRNG("SHA1PRNG"),
	/** The Windows PRNG. */
	Windows_PRNG("Windows-PRNG");
	/** The algorithm. */

	/**
	 * {@inheritDoc}
	 */
	@Getter
	private final String algorithm;

	/**
	 * Instantiates a new rng algorithm.
	 *
	 * @param algorithm
	 *            the algorithm
	 */
	RngAlgorithm(final String algorithm)
	{
		this.algorithm = algorithm;
	}
}
