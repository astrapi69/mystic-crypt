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
package de.alpharogroup.crypto.factories;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import de.alpharogroup.crypto.algorithm.Algorithm;
import lombok.experimental.UtilityClass;

/**
 * A factory for create {@link KeyPair} objects.
 */
@UtilityClass
public class KeyPairFactory
{

	/**
	 * Factory method for creating a new {@link KeyPair} from the given algorithm and key size.
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param keySize
	 *            the key size
	 * @return the new {@link KeyPair} from the given salt and iteration count.
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 */
	public static KeyPair newKeyPair(final Algorithm algorithm, final int keySize)
		throws NoSuchAlgorithmException
	{
		return newKeyPair(algorithm.getAlgorithm(), keySize);
	}

	/**
	 * Factory method for creating a new {@link KeyPair} from the given parameters.
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param keySize
	 *            the key size
	 * @return the new {@link KeyPair} from the given parameters.
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 */
	public static KeyPair newKeyPair(final String algorithm, final int keySize)
		throws NoSuchAlgorithmException
	{
		final KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
		generator.initialize(keySize);
		return generator.generateKeyPair();
	}

}
