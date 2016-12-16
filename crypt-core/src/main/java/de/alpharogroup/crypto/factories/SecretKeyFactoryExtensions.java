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

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;


/**
 * A factory for creating SecretKeyFactory objects.
 */
public class SecretKeyFactoryExtensions
{


	/**
	 * Factory method for creating a new {@link SecretKeyFactory} from the given algorithm.
	 *
	 * @param algorithm            the algorithm
	 * @return the new {@link SecretKeyFactory} from the given algorithm.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 */
	public static SecretKeyFactory newSecretKeyFactory(final String algorithm) throws NoSuchAlgorithmException {
		final SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
		return factory;
	}


	/**
	 * New secret key spec.
	 *
	 * @param algorithm the algorithm
	 * @param keyLength the key length
	 * @return the secret key spec
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 */
	public static SecretKeySpec newSecretKeySpec(final String algorithm, final int keyLength) throws NoSuchAlgorithmException {
		final KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
		keyGenerator.init(keyLength);
	    final SecretKey secretKey = keyGenerator.generateKey();
	    final byte[] secretKeyEncoded = secretKey.getEncoded();
	    final SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyEncoded, algorithm);
		return secretKeySpec;
	}
}
