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
package io.github.astrapi69.crypto.simple;

import io.github.astrapi69.crypto.compound.CompoundAlgorithm;
import io.github.astrapi69.crypto.factories.CipherFactory;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Temporary class. Calls will be replaced with the the corresponding methods in CipherFactory
 */
public class PBECipherFactory
{

	/**
	 * Factory method for creating a new PBE {@link Cipher} from the given parameters.
	 *
	 * @param password
	 *            the password
	 * @param operationMode
	 *            the operation mode
	 * @param algorithm
	 *            the algorithm
	 *
	 * @return the cipher
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 */
	public static Cipher newPBECipher(char[] password, int operationMode, String algorithm)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidAlgorithmParameterException, InvalidKeyException
	{
		return newPBECipher(password, operationMode, algorithm, CompoundAlgorithm.SALT,
			CompoundAlgorithm.ITERATIONCOUNT);
	}

	/**
	 * Factory method for creating a new PBE {@link Cipher} from the given parameters.
	 *
	 * @param password
	 *            the password
	 * @param operationMode
	 *            the operation mode
	 * @param algorithm
	 *            the algorithm
	 * @param salt
	 *            the salt
	 * @param iterationCount
	 *            the iteration count
	 *
	 * @return the cipher
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 */
	public static Cipher newPBECipher(char[] password, int operationMode, String algorithm,
		final byte[] salt, final int iterationCount)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidAlgorithmParameterException, InvalidKeyException
	{
		final PBEKeySpec keySpec = new PBEKeySpec(password);
		final SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
		final SecretKey key = factory.generateSecret(keySpec);
		final PBEParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);
		return CipherFactory.newCipher(operationMode, key, paramSpec, key.getAlgorithm());
	}
}
