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

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import de.alpharogroup.crypto.model.CryptModel;
import lombok.experimental.UtilityClass;

/**
 * The factory class {@link CipherFactory} holds methods for creating {@link Cipher} objects.
 */
@UtilityClass
public class CipherFactory
{

	/**
	 * Factory method for creating a new {@link Cipher} from the given parameters.
	 *
	 * @param operationMode
	 *            the operation mode
	 * @param key
	 *            the key
	 * @param paramSpec
	 *            the param spec
	 * @param algorithm
	 *            the algorithm
	 * @return the new {@link Cipher}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 */
	public static Cipher newCipher(final int operationMode, final SecretKey key,
		final AlgorithmParameterSpec paramSpec, final String algorithm)
		throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
		InvalidAlgorithmParameterException
	{
		final Cipher cipher = newCipher(algorithm);
		cipher.init(operationMode, key, paramSpec);
		return cipher;
	}


	/**
	 * Factory method for creating a new {@link Cipher} from the given algorithm.
	 *
	 * @param algorithm
	 *            the alg
	 * @return the new {@link Cipher}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails.
	 */
	public static Cipher newCipher(final String algorithm)
		throws NoSuchAlgorithmException, NoSuchPaddingException
	{
		final Cipher cipher = Cipher.getInstance(algorithm);
		return cipher;
	}


	/**
	 * Factory method for creating a new {@link Cipher} from the given algorithm and provider.
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param provider
	 *            the provider
	 * @return the new {@link Cipher}
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 * @throws NoSuchPaddingException
	 *             is thrown if algorithm contains a padding scheme that is not available.
	 */
	public static Cipher newCipher(final String algorithm, final String provider)
		throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException
	{
		final Cipher cipher = Cipher.getInstance(algorithm, provider);
		return cipher;
	}


	/**
	 * Factory method for creating a new {@link Cipher} from the given parameters. This method is
	 * invoked in the constructor from the derived classes and can be overridden so users can
	 * provide their own version of a new {@link Cipher} from the given parameters.
	 *
	 * @param privateKey
	 *            the private key
	 * @param algorithm
	 *            the algorithm
	 * @param salt
	 *            the salt.
	 * @param iterationCount
	 *            the iteration count
	 * @param operationMode
	 *            the operation mode for the new cipher object
	 * @return the cipher
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public static Cipher newCipher(final String privateKey, final String algorithm,
		final byte[] salt, final int iterationCount, final int operationMode)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		final KeySpec keySpec = KeySpecFactory.newPBEKeySpec(privateKey, salt, iterationCount);
		final SecretKeyFactory factory = SecretKeyFactoryExtensions.newSecretKeyFactory(algorithm);
		final SecretKey key = factory.generateSecret(keySpec);
		final AlgorithmParameterSpec paramSpec = AlgorithmParameterSpecFactory
			.newPBEParameterSpec(salt, iterationCount);
		return newCipher(operationMode, key, paramSpec, key.getAlgorithm());
	}

	/**
	 * Factory method for creating a new {@link Cipher} from the given parameters. This method is
	 * invoked in the constructor from the derived classes and can be overridden so users can
	 * provide their own version of a new {@link Cipher} from the given parameters.
	 *
	 * @param model
	 *            the model bean for create the cipher
	 * @return the cipher
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cypher object fails
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported
	 */
	public static Cipher newCipher(final CryptModel<Cipher, String> model)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		final KeySpec keySpec = KeySpecFactory.newPBEKeySpec(model.getKey(), model.getSalt(), model.getIterationCount());
		final SecretKeyFactory factory = SecretKeyFactoryExtensions.newSecretKeyFactory(model.getAlgorithm().getAlgorithm());
		final SecretKey key = factory.generateSecret(keySpec);
		final AlgorithmParameterSpec paramSpec = AlgorithmParameterSpecFactory
			.newPBEParameterSpec(model.getSalt(), model.getIterationCount());
		return newCipher(model.getOperationMode(), key, paramSpec, key.getAlgorithm());
	}

}
