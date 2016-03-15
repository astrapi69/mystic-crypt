package de.alpharogroup.crypto.factories;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * A factory for creating Cipher objects.
 */
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
	 * @return the cipher
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
	 * @return the cipher
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
	 * @return the cipher
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

}
