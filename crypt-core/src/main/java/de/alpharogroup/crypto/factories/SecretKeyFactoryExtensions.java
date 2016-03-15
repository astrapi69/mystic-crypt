package de.alpharogroup.crypto.factories;

import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKeyFactory;


/**
 * A factory for creating SecretKeyFactory objects.
 */
public class SecretKeyFactoryExtensions
{


	/**
	 * Factory method for creating a new {@link SecretKeyFactory} from the given algorithm.
	 *
	 * @param algorithm
	 *            the algorithm
	 * @return the new {@link SecretKeyFactory} from the given algorithm.
	 */
	public static SecretKeyFactory newSecretKeyFactory(final String algorithm) throws NoSuchAlgorithmException {
		final SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
		return factory;
	}
}
