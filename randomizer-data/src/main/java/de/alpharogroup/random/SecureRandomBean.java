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
package de.alpharogroup.random;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import org.apache.log4j.Logger;

import lombok.NonNull;

/**
 * The class {@link SecureRandomBean} builds a {@link SecureRandom} from the given algorithm and
 * provider. If nothing is set the default {@link SecureRandom} object with the default algorithm
 * will be build.
 */
public class SecureRandomBean
{

	/** The Constant DEFAULT_ALGORITHM. */
	public static final String DEFAULT_ALGORITHM = "SHA1PRNG";
	/** The Constant DEFAULT_ALGORITHM. */
	public static final String DEFAULT_PROVIDER = "SUN";
	/** The Constant logger. */
	private static final Logger logger = Logger.getLogger(SecureRandomBean.class.getName());

	/**
	 * Gets an instance of {@link SecureRandomBean} for build a {@link SecureRandom} object.
	 *
	 * @return the {@link SecureRandomBean}
	 */
	public static SecureRandomBean builder()
	{
		return new SecureRandomBean();
	}

	/** The algorithm. */
	private String algorithm;

	/** The provider. */
	private String provider;

	/**
	 * Instantiates a new {@link SecureRandomBean}.
	 */
	private SecureRandomBean()
	{
	}

	/**
	 * Sets the algorithm.
	 *
	 * @param algorithm
	 *            the algorithm
	 * @return this {@link SecureRandomBean} object. For chaining.
	 */
	public SecureRandomBean algorithm(@NonNull final String algorithm)
	{
		this.algorithm = algorithm;
		return this;
	}

	/**
	 * Builds a {@link SecureRandom} from the given algorithm and provider. If nothing is set the
	 * default {@link SecureRandom} object with the default algorithm will be build.
	 *
	 * @return the new {@link SecureRandom} object
	 * @throws NoSuchAlgorithmException
	 *             is thrown if a SecureRandomSpi implementation for the specified algorithm is not
	 *             available from the specified provider.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	public SecureRandom build() throws NoSuchAlgorithmException, NoSuchProviderException
	{
		if (algorithm != null && provider != null)
		{
			return SecureRandom.getInstance(algorithm, provider);
		}
		if (algorithm != null)
		{
			return SecureRandom.getInstance(algorithm);
		}
		return SecureRandom.getInstance(DEFAULT_ALGORITHM);
	}

	/**
	 * Builds a {@link SecureRandom} from the given algorithm and provider. If nothing is set the
	 * default {@link SecureRandom} object with the default algorithm will be build.
	 *
	 * @return the new {@link SecureRandom} object
	 */
	public SecureRandom buildQuietly()
	{
		SecureRandom secureRandom = null;
		try
		{
			secureRandom = build();
		}
		catch (final NoSuchAlgorithmException e)
		{
			logger.error("The specified algorithm is not available from the specified provider.",
				e);
		}
		catch (final NoSuchProviderException e)
		{
			logger.error("The specified provider is not registered in the security provider list.",
				e);
		}
		return secureRandom;
	}

	/**
	 * Sets the provider.
	 *
	 * @param provider
	 *            the provider
	 * @return this {@link SecureRandomBean} object. For chaining.
	 */
	public SecureRandomBean provider(@NonNull final String provider)
	{
		this.provider = provider;
		return this;
	}
}
