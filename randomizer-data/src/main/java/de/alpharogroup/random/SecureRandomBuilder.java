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

import javax.annotation.Nonnull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The class {@link SecureRandomBuilder} builds a {@link SecureRandom} from the given algorithm and
 * provider. If nothing is set the default {@link SecureRandom} object with the default algorithm
 * will be build.
 */
public class SecureRandomBuilder
{

	/** The Constant DEFAULT_ALGORITHM. */
	public static final String DEFAULT_ALGORITHM = "SHA1PRNG";

	/** The Constant logger. */
	private static final Logger logger = LoggerFactory
		.getLogger(SecureRandomBuilder.class.getName());

	/**
	 * Gets an instance of {@link SecureRandomBuilder} for build a {@link SecureRandom} object.
	 *
	 * @return the {@link SecureRandomBuilder}
	 */
	private static SecureRandomBuilder builder()
	{
		return new SecureRandomBuilder();
	}

	/**
	 * Gets an instance of {@link SecureRandomBuilder} with the default algorithm and provider.
	 *
	 * @return the new {@link SecureRandomBuilder} object
	 */
	public static SecureRandomBuilder getInstance()
	{
		return SecureRandomBuilder.builder();
	}

	/**
	 * Gets an instance of {@link SecureRandomBuilder} from the given algorithm and provider.
	 *
	 * @param algorithm
	 *            the algorithm
	 * @return the new {@link SecureRandomBuilder} object
	 */
	public static SecureRandomBuilder getInstance(final String algorithm)
	{
		return SecureRandomBuilder.builder().algorithm(algorithm);
	}

	/**
	 * Gets an instance of {@link SecureRandomBuilder} from the given algorithm and provider.
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param provider
	 *            the provider
	 * @return the new {@link SecureRandomBuilder} object
	 */
	public static SecureRandomBuilder getInstance(final String algorithm, final String provider)
	{
		return SecureRandomBuilder.builder().algorithm(algorithm).provider(provider);
	}

	/** The algorithm. */
	private String algorithm;

	/** The provider. */
	private String provider;

	/**
	 * Instantiates a new {@link SecureRandomBuilder}.
	 */
	private SecureRandomBuilder()
	{
	}

	/**
	 * Sets the algorithm.
	 *
	 * @param algorithm
	 *            the algorithm
	 * @return this {@link SecureRandomBuilder} object. For chaining.
	 */
	public SecureRandomBuilder algorithm(@Nonnull final String algorithm)
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
	public SecureRandom buildQueitly()
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
	 * @return this {@link SecureRandomBuilder} object. For chaining.
	 */
	public SecureRandomBuilder provider(@Nonnull final String provider)
	{
		this.provider = provider;
		return this;
	}
}
