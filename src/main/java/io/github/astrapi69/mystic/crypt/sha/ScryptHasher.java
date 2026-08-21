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
package io.github.astrapi69.mystic.crypt.sha;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The class {@link ScryptHasher} provides scrypt hashing functionality using Bouncy Castle.
 * Scrypt is a password-based key derivation function designed to be computationally expensive
 * and memory-hard, making it resistant to hardware brute-force attacks. It requires significant
 * amounts of memory to compute, which makes large-scale custom hardware attacks economically
 * infeasible.
 * 
 * <p>
 * Scrypt parameters:
 * <ul>
 * <li>N: CPU/memory cost parameter (must be a power of 2)</li>
 * <li>r: block size parameter</li>
 * <li>p: parallelization parameter</li>
 * </ul>
 * </p>
 * 
 * @author Asterios Raptis
 */
public final class ScryptHasher
{

	static
	{
		// Register Bouncy Castle provider if not already registered
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	/** Default N parameter (CPU/memory cost): 2^14 = 16384 */
	public static final int DEFAULT_N = 16384;

	/** Default r parameter (block size): 8 */
	public static final int DEFAULT_R = 8;

	/** Default p parameter (parallelization): 1 */
	public static final int DEFAULT_P = 1;

	/** Salt length in bytes */
	public static final int SALT_LENGTH = 16;

	/** Output hash length in bytes */
	public static final int HASH_LENGTH = 32;

	/** Minimum N value (must be at least 2) */
	public static final int MIN_N = 2;

	/** Minimum r value */
	public static final int MIN_R = 1;

	/** Minimum p value */
	public static final int MIN_P = 1;

	private ScryptHasher()
	{
	}

	/**
	 * Hashes the given password with scrypt using default parameters.
	 *
	 * @param password
	 *            the password to hash
	 * @return the hash as a byte array
	 * @throws IllegalArgumentException
	 *             if password is null
	 */
	public static byte[] hash(final char[] password)
	{
		return hash(password, DEFAULT_N, DEFAULT_R, DEFAULT_P);
	}

	/**
	 * Hashes the given password with scrypt using specified parameters.
	 *
	 * @param password
	 *            the password to hash
	 * @param n
	 *            CPU/memory cost parameter (must be a power of 2, minimum 2)
	 * @param r
	 *            block size parameter (minimum 1)
	 * @param p
	 *            parallelization parameter (minimum 1)
	 * @return the hash as a byte array
	 * @throws IllegalArgumentException
	 *             if password is null or parameters are invalid
	 */
	public static byte[] hash(final char[] password, final int n, final int r, final int p)
	{
		if (password == null)
		{
			throw new IllegalArgumentException("Password cannot be null");
		}
		validateParameters(n, r, p);

		try
		{
			final byte[] passwordBytes = toBytes(password);
			final byte[] salt = generateSalt();
			return SCrypt.generate(passwordBytes, salt, n, r, p, HASH_LENGTH);
		}
		finally
		{
			Arrays.fill(password, '\0');
		}
	}

	/**
	 * Hashes the given password with scrypt using specified parameters and salt.
	 *
	 * @param password
	 *            the password to hash
	 * @param salt
	 *            the salt to use (recommended at least 16 bytes)
	 * @param n
	 *            CPU/memory cost parameter (must be a power of 2, minimum 2)
	 * @param r
	 *            block size parameter (minimum 1)
	 * @param p
	 *            parallelization parameter (minimum 1)
	 * @param outputLength
	 *            the desired output length in bytes
	 * @return the hash as a byte array
	 * @throws IllegalArgumentException
	 *             if password or salt is null, or parameters are invalid
	 */
	public static byte[] hashWithSalt(final char[] password, final byte[] salt, final int n,
		final int r, final int p, final int outputLength)
	{
		if (password == null)
		{
			throw new IllegalArgumentException("Password cannot be null");
		}
		if (salt == null)
		{
			throw new IllegalArgumentException("Salt cannot be null");
		}
		validateParameters(n, r, p);

		try
		{
			final byte[] passwordBytes = toBytes(password);
			return SCrypt.generate(passwordBytes, salt, n, r, p, outputLength);
		}
		finally
		{
			Arrays.fill(password, '\0');
		}
	}

	/**
	 * Verifies that the given password matches the expected hash.
	 *
	 * @param password
	 *            the password to verify
	 * @param salt
	 *            the salt used for hashing
	 * @param expectedHash
	 *            the expected hash to compare against
	 * @param n
	 *            CPU/memory cost parameter
	 * @param r
	 *            block size parameter
	 * @param p
	 *            parallelization parameter
	 * @return true if the password matches, false otherwise
	 * @throws IllegalArgumentException
	 *             if any parameter is null
	 */
	public static boolean verify(final char[] password, final byte[] salt, final byte[] expectedHash,
		final int n, final int r, final int p)
	{
		if (password == null)
		{
			throw new IllegalArgumentException("Password cannot be null");
		}
		if (salt == null)
		{
			throw new IllegalArgumentException("Salt cannot be null");
		}
		if (expectedHash == null)
		{
			throw new IllegalArgumentException("Expected hash cannot be null");
		}
		validateParameters(n, r, p);

		try
		{
			final byte[] passwordBytes = toBytes(password);
			final byte[] actualHash = SCrypt.generate(passwordBytes, salt, n, r, p,
				expectedHash.length);
			return Arrays.equals(expectedHash, actualHash);
		}
		finally
		{
			Arrays.fill(password, '\0');
		}
	}

	/**
	 * Validates scrypt parameters.
	 *
	 * @param n
	 *            CPU/memory cost parameter
	 * @param r
	 *            block size parameter
	 * @param p
	 *            parallelization parameter
	 * @throws IllegalArgumentException
	 *             if parameters are invalid
	 */
	private static void validateParameters(final int n, final int r, final int p)
	{
		if (n < MIN_N || !isPowerOfTwo(n))
		{
			throw new IllegalArgumentException(
				"N must be a power of 2 and at least " + MIN_N);
		}
		if (r < MIN_R)
		{
			throw new IllegalArgumentException("R must be at least " + MIN_R);
		}
		if (p < MIN_P)
		{
			throw new IllegalArgumentException("P must be at least " + MIN_P);
		}
	}

	/**
	 * Checks if a number is a power of two.
	 *
	 * @param n
	 *            the number to check
	 * @return true if n is a power of two, false otherwise
	 */
	private static boolean isPowerOfTwo(final int n)
	{
		return n > 0 && (n & (n - 1)) == 0;
	}

	/**
	 * Generates a random salt.
	 *
	 * @return the salt as a byte array
	 */
	private static byte[] generateSalt()
	{
		final byte[] salt = new byte[SALT_LENGTH];
		final java.security.SecureRandom random = new java.security.SecureRandom();
		random.nextBytes(salt);
		return salt;
	}

	/**
	 * Converts a char array to UTF-8 byte array.
	 *
	 * @param chars
	 *            the char array
	 * @return the byte array
	 */
	private static byte[] toBytes(final char[] chars)
	{
		return new String(chars).getBytes(StandardCharsets.UTF_8);
	}

}
