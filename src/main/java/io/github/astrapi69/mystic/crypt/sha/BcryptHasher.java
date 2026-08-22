/*
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

import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The class {@link BcryptHasher} provides BCrypt hashing functionality using Bouncy Castle. BCrypt
 * is an adaptive cryptographic hash function designed for password hashing. It incorporates a salt
 * to protect against rainbow table attacks and is computationally expensive to resist brute-force
 * attacks. The cost factor can be adjusted to increase computational requirements over time as
 * hardware becomes faster.
 * 
 * <p>
 * BCrypt produces hashes in the standard format: {@code $2a$<cost>$<salt><hash>} or
 * {@code $2b$<cost>$<salt><hash>} for version 2b.
 * </p>
 * 
 * @author Asterios Raptis
 */
public final class BcryptHasher
{

	static
	{
		// Register Bouncy Castle provider if not already registered
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	/** Default log rounds (cost factor): 2^10 = 1024 iterations */
	public static final int DEFAULT_LOG_ROUNDS = 10;

	/** Minimum log rounds */
	public static final int MIN_LOG_ROUNDS = 4;

	/** Maximum log rounds */
	public static final int MAX_LOG_ROUNDS = 31;

	private BcryptHasher()
	{
	}

	/**
	 * Hashes the given password with BCrypt using default log rounds (10).
	 *
	 * @param password
	 *            the password to hash
	 * @return the BCrypt hash string in standard format
	 * @throws IllegalArgumentException
	 *             if password is null
	 */
	public static String hash(final char[] password)
	{
		return hash(password, DEFAULT_LOG_ROUNDS);
	}

	/**
	 * Hashes the given password with BCrypt using specified log rounds.
	 *
	 * @param password
	 *            the password to hash
	 * @param logRounds
	 *            the log2 of the number of rounds of hashing to apply (e.g., 10 means 2^10 = 1024
	 *            iterations)
	 * @return the BCrypt hash string in standard format
	 * @throws IllegalArgumentException
	 *             if password is null or logRounds is out of range
	 */
	public static String hash(final char[] password, final int logRounds)
	{
		if (password == null)
		{
			throw new IllegalArgumentException("Password cannot be null");
		}
		if (logRounds < MIN_LOG_ROUNDS || logRounds > MAX_LOG_ROUNDS)
		{
			throw new IllegalArgumentException(
				"Log rounds must be between " + MIN_LOG_ROUNDS + " and " + MAX_LOG_ROUNDS);
		}

		try
		{
			final byte[] salt = new byte[16];
			new SecureRandom().nextBytes(salt);
			return OpenBSDBCrypt.generate(password, salt, logRounds);
		}
		finally
		{
			Arrays.fill(password, '\0');
		}
	}

	/**
	 * Hashes the given password with BCrypt using specified log rounds and salt.
	 *
	 * @param password
	 *            the password to hash
	 * @param salt
	 *            the salt to use (must be at least 16 bytes)
	 * @param logRounds
	 *            the log2 of the number of rounds of hashing to apply
	 * @return the BCrypt hash string in standard format
	 * @throws IllegalArgumentException
	 *             if password or salt is null, or salt is too short
	 */
	public static String hashWithSalt(final char[] password, final byte[] salt, final int logRounds)
	{
		if (password == null)
		{
			throw new IllegalArgumentException("Password cannot be null");
		}
		if (salt == null)
		{
			throw new IllegalArgumentException("Salt cannot be null");
		}
		if (salt.length != 16)
		{
			throw new IllegalArgumentException("Salt must be exactly 16 bytes");
		}
		if (logRounds < MIN_LOG_ROUNDS || logRounds > MAX_LOG_ROUNDS)
		{
			throw new IllegalArgumentException(
				"Log rounds must be between " + MIN_LOG_ROUNDS + " and " + MAX_LOG_ROUNDS);
		}

		try
		{
			return OpenBSDBCrypt.generate(password, salt, logRounds);
		}
		finally
		{
			Arrays.fill(password, '\0');
		}
	}

	/**
	 * Verifies that the given password matches the BCrypt hash.
	 *
	 * @param password
	 *            the password to verify
	 * @param hash
	 *            the BCrypt hash string to verify against
	 * @return true if the password matches the hash, false otherwise
	 * @throws IllegalArgumentException
	 *             if password or hash is null
	 */
	public static boolean verify(final char[] password, final String hash)
	{
		if (password == null)
		{
			throw new IllegalArgumentException("Password cannot be null");
		}
		if (hash == null)
		{
			throw new IllegalArgumentException("Hash cannot be null");
		}

		try
		{
			return OpenBSDBCrypt.checkPassword(hash, password);
		}
		finally
		{
			Arrays.fill(password, '\0');
		}
	}

	/**
	 * Extracts the log rounds (cost factor) from a BCrypt hash string.
	 *
	 * @param hash
	 *            the BCrypt hash string
	 * @return the log rounds value
	 * @throws IllegalArgumentException
	 *             if hash is null or malformed
	 */
	public static int getLogRounds(final String hash)
	{
		if (hash == null)
		{
			throw new IllegalArgumentException("Hash cannot be null");
		}

		// BCrypt format: $<version>$<cost>$<salt+hash> where version is 1-2 chars (2, 2a, 2b, 2x,
		// 2y)
		final String[] parts = hash.split("\\$");
		if (parts.length < 4 || !parts[1].startsWith("2"))
		{
			throw new IllegalArgumentException("Invalid BCrypt hash format");
		}

		try
		{
			return Integer.parseInt(parts[2]);
		}
		catch (final NumberFormatException e)
		{
			throw new IllegalArgumentException("Invalid BCrypt hash format", e);
		}
	}

}
