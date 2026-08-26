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
package io.github.astrapi69.mystic.crypt.pw;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

import io.github.astrapi69.mystic.crypt.sha.ScryptHasher;
import io.github.astrapi69.random.number.RandomByteFactory;

/**
 * Package-private helper for scrypt password hashing, encoded in a PHC-like string format so the
 * parameters travel with the hash:
 *
 * <pre>
 * $scrypt$ln=&lt;log2 of n&gt;,r=&lt;r&gt;,p=&lt;p&gt;$&lt;salt&gt;$&lt;hash&gt;
 * </pre>
 *
 * <p>
 * {@link ScryptHasher} produces raw bytes and verifies against them, which means the caller has to
 * keep the salt and the three cost parameters somewhere else. That is exactly what a stored
 * password hash cannot rely on, so this wraps it in the same self-describing form that
 * {@link Argon2Support} and {@link Pbkdf2Support} use, and it is what lets {@code verify} recognise
 * a scrypt hash by its own encoding.
 * <p>
 * The cost is written as {@code ln}, the base-2 logarithm of n, which is how scrypt's cost is
 * conventionally written and keeps the field short.
 * <p>
 * Both {@link #hash(char[])} and {@link #verify(char[], String)} zero the given {@code password}
 * array before returning; callers must not reuse the array afterwards.
 */
final class ScryptSupport
{

	/** The prefix every encoded scrypt hash of this library starts with. */
	static final String PREFIX = "$scrypt$";

	/** Salt length in bytes. */
	static final int SALT_LENGTH = 16;

	/** Output hash length in bytes. */
	static final int HASH_LENGTH = 32;

	/** Default CPU and memory cost, as the base-2 logarithm of n. */
	static final int DEFAULT_LOG_N = 15;

	/** Default block size. */
	static final int DEFAULT_R = 8;

	/** Default parallelism. */
	static final int DEFAULT_P = 1;

	private ScryptSupport()
	{
	}

	/**
	 * Hashes the given password with a fresh random salt and the default parameters.
	 *
	 * @param password
	 *            the password
	 * @return the encoded hash
	 */
	static String hash(final char[] password)
	{
		Objects.requireNonNull(password);
		try
		{
			final byte[] salt = RandomByteFactory.randomByteArray(SALT_LENGTH);
			final byte[] hash = ScryptHasher.hashWithSalt(password.clone(), salt,
				1 << DEFAULT_LOG_N, DEFAULT_R, DEFAULT_P, HASH_LENGTH);
			final Base64.Encoder encoder = Base64.getEncoder().withoutPadding();
			return PREFIX + "ln=" + DEFAULT_LOG_N + ",r=" + DEFAULT_R + ",p=" + DEFAULT_P + "$"
				+ encoder.encodeToString(salt) + "$" + encoder.encodeToString(hash);
		}
		finally
		{
			Arrays.fill(password, '\0');
		}
	}

	/**
	 * Verifies the given password against a previously encoded hash.
	 *
	 * @param password
	 *            the password to check
	 * @param encoded
	 *            the previously encoded hash, as produced by {@link #hash(char[])}
	 * @return true if the password matches, false if it does not match or {@code encoded} is
	 *         malformed
	 */
	static boolean verify(final char[] password, final String encoded)
	{
		Objects.requireNonNull(password);
		Objects.requireNonNull(encoded);
		try
		{
			return decodeAndCompare(password, encoded);
		}
		finally
		{
			Arrays.fill(password, '\0');
		}
	}

	/**
	 * Decodes {@code encoded} and compares its hash against one computed for {@code password} with
	 * the decoded parameters. Split out of {@link #verify(char[], String)} for the same reason as
	 * in {@link Argon2Support}: a {@code return false} that is the last statement of a {@code try}
	 * with a {@code finally} compiles through a local variable, which defeats PIT's
	 * equivalent-constant filter.
	 *
	 * @param password
	 *            the password to check
	 * @param encoded
	 *            the previously encoded hash
	 * @return true if the password matches
	 */
	private static boolean decodeAndCompare(final char[] password, final String encoded)
	{
		try
		{
			final Decoded decoded = decode(encoded);
			// the hasher is inside the guard as well: a cost that is well formed but absurd - ln=30
			// asks for a gigabyte of state - makes Bouncy Castle fail rather than return, and the
			// contract of verify is "false for a hash this password does not open", not "throws
			// for a hash somebody wrote a large number into"
			return ScryptHasher.verify(password.clone(), decoded.salt, decoded.hash,
				1 << decoded.logN, decoded.r, decoded.p);
		}
		catch (final RuntimeException malformedOrUnusable)
		{
			return false;
		}
	}

	private static Decoded decode(final String encoded)
	{
		final String[] parts = encoded.split("\\$");
		// parts[0] is empty (string starts with '$'); parts[1]="scrypt";
		// parts[2]="ln=..,r=..,p=.."; parts[3]=salt; parts[4]=hash
		if (parts.length != 5 || !"scrypt".equals(parts[1]))
		{
			throw new IllegalArgumentException("not a valid scrypt encoded hash");
		}
		final String[] params = parts[2].split(",");
		int logN = -1;
		int r = -1;
		int p = -1;
		for (final String param : params)
		{
			final String[] keyValue = param.split("=");
			if (keyValue.length != 2)
			{
				throw new IllegalArgumentException("not a valid scrypt encoded hash");
			}
			switch (keyValue[0])
			{
				case "ln" :
					logN = Integer.parseInt(keyValue[1]);
					break;
				case "r" :
					r = Integer.parseInt(keyValue[1]);
					break;
				case "p" :
					p = Integer.parseInt(keyValue[1]);
					break;
				default :
					throw new IllegalArgumentException("not a valid scrypt encoded hash");
			}
		}
		// scrypt requires n to be a power of two greater than one, and r and p at least one. The
		// upper bound on ln is only about the shift: 1 << 31 is negative, and a negative n is not
		// a large cost but a broken one. Costs that are in range yet unusable are caught where the
		// hasher runs.
		if (logN < 1 || logN > 30 || r < 1 || p < 1)
		{
			throw new IllegalArgumentException("not a valid scrypt encoded hash");
		}
		final byte[] salt = Base64.getDecoder().decode(parts[3]);
		final byte[] hash = Base64.getDecoder().decode(parts[4]);
		return new Decoded(salt, hash, logN, r, p);
	}

	private static final class Decoded
	{
		private final byte[] salt;
		private final byte[] hash;
		private final int logN;
		private final int r;
		private final int p;

		private Decoded(final byte[] salt, final byte[] hash, final int logN, final int r,
			final int p)
		{
			this.salt = salt;
			this.hash = hash;
			this.logN = logN;
			this.r = r;
			this.p = p;
		}
	}
}
