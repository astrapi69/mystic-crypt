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
package io.github.astrapi69.mystic.crypt.pw;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import io.github.astrapi69.random.number.RandomByteFactory;

/**
 * Package-private helper for PBKDF2 password hashing, encoded in a PHC-like string format
 * ({@code $pbkdf2-sha256$i=<iterations>$<salt>$<hash>}) so the parameters travel with the hash.
 * Pure JDK ({@code SecretKeyFactory}), no Bouncy Castle needed.
 * <p>
 * Unlike Argon2id ({@link Argon2Support}), PBKDF2 is not memory-hard - it is vulnerable to cheap
 * parallelization on GPUs/ASICs even at a high iteration count. Prefer
 * {@link PasswordEncryptor#hashPasswordArgon2id(String)} for new code; this exists for interop with
 * systems that specifically require PBKDF2.
 */
final class Pbkdf2Support
{

	/** The JCA algorithm name for PBKDF2 with HMAC-SHA256. */
	private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

	/** Salt length in bytes. */
	static final int SALT_LENGTH = 16;

	/** Output hash length in bits. */
	static final int HASH_LENGTH_BITS = 256;

	/**
	 * Default number of iterations, per the OWASP Password Storage Cheat Sheet (2023) guidance for
	 * PBKDF2-HMAC-SHA256.
	 */
	static final int DEFAULT_ITERATIONS = 600_000;

	private static final String PREFIX = "$pbkdf2-sha256$i=";

	private Pbkdf2Support()
	{
	}

	/**
	 * Hashes the given password with a fresh random salt and the default iteration count, encoded
	 * as a PHC-like format string.
	 *
	 * @param password
	 *            the password
	 * @return the encoded hash
	 */
	static String hash(final char[] password)
	{
		Objects.requireNonNull(password);
		final byte[] salt = RandomByteFactory.randomByteArray(SALT_LENGTH);
		final byte[] hash = rawHash(password, salt, DEFAULT_ITERATIONS);
		return encode(salt, hash, DEFAULT_ITERATIONS);
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
		final Decoded decoded;
		try
		{
			decoded = decode(encoded);
		}
		catch (final RuntimeException malformed)
		{
			return false;
		}
		final byte[] actualHash = rawHash(password, decoded.salt, decoded.iterations);
		return MessageDigest.isEqual(decoded.hash, actualHash);
	}

	private static byte[] rawHash(final char[] password, final byte[] salt, final int iterations)
	{
		try
		{
			final PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_LENGTH_BITS);
			final SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
			return factory.generateSecret(spec).getEncoded();
		}
		catch (final NoSuchAlgorithmException | InvalidKeySpecException impossible)
		{
			// PBKDF2WithHmacSHA256 is a standard JDK algorithm and the key spec above is always
			// well-formed, so this can never actually happen.
			throw new IllegalStateException(impossible);
		}
	}

	private static String encode(final byte[] salt, final byte[] hash, final int iterations)
	{
		final Base64.Encoder encoder = Base64.getEncoder().withoutPadding();
		return PREFIX + iterations + "$" + encoder.encodeToString(salt) + "$"
			+ encoder.encodeToString(hash);
	}

	private static Decoded decode(final String encoded)
	{
		final String[] parts = encoded.split("\\$");
		// parts[0] is empty (string starts with '$'); parts[1]="pbkdf2-sha256";
		// parts[2]="i=<iterations>"; parts[3]=salt; parts[4]=hash
		if (parts.length != 5 || !"pbkdf2-sha256".equals(parts[1]) || !parts[2].startsWith("i="))
		{
			throw new IllegalArgumentException("not a valid pbkdf2-sha256 encoded hash");
		}
		final int iterations = Integer.parseInt(parts[2].substring(2));
		final byte[] salt = Base64.getDecoder().decode(parts[3]);
		final byte[] hash = Base64.getDecoder().decode(parts[4]);
		return new Decoded(salt, hash, iterations);
	}

	private static final class Decoded
	{
		private final byte[] salt;
		private final byte[] hash;
		private final int iterations;

		private Decoded(final byte[] salt, final byte[] hash, final int iterations)
		{
			this.salt = salt;
			this.hash = hash;
			this.iterations = iterations;
		}
	}

}
